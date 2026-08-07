#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Tapscript v2 leaf version 0xc2 behavior."""

import hashlib
import random

from feature_taproot import (
    ERR_EVAL_FALSE,
    ERR_PUSH_SIZE,
    TaprootTest,
    add_spender,
    bitflipper,
    get,
    make_spender,
)

from test_framework.blocktools import (
    COINBASE_MATURITY,
    MAX_BLOCK_SIGOPS_WEIGHT,
    MAX_STANDARD_TX_WEIGHT,
)
from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MAX_BLOCK_WEIGHT,
    SEQUENCE_FINAL,
    ser_string,
    tx_from_hex,
)
from test_framework.psbt import (
    PSBT,
    PSBTMap,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_WITNESS_UTXO,
)
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    CScriptOp,
    LEAF_VERSION_TAPSCRIPT,
    LEAF_VERSION_TAPSCRIPT_V2,
    MAX_SCRIPT_ELEMENT_SIZE,
    OP_0,
    OP_1,
    OP_CAT,
    OP_CHECKSIG,
    OP_DROP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_MUL,
    OP_PUSHDATA1,
    OP_RETURN,
    OP_SHA256,
    OP_SIZE,
    OP_TX,
    taproot_construct,
)
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.wallet import NodeSigner


ERR_VAROP_COUNT = {"err_msg": "Varops budget exceeded"}

MAX_TAPSCRIPT_V2_STACK_SIZE = 32_768
MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE = 4_000_000

VERSIONBITS_PERIOD = 144
SCRIPT_RESTORATION_VBPARAMS = "-vbparams=script_restoration:0:3999999999"


def script_restoration_bip9(node):
    return node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]


def advance_script_restoration_to_started(test, node):
    while script_restoration_bip9(node)["status"] != "started":
        assert_equal(script_restoration_bip9(node)["status"], "defined")
        test.generate(node, VERSIONBITS_PERIOD - node.getblockcount() % VERSIONBITS_PERIOD)


def v2_num(value):
    """Return the minimal unsigned little-endian encoding used by Tapscript v2."""
    assert value >= 0
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def tapscript_v2_spenders():
    # The BIP vectors cover the semantics of 0xc2 scripts. These spends show
    # that the node accepts 0xc2 leaves, alone and next to other inputs.
    pub = compute_xonly_pubkey(generate_privkey())[0]
    spenders = []

    # Initial witness elements can exceed 520 bytes in v2, but the same leaf
    # body under 0xc0 still uses the BIP342 element limit.
    big_item = b"a" * (MAX_SCRIPT_ELEMENT_SIZE + 80)
    big_item_script = CScript([OP_SIZE, v2_num(len(big_item)), OP_EQUALVERIFY, OP_DROP, OP_1])
    tap = taproot_construct(pub, [
        ("big_item_v2", big_item_script, LEAF_VERSION_TAPSCRIPT_V2),
        ("big_item_c0", big_item_script, LEAF_VERSION_TAPSCRIPT),
    ])
    add_spender(
        spenders,
        "v2/witness_item_over_520",
        tap=tap,
        leaf="big_item_v2",
        inputs=[big_item],
        failure={"leaf": "big_item_c0"},
        **ERR_PUSH_SIZE,
    )

    # OP_CAT is restored under 0xc2 and can produce elements over 520 bytes.
    cat_a = b"x" * 400
    cat_b = b"y" * 180
    cat_script = CScript([OP_CAT, cat_a + cat_b, OP_EQUAL])
    tap = taproot_construct(pub, [
        ("cat_v2", cat_script, LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/cat_restored_over_520",
        tap=tap,
        leaf="cat_v2",
        inputs=[cat_a, cat_b],
    )

    return spenders


def op_tx_spenders():
    sec = generate_privkey()
    pub = compute_xonly_pubkey(sec)[0]
    spenders = []

    current_input_amount = bytes.fromhex("000000100400")
    def expected_input_amount(ctx):
        return v2_num(get(ctx, "utxos")[get(ctx, "idx")].nValue)

    script = CScript([current_input_amount, OP_TX, OP_EQUAL])
    tap = taproot_construct(pub, [("amount", script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/op_tx_current_input_amount",
        tap=tap,
        leaf="amount",
        inputs=[expected_input_amount],
        failure={"inputs": [bitflipper(expected_input_amount)]},
        **ERR_EVAL_FALSE,
    )

    internal_key = bytes.fromhex("000020000000")
    script = CScript([internal_key, OP_TX, pub, OP_EQUAL])
    tap = taproot_construct(pub, [("internal_key", script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(spenders, "v2/op_tx_internal_key", tap=tap, leaf="internal_key")

    current_tree = bytes.fromhex("000148000000")
    script = CScript([current_tree, OP_TX, OP_EQUAL])
    tap = taproot_construct(pub, [
        ("current_tree", script, LEAF_VERSION_TAPSCRIPT_V2),
        ("sibling", CScript([OP_1]), LEAF_VERSION_TAPSCRIPT_V2),
    ])

    def expected_current_tree(ctx):
        return get(ctx, "tapleaf").leaf_hash + get(ctx, "tap").merkle_root

    add_spender(
        spenders,
        "v2/op_tx_current_tapleaf_and_taptree_root",
        tap=tap,
        leaf="current_tree",
        inputs=[expected_current_tree],
        failure={"inputs": [bitflipper(expected_current_tree)]},
        **ERR_EVAL_FALSE,
    )

    annex = bytes([ANNEX_TAG]) + b"op_tx"

    def templatehash_like_hash(ctx):
        tx = get(ctx, "tx")
        current_annex = get(ctx, "annex")
        preimage = tx.version.to_bytes(4, "little") + tx.nLockTime.to_bytes(4, "little")
        preimage += len(tx.vin).to_bytes(4, "little")
        preimage += b"".join(txin.nSequence.to_bytes(4, "little") for txin in tx.vin)
        preimage += len(tx.vout).to_bytes(4, "little")
        preimage += b"".join(txout.serialize() for txout in tx.vout)
        preimage += get(ctx, "idx").to_bytes(4, "little")
        preimage += ser_string(current_annex if current_annex is not None else b"")
        return hashlib.sha256(preimage).digest()

    script = CScript([bytes.fromhex("005703222003"), OP_TX, OP_SHA256, OP_EQUAL])
    tap = taproot_construct(pub, [("templatehash", script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/op_tx_templatehash_like_commitment",
        tap=tap,
        leaf="templatehash",
        annex=annex,
        standard=False,
        inputs=[templatehash_like_hash],
        failure={"inputs": [bitflipper(templatehash_like_hash)]},
        **ERR_EVAL_FALSE,
    )

    future_version_script = CScript([b"\x01", OP_TX, OP_RETURN])
    tap = taproot_construct(pub, [("future_version", future_version_script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/op_tx_future_selector_version",
        tap=tap,
        leaf="future_version",
        standard=False,
    )

    return spenders


class TapscriptV2Test(TaprootTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [[SCRIPT_RESTORATION_VBPARAMS]]

    def run_test(self):
        random.seed(441)
        self.nodesigner = NodeSigner(self.nodes[0])

        self.generatetoaddress(
            self.nodes[0],
            COINBASE_MATURITY + 1,
            self.nodesigner.getnewaddress(address_type="bech32")[2],
        )

        self.log.info("Tapscript v2 pre-activation unknown leaf test")
        self.test_tapscript_v2_leaf_before_activation()

        self.log.info("Tapscript v2 activation rollback/reapply test")
        self.test_script_restoration_activation_rollback_reapply()

        self.log.info("Tapscript v2 spender tests")
        self.test_spenders(self.nodes[0], tapscript_v2_spenders(), input_counts=[1, 2, 3])

        self.log.info("Tapscript v2 OP_TX tests")
        self.test_spenders(self.nodes[0], op_tx_spenders(), input_counts=[1])

        self.log.info("Tapscript v2 transaction-wide varops budget test")
        self.test_transaction_wide_varops_budget()

        self.log.info("Tapscript v2 standard transaction weight policy test")
        self.test_standard_tx_weight_policy()

        self.log.info("Tapscript v2 upgrade-semantics policy tests")
        self.test_upgrade_semantics_policy()

    def test_tapscript_v2_leaf_before_activation(self):
        """Before SCRIPT_RESTORATION activation, 0xc2 has unknown-leaf consensus semantics."""
        node = self.nodes[0]
        host_pubkey, _host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        cases = [
            ("false", CScript([OP_0]), []),
            ("return", CScript([OP_RETURN]), []),
            ("malformed_push", CScript([OP_PUSHDATA1]), []),
            ("oversized_initial_stack", CScript([OP_0]), [b""] * (MAX_TAPSCRIPT_V2_STACK_SIZE + 1)),
        ]
        funded = [
            (name, self.fund_tapscript_v2(script, amount=50_000_000), witness_elements)
            for name, script, witness_elements in cases
        ]
        assert not self.script_restoration_info()["active"]

        spending_txs = []
        for name, utxo, witness_elements in funded:
            spending_tx = self.spending_tx(utxo, witness_elements=witness_elements)
            spending_txs.append(spending_tx)

            result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
            assert not result["allowed"], f"{name}: {result}"
            assert "SCRIPT_RESTORATION" in result.get("reject-reason", ""), f"{name}: {result}"
            assert_raises_rpc_error(-26, None, node.sendrawtransaction, spending_tx.serialize().hex(), 0)

        self.init_blockinfo(node)
        self.block_submit(
            node,
            spending_txs,
            "Tapscript v2 leaves before SCRIPT_RESTORATION activation",
            err_msg=None,
            cb_pubkey=host_pubkey,
            fees=10_000 * len(spending_txs),
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
            witness=True,
            accept=True,
        )

    def script_restoration_info(self):
        return self.nodes[0].getdeploymentinfo()["deployments"]["script_restoration"]

    def script_restoration_state(self):
        return script_restoration_bip9(self.nodes[0])

    def signal_script_restoration_activation(self):
        node = self.nodes[0]
        return self.generate(node, 1)[0]

    def submit_spend_block(self, spending_tx, comment, *, err_msg=None, accept=True, fee=10_000):
        node = self.nodes[0]
        host_pubkey, _host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        self.init_blockinfo(node)
        self.block_submit(
            node,
            [spending_tx],
            comment,
            err_msg,
            host_pubkey,
            fee,
            MAX_BLOCK_SIGOPS_WEIGHT,
            True,
            accept,
        )
        if accept:
            return node.getbestblockhash()
        return None

    def test_script_restoration_activation_rollback_reapply(self):
        node = self.nodes[0]

        original_pre_active_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)
        active_invalid_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)
        active_valid_utxo = self.fund_tapscript_v2(CScript([OP_1]), amount=50_000_000)
        alternate_pre_active_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)
        reapplied_invalid_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)

        advance_script_restoration_to_started(self, node)
        assert_equal(self.script_restoration_state()["status"], "started")
        started_height = node.getblockcount()
        period = self.script_restoration_state()["statistics"]["period"]

        self.signal_script_restoration_activation()
        target_parent_height = started_height + 2 * period - 2
        blocks_to_target_parent = target_parent_height - node.getblockcount()
        assert blocks_to_target_parent >= 0
        self.generate(node, blocks_to_target_parent)
        assert_equal(node.getblockcount(), target_parent_height)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "locked_in")

        original_pre_active_tx = self.spending_tx(original_pre_active_utxo)
        original_pre_active_hash = self.submit_spend_block(
            original_pre_active_tx,
            "Tapscript v2 0xc2 OP_0 spend in last pre-active block",
        )
        last_pre_active_height = node.getblockcount()
        assert_equal(last_pre_active_height, started_height + 2 * period - 1)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "active")

        active_invalid_tx = self.spending_tx(active_invalid_utxo)
        self.submit_spend_block(
            active_invalid_tx,
            "Tapscript v2 0xc2 OP_0 spend in first active block",
            err_msg=ERR_EVAL_FALSE["err_msg"],
            accept=False,
        )

        active_valid_tx = self.spending_tx(active_valid_utxo)
        active_hash = self.submit_spend_block(
            active_valid_tx,
            "Tapscript v2 0xc2 OP_1 spend in first active block",
        )
        assert_equal(node.getblockcount(), last_pre_active_height + 1)
        assert_equal(self.script_restoration_state()["status"], "active")

        node.invalidateblock(original_pre_active_hash)
        assert_equal(node.getblockcount(), last_pre_active_height - 1)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "locked_in")
        assert not self.script_restoration_info()["active"]

        alternate_pre_active_tx = self.spending_tx(alternate_pre_active_utxo)
        alternate_pre_active_hash = self.submit_spend_block(
            alternate_pre_active_tx,
            "Tapscript v2 0xc2 OP_0 spend in alternate last pre-active block",
        )
        assert alternate_pre_active_hash != original_pre_active_hash
        assert_equal(node.getblockcount(), last_pre_active_height)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "active")

        node.reconsiderblock(original_pre_active_hash)
        node.reconsiderblock(active_hash)
        self.wait_until(lambda: node.getbestblockhash() == active_hash)
        assert_equal(self.script_restoration_state()["status"], "active")

        reapplied_invalid_tx = self.spending_tx(reapplied_invalid_utxo)
        self.submit_spend_block(
            reapplied_invalid_tx,
            "Tapscript v2 0xc2 OP_0 spend after activation branch reapply",
            err_msg=ERR_EVAL_FALSE["err_msg"],
            accept=False,
        )

    def fund_spenders(self, spenders, amount=10_000_000):
        node = self.nodes[0]
        host_pubkey, host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        fund_tx = CTransaction()
        unspents = self.nodesigner.listunspent()
        unspents.sort(key=lambda x: int(x["amount"] * 100_000_000), reverse=True)
        balance = 0
        for unspent in unspents[:20]:
            balance += int(unspent["amount"] * 100_000_000)
            fund_tx.vin.append(CTxIn(COutPoint(int(unspent["txid"], 16), int(unspent["vout"])), CScript()))

        for spender in spenders:
            fund_tx.vout.append(CTxOut(amount, spender.script))
            balance -= amount

        assert balance > 100_000
        fund_tx.vout.append(CTxOut(balance - 10_000, host_spk))
        fund_tx = self.nodesigner.signrawtransaction(fund_tx.serialize().hex(), unspents)
        fund_tx = tx_from_hex(fund_tx["hex"])
        self.init_blockinfo(node)
        self.block_submit(
            node,
            [fund_tx],
            "Tapscript v2 funding tx",
            None,
            host_pubkey,
            10_000,
            MAX_BLOCK_SIGOPS_WEIGHT,
            True,
            True,
        )

        return [
            (COutPoint(fund_tx.txid_int, i), fund_tx.vout[i], spender)
            for i, spender in enumerate(spenders)
        ], host_spk, host_pubkey

    def fund_tapscript_v2(self, script, *, internal_key=None, amount=10_000_000, leaves=None, leaf_name="script"):
        node = self.nodes[0]
        if internal_key is None:
            internal_key = generate_privkey()
        internal_pubkey = compute_xonly_pubkey(internal_key)[0]

        if leaves is None:
            leaves = [(leaf_name, script, LEAF_VERSION_TAPSCRIPT_V2)]
        tap = taproot_construct(internal_pubkey, leaves)

        unspents = self.nodesigner.listunspent()
        unspents.sort(key=lambda x: int(x["amount"] * COIN), reverse=True)
        selected = unspents[0]
        selected_value = int(selected["amount"] * COIN)
        fee = 10_000
        assert selected_value > amount + fee

        _change_pubkey, change_spk, _change_addr = self.nodesigner.getnewaddress(address_type="bech32")
        funding_tx = CTransaction()
        funding_tx.vin = [CTxIn(COutPoint(int(selected["txid"], 16), int(selected["vout"])))]
        funding_tx.vout = [
            CTxOut(amount, tap.scriptPubKey),
            CTxOut(selected_value - amount - fee, change_spk),
        ]
        signed = self.nodesigner.signrawtransaction(funding_tx.serialize().hex(), [selected])
        funding_tx = tx_from_hex(signed["hex"])
        funding_txid = node.sendrawtransaction(funding_tx.serialize().hex(), 0)
        self.generate(node, 1)
        return {
            "amount": amount,
            "internal_key": internal_key,
            "leaf": leaf_name,
            "script": tap.leaves[leaf_name].script,
            "tap": tap,
            "txid": funding_txid,
            "vout": 0,
        }

    def control_block(self, utxo):
        tap = utxo["tap"]
        leaf_info = tap.leaves[utxo["leaf"]]
        return bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch

    def spending_tx(self, utxo, *, witness_elements=(), fee=10_000, nlocktime=0, nsequence=SEQUENCE_FINAL):
        _output_pubkey, output_spk, _output_addr = self.nodesigner.getnewaddress(address_type="bech32")

        spending_tx = CTransaction()
        spending_tx.version = 2
        spending_tx.nLockTime = nlocktime
        spending_tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), nsequence)]
        spending_tx.vout = [CTxOut(utxo["amount"] - fee, output_spk)]
        spending_tx.wit.vtxinwit = [CTxInWitness()]
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = [
            *witness_elements,
            bytes(utxo["script"]),
            self.control_block(utxo),
        ]
        return spending_tx

    def submit_and_mine(self, spending_tx, comment):
        node = self.nodes[0]
        result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], f"{comment}: {result.get('reject-reason', 'unknown reject reason')}"
        node.sendrawtransaction(spending_tx.serialize().hex(), 0)
        self.generate(node, 1)

    def submit_nonstandard_and_mine(self, spending_tx, comment, fee=10_000):
        node = self.nodes[0]
        host_pubkey, _host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], f"{comment}: unexpectedly accepted into mempool"
        assert "OP_SUCCESS" in result.get("reject-reason", ""), result

        self.init_blockinfo(node)
        self.block_submit(
            node,
            [spending_tx],
            comment,
            None,
            host_pubkey,
            fee,
            MAX_BLOCK_SIGOPS_WEIGHT,
            True,
            True,
        )

    def test_standard_tx_weight_policy(self):
        node = self.nodes[0]
        fee = 200_000
        large_witness_script = CScript([OP_DROP, OP_1])

        def tx_with_padding(utxo, padding_len):
            return self.spending_tx(utxo, witness_elements=[b"\x00" * padding_len], fee=fee)

        def tx_at_weight_boundary(utxo, weight_limit, *, over):
            def weight_at(padding_len):
                return tx_with_padding(utxo, padding_len).get_weight()

            high = weight_limit
            while weight_at(high) <= weight_limit:
                high *= 2

            low = 0
            selected_padding_len = high if over else 0
            while low <= high:
                mid = (low + high) // 2
                weight = weight_at(mid)
                if weight > weight_limit:
                    if over:
                        selected_padding_len = mid
                    high = mid - 1
                else:
                    if not over:
                        selected_padding_len = mid
                    low = mid + 1

            tx = tx_with_padding(utxo, selected_padding_len)
            padding = tx.wit.vtxinwit[0].scriptWitness.stack[0]
            assert_equal(len(padding), selected_padding_len)
            assert_greater_than(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, len(padding))

            if over:
                assert_greater_than(tx.get_weight(), weight_limit)
                assert weight_at(selected_padding_len - 1) <= weight_limit
            else:
                assert tx.get_weight() <= weight_limit
                assert_greater_than(weight_at(selected_padding_len + 1), weight_limit)
            return tx

        standard_utxo = self.fund_tapscript_v2(large_witness_script)
        standard_tx = tx_at_weight_boundary(standard_utxo, MAX_STANDARD_TX_WEIGHT, over=False)
        assert standard_tx.get_weight() <= MAX_STANDARD_TX_WEIGHT
        self.submit_and_mine(standard_tx, "v2 large witness item at standard tx weight")

        oversized_utxo = self.fund_tapscript_v2(large_witness_script)
        oversized_tx = tx_at_weight_boundary(oversized_utxo, MAX_STANDARD_TX_WEIGHT, over=True)
        assert_greater_than(oversized_tx.get_weight(), MAX_STANDARD_TX_WEIGHT)
        assert_greater_than(MAX_BLOCK_WEIGHT, oversized_tx.get_weight())

        result = node.testmempoolaccept([oversized_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], result
        assert_equal(result["reject-reason"], "tx-size")

        self.submit_spend_block(
            oversized_tx,
            "v2 large witness item above standard tx weight",
            fee=fee,
        )

    def test_upgrade_semantics_policy(self):
        node = self.nodes[0]

        # Future pubkey encodings remain policy-discouraged but consensus-valid
        # through BIP342-style unknown-pubkey semantics.
        future_pubkey = b"\x01" + compute_xonly_pubkey(generate_privkey())[0]
        future_pubkey_script = CScript([future_pubkey, OP_CHECKSIG])
        utxo = self.fund_tapscript_v2(future_pubkey_script)
        spending_tx = self.spending_tx(utxo)
        spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, b"\x01" * 64)
        result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], result
        assert "Public key version reserved for soft-fork upgrades" in result.get("reject-reason", ""), result
        self.submit_spend_block(
            spending_tx,
            "v2 future pubkey encoding remains upgradable",
        )

        # Inquisition assigns semantics to 0xcb and 0xcc. On Core master they
        # remain OP_SUCCESS code points, including in tapscript v2.
        for name, success_op in (("0xcb", CScriptOp(0xcb)), ("0xcc", CScriptOp(0xcc))):
            utxo = self.fund_tapscript_v2(CScript([success_op, OP_RETURN]))
            spending_tx = self.spending_tx(utxo)
            self.submit_nonstandard_and_mine(spending_tx, f"{name} as v2 OP_SUCCESS leaf")

    def test_transaction_wide_varops_budget(self):
        node = self.nodes[0]
        sec = generate_privkey()
        pub = compute_xonly_pubkey(sec)[0]

        # A multiplication of two 60,000-byte operands costs more than the
        # weight of its own input funds, and less than that of two such inputs
        # (varops.json, "Shared budget"). Both transactions have the same
        # weight: a cheap sibling funds one multiplication, and a second
        # multiplication exhausts the shared budget.
        operand = b"\xff" * 60_000
        padding = b"\x00" * 11
        expensive_script = CScript([OP_MUL, OP_DROP, OP_DROP, OP_1])
        cheap_script = CScript([OP_DROP, OP_DROP, OP_DROP, OP_1])
        assert_equal(len(expensive_script), len(cheap_script))

        def make_budget_spender(name, script):
            tap = taproot_construct(pub, [(name, script, LEAF_VERSION_TAPSCRIPT_V2)])
            return make_spender(name, tap=tap, leaf=name, key=sec, inputs=[padding, operand, operand])

        spenders = [
            make_budget_spender("v2/shared_budget_accepted_expensive", expensive_script),
            make_budget_spender("v2/shared_budget_accepted_cheap", cheap_script),
            make_budget_spender("v2/shared_budget_rejected_expensive", expensive_script),
            make_budget_spender("v2/shared_budget_rejected_second_expensive", expensive_script),
        ]
        funded, host_spk, host_pubkey = self.fund_spenders(spenders)

        def make_spend_tx(funded_inputs):
            spend_tx = CTransaction()
            spend_tx.version = 2
            spend_tx.vin = [CTxIn(outpoint) for outpoint, _output, _spender in funded_inputs]
            output_value = sum(output.nValue for _outpoint, output, _spender in funded_inputs) - 50_000
            spend_tx.vout = [CTxOut(output_value, host_spk)]
            spend_tx.wit.vtxinwit = [CTxInWitness() for _ in funded_inputs]

            spent_outputs = [output for _outpoint, output, _spender in funded_inputs]
            for index, (_outpoint, _output, spender) in enumerate(funded_inputs):
                script_sig, witness_stack = spender.sat_function(spend_tx, index, spent_outputs, True)
                spend_tx.vin[index].scriptSig = script_sig
                spend_tx.wit.vtxinwit[index].scriptWitness.stack = witness_stack
            return spend_tx

        accepted_funded = funded[:2]
        rejected_funded = funded[2:]
        accepted_tx = make_spend_tx(accepted_funded)
        rejected_tx = make_spend_tx(rejected_funded)
        assert_equal(accepted_tx.get_weight(), rejected_tx.get_weight())

        result = node.testmempoolaccept([accepted_tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], result
        node.sendrawtransaction(accepted_tx.serialize().hex(), 0)
        assert node.getmempoolentry(accepted_tx.txid_hex) is not None
        self.block_submit(
            node,
            [accepted_tx],
            "two v2 inputs share the transaction-wide varops budget",
            err_msg=None,
            witness=True,
            accept=True,
            cb_pubkey=host_pubkey,
            fees=50_000,
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
        )

        finalized_psbt = PSBT(
            g=PSBTMap({PSBT_GLOBAL_UNSIGNED_TX: rejected_tx.serialize_without_witness()}),
            i=[
                PSBTMap({
                    PSBT_IN_WITNESS_UTXO: output.serialize(),
                    PSBT_IN_FINAL_SCRIPTWITNESS: rejected_tx.wit.vtxinwit[index].serialize(),
                })
                for index, (_outpoint, output, _spender) in enumerate(rejected_funded)
            ],
            o=[PSBTMap() for _ in rejected_tx.vout],
        ).to_base64()

        analysis = node.analyzepsbt(finalized_psbt)
        assert_equal(analysis["next"], "creator")
        assert_equal(analysis["error"], "PSBT is not valid. Finalized transaction exceeds the varops budget")

        processed = node.descriptorprocesspsbt(finalized_psbt, [])
        assert_equal(processed["complete"], False)
        assert "hex" not in processed

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, rejected_tx.serialize().hex(), 0)
        self.block_submit(
            node,
            [rejected_tx],
            "two v2 inputs exceed the transaction-wide varops budget",
            witness=True,
            accept=False,
            cb_pubkey=host_pubkey,
            fees=50_000,
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
            err_msg=ERR_VAROP_COUNT["err_msg"],
        )


if __name__ == "__main__":
    TapscriptV2Test(__file__).main()
