#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build the same vault two ways with OP_TX, then compare them.

Chapter 1 hashes a fixed transaction template selected with OP_TX.

Chapter 2 uses general OP_TX introspection instead. It protects one indexed
output's amount and scriptPubKey while allowing separately funded fee inputs and
change outputs.

Chapter 3 puts both constructions under the same fee-sponsorship mutation. The
fixed template rejects it; the indexed-output covenant accepts it without
letting sponsor-controlled outputs take any value from the vault.
"""

import copy
from dataclasses import dataclass
import hashlib

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
    ser_string,
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT_V2,
    OP_0,
    OP_1,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_SHA256,
    OP_TX,
    SIGHASH_DEFAULT,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import NodeSigner


VERSIONBITS_PERIOD = 144

# BIP 341's suggested nothing-up-my-sleeve internal key. Covenant trees must
# not have a usable key path, because a key-path spend bypasses every leaf.
NUMS_XONLY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

# Collate version, locktime, all input sequences, all outputs, input and output
# counts, the current input index, and the current annex.
FIXED_TEMPLATE_SELECTOR = bytes.fromhex("005703222003")

# Selector 00 00 01 11 04 03 emits, in this order:
#
#   current input amount
#   output 0 amount
#   output 0 scriptPubKey
#   current input index
#
# INPUT_PREVOUT_AMOUNT is 0x04, OUTPUT_AMOUNT | OUTPUT_SCRIPTPUBKEY is 0x03, and both scopes
# are CURRENT. The script separately requires current input index zero, so
# CURRENT selects output zero without a stack operand.
INDEXED_OUTPUT_SELECTOR = bytes.fromhex("000001110403")

SPONSOR_WITNESS_SCRIPT = CScript([OP_1])
SPONSOR_SCRIPT_PUBKEY = script_to_p2wsh_script(SPONSOR_WITNESS_SCRIPT)

FIXED_TEMPLATE_VAULT_AMOUNT = 20_000_000
FIXED_TEMPLATE_STEP_FEE = 10_000
ANCHOR_AMOUNT = 550
SPONSOR_AMOUNT = 1_000_000
SPONSOR_FEE = 10_000
HOT_SPEND_FEE = 10_000
BLOCK_DELAY = 3


def p2tr_keypath_script(xonly_pubkey):
    """Return a plain P2TR scriptPubKey controlled by xonly_pubkey."""
    return taproot_construct(xonly_pubkey).scriptPubKey


def control_block(tap, leaf_name):
    """Serialize the control block for one named leaf."""
    leaf = tap.leaves[leaf_name]
    return bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch


def blank_input(sequence=SEQUENCE_FINAL):
    """A template input whose prevout can be bound after the vault is funded."""
    return CTxIn(COutPoint(0, 0), CScript(), sequence)


def fixed_template_hash(tx, input_index=0, annex=None):
    """Hash the canonical output of FIXED_TEMPLATE_SELECTOR."""
    preimage = tx.version.to_bytes(4, "little")
    preimage += tx.nLockTime.to_bytes(4, "little")
    preimage += len(tx.vin).to_bytes(4, "little")
    preimage += b"".join(txin.nSequence.to_bytes(4, "little") for txin in tx.vin)
    preimage += len(tx.vout).to_bytes(4, "little")
    preimage += b"".join(txout.serialize() for txout in tx.vout)
    preimage += input_index.to_bytes(4, "little")
    preimage += ser_string(annex if annex is not None else b"")
    return hashlib.sha256(preimage).digest()


def fixed_template_leaf(expected_hash):
    """Commit to one complete transaction template."""
    return CScript([FIXED_TEMPLATE_SELECTOR, OP_TX, OP_SHA256, expected_hash, OP_EQUAL])


def indexed_output_leaf(expected_script_pubkey):
    """Preserve the current input's value in output 0 at one permitted script.

    OP_TX leaves [input_amount, output_amount, output_script, input_index]. The
    checks consume those values from right to left. Additional inputs and
    outputs remain legal, but output 0 already preserves every satoshi from the
    covenant input, so those additions must fund themselves.
    """
    return CScript([
        INDEXED_OUTPUT_SELECTOR,
        OP_TX,
        OP_0,
        OP_EQUALVERIFY,
        expected_script_pubkey,
        OP_EQUALVERIFY,
        OP_EQUAL,
    ])


def hot_leaf(block_delay, hot_xonly):
    """After block_delay, the hot key may choose an unrestricted destination."""
    return CScript([
        block_delay,
        OP_CHECKSEQUENCEVERIFY,
        OP_DROP,
        hot_xonly,
        OP_CHECKSIG,
    ])


@dataclass(frozen=True)
class FixedTemplateVault:
    """The fixed-template single-hop vault, expressed through OP_TX."""

    hot_xonly: bytes
    cold_xonly: bytes
    fee_xonly: bytes
    vault_amount: int = FIXED_TEMPLATE_VAULT_AMOUNT
    step_fee: int = FIXED_TEMPLATE_STEP_FEE
    anchor_amount: int = ANCHOR_AMOUNT
    block_delay: int = BLOCK_DELAY

    @property
    def unvault_amount(self):
        return self.vault_amount - self.step_fee

    @property
    def final_amount(self):
        return self.unvault_amount - self.step_fee - self.anchor_amount

    @property
    def hot_leaf(self):
        return hot_leaf(self.block_delay, self.hot_xonly)

    @property
    def tocold_template(self):
        tx = CTransaction()
        tx.version = 2
        tx.vin = [blank_input()]
        tx.vout = [
            CTxOut(self.final_amount, p2tr_keypath_script(self.cold_xonly)),
            CTxOut(self.anchor_amount, p2tr_keypath_script(self.fee_xonly)),
        ]
        return tx

    @property
    def cold_leaf(self):
        return fixed_template_leaf(fixed_template_hash(self.tocold_template))

    @property
    def unvault_tap(self):
        return taproot_construct(NUMS_XONLY, [
            ("hot", self.hot_leaf, LEAF_VERSION_TAPSCRIPT_V2),
            ("cold", self.cold_leaf, LEAF_VERSION_TAPSCRIPT_V2),
        ])

    @property
    def unvault_template(self):
        tx = CTransaction()
        tx.version = 2
        tx.vin = [blank_input()]
        tx.vout = [CTxOut(self.unvault_amount, self.unvault_tap.scriptPubKey)]
        return tx

    @property
    def vault_leaf(self):
        return fixed_template_leaf(fixed_template_hash(self.unvault_template))

    @property
    def vault_tap(self):
        return taproot_construct(NUMS_XONLY, [
            ("vault", self.vault_leaf, LEAF_VERSION_TAPSCRIPT_V2),
        ])

    @property
    def vault_script_pubkey(self):
        return self.vault_tap.scriptPubKey


@dataclass(frozen=True)
class IndexedOutputVault:
    """A value-preserving vault whose deposit address is amount-independent."""

    hot_xonly: bytes
    cold_xonly: bytes
    block_delay: int = BLOCK_DELAY

    @property
    def hot_leaf(self):
        return hot_leaf(self.block_delay, self.hot_xonly)

    @property
    def cold_leaf(self):
        return indexed_output_leaf(p2tr_keypath_script(self.cold_xonly))

    @property
    def unvault_tap(self):
        return taproot_construct(NUMS_XONLY, [
            ("hot", self.hot_leaf, LEAF_VERSION_TAPSCRIPT_V2),
            ("cold", self.cold_leaf, LEAF_VERSION_TAPSCRIPT_V2),
        ])

    @property
    def vault_leaf(self):
        return indexed_output_leaf(self.unvault_tap.scriptPubKey)

    @property
    def vault_tap(self):
        return taproot_construct(NUMS_XONLY, [
            ("vault", self.vault_leaf, LEAF_VERSION_TAPSCRIPT_V2),
        ])

    @property
    def vault_script_pubkey(self):
        return self.vault_tap.scriptPubKey


class OpTxVaultsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-vbparams=script_restoration:0:3999999999"]]

    def activate_script_restoration(self):
        node = self.nodes[0]
        deployment = node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]

        while deployment["status"] != "started":
            assert_equal(deployment["status"], "defined")
            blocks = VERSIONBITS_PERIOD - (node.getblockcount() % VERSIONBITS_PERIOD)
            self.generate(node, blocks)
            deployment = node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]

        self.generate(node, 2 * deployment["statistics"]["period"])
        assert_equal(
            node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]["status"],
            "active",
        )

    def fund_outputs(self, outputs):
        """Fund every named test output in one wallet-signed transaction."""
        node = self.nodes[0]
        selected = max(
            self.nodesigner.listunspent(),
            key=lambda entry: int(entry["amount"] * COIN),
        )
        selected_value = int(selected["amount"] * COIN)
        funding_fee = 10_000
        output_value = sum(amount for _name, amount, _script in outputs)
        assert selected_value > output_value + funding_fee

        _pubkey, change_script, _address = self.nodesigner.getnewaddress(address_type="bech32")
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(selected["txid"], 16), int(selected["vout"])))]
        tx.vout = [CTxOut(amount, script) for _name, amount, script in outputs]
        tx.vout.append(CTxOut(selected_value - output_value - funding_fee, change_script))

        signed = self.nodesigner.signrawtransaction(tx.serialize().hex(), [selected])
        assert signed["complete"]
        tx = tx_from_hex(signed["hex"])
        txid = node.sendrawtransaction(tx.serialize().hex(), 0)
        self.generate(node, 1)

        return {
            name: (COutPoint(int(txid, 16), index), tx.vout[index])
            for index, (name, _amount, _script) in enumerate(outputs)
        }

    def script_path_witness(self, tx, input_index, tap, leaf_name, stack_prefix=()):
        """Reveal one leaf and its control block after any leaf arguments."""
        tx.wit.vtxinwit[input_index].scriptWitness.stack = [
            *stack_prefix,
            bytes(tap.leaves[leaf_name].script),
            control_block(tap, leaf_name),
        ]

    def fixed_unvault(self, plan, funded_vault):
        tx = copy.deepcopy(plan.unvault_template)
        tx.vin[0].prevout = funded_vault[0]
        tx.wit.vtxinwit = [CTxInWitness()]
        self.script_path_witness(tx, 0, plan.vault_tap, "vault")
        return tx

    def fixed_tocold(self, plan, funded_unvault):
        tx = copy.deepcopy(plan.tocold_template)
        tx.vin[0].prevout = funded_unvault[0]
        tx.wit.vtxinwit = [CTxInWitness()]
        self.script_path_witness(tx, 0, plan.unvault_tap, "cold")
        return tx

    def hot_spend(self, *, hot_priv, hot_leaf_script, tap, funded_unvault, amount, block_delay, anchor=None):
        """Spend the delayed leaf; unlike both covenant paths, outputs are signed."""
        _pubkey, destination_script, _address = self.nodesigner.getnewaddress(address_type="bech32")
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(funded_unvault[0], CScript(), block_delay)]
        tx.vout = [CTxOut(amount, destination_script)]
        if anchor is not None:
            tx.vout.append(anchor)
        tx.wit.vtxinwit = [CTxInWitness()]

        sighash = TaprootSignatureHash(
            tx,
            [funded_unvault[1]],
            SIGHASH_DEFAULT,
            scriptpath=True,
            leaf_script=hot_leaf_script,
            leaf_ver=LEAF_VERSION_TAPSCRIPT_V2,
            codeseparator_pos=0xffffffff,
        )
        self.script_path_witness(
            tx,
            0,
            tap,
            "hot",
            stack_prefix=[sign_schnorr(hot_priv, sighash)],
        )
        return tx

    def native_transition(self, *, leaf_tap, leaf_name, funded_covenant, funded_sponsor, next_script, extra_outputs=()):
        """Move the protected value and let a P2WSH sponsor pay transaction fees."""
        sponsor_outpoint, sponsor_output = funded_sponsor
        extra_value = sum(output.nValue for output in extra_outputs)
        sponsor_change = sponsor_output.nValue - SPONSOR_FEE - extra_value
        assert sponsor_change > 0

        _pubkey, change_script, _address = self.nodesigner.getnewaddress(address_type="bech32")
        tx = CTransaction()
        tx.version = 2
        tx.vin = [
            CTxIn(funded_covenant[0]),
            CTxIn(sponsor_outpoint),
        ]
        tx.vout = [
            CTxOut(funded_covenant[1].nValue, next_script),
            *extra_outputs,
            CTxOut(sponsor_change, change_script),
        ]
        tx.wit.vtxinwit = [CTxInWitness(), CTxInWitness()]
        self.script_path_witness(tx, 0, leaf_tap, leaf_name)
        tx.wit.vtxinwit[1].scriptWitness.stack = [bytes(SPONSOR_WITNESS_SCRIPT)]
        return tx

    def assert_allowed(self, tx, label):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], f"{label}: {result}"

    def assert_script_rejected(self, tx, label):
        result = self.nodes[0].testmempoolaccept([tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], f"{label} was unexpectedly accepted"
        assert "script-verify-flag-failed" in result.get("reject-reason", ""), (
            f"{label} failed for the wrong reason: {result}"
        )

    def broadcast_and_mine(self, tx):
        txid = self.nodes[0].sendrawtransaction(tx.serialize().hex(), 0)
        self.generate(self.nodes[0], 1)
        return COutPoint(int(txid, 16), 0), tx.vout[0]

    def test_fixed_template_vault(self, plan, hot_priv, funded):
        self.log.info("Chapter 1: fixed-template OP_TX vault")
        self.log.info("  A hash of the complete selected transaction template is the covenant")

        unvault = self.fixed_unvault(plan, funded["fixed_cold"])

        mutation = copy.deepcopy(unvault)
        mutation.vout[0].nValue -= 1
        self.assert_script_rejected(mutation, "fixed-template unvault amount mutation")

        mutation = copy.deepcopy(unvault)
        mutation.vout[0].scriptPubKey = p2tr_keypath_script(compute_xonly_pubkey(generate_privkey())[0])
        self.assert_script_rejected(mutation, "fixed-template unvault destination mutation")

        mutation = copy.deepcopy(unvault)
        mutation.vin[0].nSequence -= 1
        self.assert_script_rejected(mutation, "fixed-template unvault sequence mutation")

        self.assert_allowed(unvault, "fixed-template unvault")
        funded_unvault = self.broadcast_and_mine(unvault)

        tocold = self.fixed_tocold(plan, funded_unvault)
        redirected = copy.deepcopy(tocold)
        redirected.vout[0].scriptPubKey = p2tr_keypath_script(compute_xonly_pubkey(generate_privkey())[0])
        self.assert_script_rejected(redirected, "fixed-template cold-path redirection")
        self.assert_allowed(tocold, "fixed-template cold path")
        self.broadcast_and_mine(tocold)

        # A second vault exercises the delayed hot exit instead of the cold exit.
        hot_unvault = self.fixed_unvault(plan, funded["fixed_hot"])
        funded_hot_unvault = self.broadcast_and_mine(hot_unvault)
        hot_tx = self.hot_spend(
            hot_priv=hot_priv,
            hot_leaf_script=plan.hot_leaf,
            tap=plan.unvault_tap,
            funded_unvault=funded_hot_unvault,
            amount=plan.final_amount,
            block_delay=plan.block_delay,
            anchor=CTxOut(plan.anchor_amount, p2tr_keypath_script(plan.fee_xonly)),
        )

        premature = self.nodes[0].testmempoolaccept([hot_tx.serialize().hex()], maxfeerate=0)[0]
        assert not premature["allowed"]
        assert "non-BIP68-final" in premature.get("reject-reason", ""), premature
        self.generate(self.nodes[0], plan.block_delay - 1)
        self.assert_allowed(hot_tx, "mature fixed-template hot path")
        self.broadcast_and_mine(hot_tx)

    def test_native_indexed_output_vault(self, plan, hot_priv, funded):
        self.log.info("Chapter 2: native indexed-output OP_TX vault")
        self.log.info("  Output 0 preserves the vault value; sponsor inputs fund fees and change")

        unvault = self.native_transition(
            leaf_tap=plan.vault_tap,
            leaf_name="vault",
            funded_covenant=funded["native_cold"],
            funded_sponsor=funded["sponsor_native_cold_unvault"],
            next_script=plan.unvault_tap.scriptPubKey,
        )

        mutation = copy.deepcopy(unvault)
        mutation.vout[0].nValue -= 1
        self.assert_script_rejected(mutation, "native protected amount mutation")

        mutation = copy.deepcopy(unvault)
        mutation.vout[0].scriptPubKey = p2tr_keypath_script(compute_xonly_pubkey(generate_privkey())[0])
        self.assert_script_rejected(mutation, "native next-state mutation")

        mutation = copy.deepcopy(unvault)
        mutation.vin.reverse()
        mutation.wit.vtxinwit.reverse()
        self.assert_script_rejected(mutation, "native covenant moved away from input 0")

        self.assert_allowed(unvault, "native sponsored unvault")
        funded_unvault = self.broadcast_and_mine(unvault)

        tocold = self.native_transition(
            leaf_tap=plan.unvault_tap,
            leaf_name="cold",
            funded_covenant=funded_unvault,
            funded_sponsor=funded["sponsor_native_cold_exit"],
            next_script=p2tr_keypath_script(plan.cold_xonly),
        )
        redirected = copy.deepcopy(tocold)
        redirected.vout[0].scriptPubKey = p2tr_keypath_script(compute_xonly_pubkey(generate_privkey())[0])
        self.assert_script_rejected(redirected, "native cold-path redirection")
        self.assert_allowed(tocold, "native sponsored cold path")
        self.broadcast_and_mine(tocold)

        # A differently valued deposit uses the same vault address and takes the
        # same delayed hot path after a separately sponsored unvault.
        hot_unvault = self.native_transition(
            leaf_tap=plan.vault_tap,
            leaf_name="vault",
            funded_covenant=funded["native_hot"],
            funded_sponsor=funded["sponsor_native_hot_unvault"],
            next_script=plan.unvault_tap.scriptPubKey,
        )
        funded_hot_unvault = self.broadcast_and_mine(hot_unvault)
        hot_tx = self.hot_spend(
            hot_priv=hot_priv,
            hot_leaf_script=plan.hot_leaf,
            tap=plan.unvault_tap,
            funded_unvault=funded_hot_unvault,
            amount=funded_hot_unvault[1].nValue - HOT_SPEND_FEE,
            block_delay=plan.block_delay,
        )

        premature = self.nodes[0].testmempoolaccept([hot_tx.serialize().hex()], maxfeerate=0)[0]
        assert not premature["allowed"]
        assert "non-BIP68-final" in premature.get("reject-reason", ""), premature
        self.generate(self.nodes[0], plan.block_delay - 1)
        self.assert_allowed(hot_tx, "mature native hot path")
        self.broadcast_and_mine(hot_tx)

    def test_side_by_side(self, fixed_plan, native_plan, funded):
        self.log.info("Chapter 3: side-by-side developer trade-offs")

        # Apply the same practical fee-sponsorship shape to both vaults: append
        # a valid input, pay an unrelated output, and return sponsor change.
        _pubkey, extra_script, _address = self.nodesigner.getnewaddress(address_type="bech32")
        _pubkey, change_script, _address = self.nodesigner.getnewaddress(address_type="bech32")
        extra_output = CTxOut(100_000, extra_script)
        sponsor_change = CTxOut(
            funded["sponsor_compare"][1].nValue - SPONSOR_FEE - extra_output.nValue,
            change_script,
        )

        # The fixed selector includes every input sequence and output, so the
        # useful sponsor additions change the committed digest.
        fixed_sponsored = self.fixed_unvault(fixed_plan, funded["fixed_compare"])
        fixed_sponsored.vin.append(CTxIn(funded["sponsor_compare"][0]))
        fixed_sponsored.vout.extend([extra_output, sponsor_change])
        fixed_sponsored.wit.vtxinwit.append(CTxInWitness())
        fixed_sponsored.wit.vtxinwit[1].scriptWitness.stack = [bytes(SPONSOR_WITNESS_SCRIPT)]
        self.assert_script_rejected(fixed_sponsored, "fixed-template vault with sponsor additions")

        # The native covenant permits both a fee input and an unrelated output.
        # Output 0 still contains the entire covenant input amount, so the extra
        # output and change are necessarily paid by the sponsor.
        native_sponsored = self.native_transition(
            leaf_tap=native_plan.vault_tap,
            leaf_name="vault",
            funded_covenant=funded["native_compare"],
            funded_sponsor=funded["sponsor_compare"],
            next_script=native_plan.unvault_tap.scriptPubKey,
            extra_outputs=[extra_output],
        )
        self.assert_allowed(native_sponsored, "native vault with sponsor change and an extra output")

        # A fixed template bakes the amount into the deposit address. The native
        # script commits only to the next output script and works at any amount.
        fixed_other_amount = FixedTemplateVault(
            hot_xonly=fixed_plan.hot_xonly,
            cold_xonly=fixed_plan.cold_xonly,
            fee_xonly=fixed_plan.fee_xonly,
            vault_amount=fixed_plan.vault_amount + 1,
        )
        assert fixed_other_amount.vault_script_pubkey != fixed_plan.vault_script_pubkey
        assert_equal(funded["native_cold"][1].scriptPubKey, funded["native_hot"][1].scriptPubKey)
        assert_equal(funded["native_cold"][1].scriptPubKey, native_plan.vault_script_pubkey)

        self.log.info(
            f"  fixed-template leaf: {len(fixed_plan.vault_leaf)} bytes; "
            f"native indexed-output leaf: {len(native_plan.vault_leaf)} bytes"
        )
        self.log.info("  fixed template: simpler audit, but amount- and transaction-specific")
        self.log.info("  native OP_TX: more script to audit, but amount-independent and sponsor-friendly")
        assert_equal(len(native_plan.vault_leaf), 47)
        assert_equal(len(fixed_plan.vault_leaf), 43)
        assert len(fixed_plan.vault_leaf) < len(native_plan.vault_leaf)

    def run_test(self):
        node = self.nodes[0]
        self.nodesigner = NodeSigner(node)
        self.generatetoaddress(
            node,
            COINBASE_MATURITY + 1,
            self.nodesigner.getnewaddress(address_type="bech32")[2],
        )

        self.log.info("Activate the 0xc2 Tapscript v2 leaf version")
        self.activate_script_restoration()

        hot_priv = generate_privkey()
        hot_xonly = compute_xonly_pubkey(hot_priv)[0]
        cold_xonly = compute_xonly_pubkey(generate_privkey())[0]
        fee_xonly = compute_xonly_pubkey(generate_privkey())[0]
        fixed_plan = FixedTemplateVault(hot_xonly, cold_xonly, fee_xonly)
        native_plan = IndexedOutputVault(hot_xonly, cold_xonly)

        funded = self.fund_outputs([
            ("fixed_cold", fixed_plan.vault_amount, fixed_plan.vault_script_pubkey),
            ("fixed_hot", fixed_plan.vault_amount, fixed_plan.vault_script_pubkey),
            ("fixed_compare", fixed_plan.vault_amount, fixed_plan.vault_script_pubkey),
            ("native_cold", 12_345_678, native_plan.vault_script_pubkey),
            ("native_hot", 23_456_789, native_plan.vault_script_pubkey),
            ("native_compare", 17_000_000, native_plan.vault_script_pubkey),
            ("sponsor_compare", SPONSOR_AMOUNT, SPONSOR_SCRIPT_PUBKEY),
            ("sponsor_native_cold_unvault", SPONSOR_AMOUNT, SPONSOR_SCRIPT_PUBKEY),
            ("sponsor_native_cold_exit", SPONSOR_AMOUNT, SPONSOR_SCRIPT_PUBKEY),
            ("sponsor_native_hot_unvault", SPONSOR_AMOUNT, SPONSOR_SCRIPT_PUBKEY),
        ])

        self.test_fixed_template_vault(fixed_plan, hot_priv, funded)
        self.test_native_indexed_output_vault(native_plan, hot_priv, funded)
        self.test_side_by_side(fixed_plan, native_plan, funded)


if __name__ == "__main__":
    OpTxVaultsTest(__file__).main()
