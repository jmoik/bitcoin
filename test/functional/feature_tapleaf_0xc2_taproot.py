#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replay Taproot script-path coverage with Tapleaf 0xC2 leaves."""

import random

import feature_taproot as taproot
from feature_tapleaf_0xc2 import (
    TAPLEAF_0XC2_VBPARAMS,
    advance_tapleaf_0xc2_to_started,
    tapleaf_0xc2_bip9,
)

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.script import (
    CScript,
    LEAF_VERSION_0XC2,
    LEAF_VERSION_TAPSCRIPT,
    OP_1,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
)
from test_framework.util import assert_equal
from test_framework.wallet import NodeSigner


_ORIGINAL_TAPROOT_CONSTRUCT = taproot.taproot_construct


def _script_tree_to_0xc2(scripts):
    if scripts is None or callable(scripts):
        return scripts

    if isinstance(scripts, tuple):
        if len(scripts) == 2:
            return (scripts[0], scripts[1], LEAF_VERSION_0XC2)
        if len(scripts) == 3 and scripts[2] == LEAF_VERSION_TAPSCRIPT:
            return (scripts[0], scripts[1], LEAF_VERSION_0XC2)
        return scripts

    if isinstance(scripts, list):
        return [_script_tree_to_0xc2(script) for script in scripts]

    return scripts


def taproot_construct_0xc2(pubkey, scripts=None, **kwargs):
    return _ORIGINAL_TAPROOT_CONSTRUCT(pubkey, _script_tree_to_0xc2(scripts), **kwargs)


def random_checksig_style_0xc2(pubkey):
    # feature_taproot's version can also pick OP_CHECKSIGADD with CScriptNum
    # operands, some negative, which are not Tapleaf 0xC2 numbers.
    opcode = random.choice([OP_CHECKSIG, OP_CHECKSIGVERIFY])
    if opcode == OP_CHECKSIGVERIFY:
        return bytes(CScript([pubkey, opcode, OP_1]))
    return bytes(CScript([pubkey, opcode]))


def is_tapleaf_0xc2_replay_spender(spender):
    comment = spender.comment

    # Replay only cases that exercise a script path converted to 0xc2. Key-path,
    # legacy, witness-v0, sighash-cache, and unrelated unknown-leaf cases are
    # already covered by feature_taproot.py without involving Tapleaf 0xC2.
    if comment.startswith(("sig/", "legacy/", "compat/", "sighashcache/", "unkver/")):
        return False
    if "keypath" in comment or comment == "sighash/purepk":
        return False

    # These are not 0xc2 leaf replay coverage: they validate future leaf versions
    # and OP_SUCCESSx behavior, whose opcode set differs under 0xc2.
    if comment.startswith(("opsuccess/", "alwaysvalid/")):
        return False

    # The BIP 441 test vectors cover the changed element, stack, numeric, and
    # signature-budget rules. This file keeps the inherited Taproot
    # matrix focused on behavior that should remain equivalent under 0xc2.
    changed_semantics = {
        "sighash/leafver",
        "tapscript/inputmaxlimit",
        "tapscript/input81limit",
        "tapscript/checksigaddresults",
        "tapscript/checksigaddoversize",
        "tapscript/1000stack",
        "tapscript/1000inputs",
        "tapscript/pushmaxlimit",
        "tapscript/bigmulti",
    }
    if comment in changed_semantics:
        return False
    if comment.startswith("tapscript/sigopsratio_"):
        return False
    if comment.startswith("tapscript/oldpk/"):
        return False

    return True


def tapleaf_0xc2_taproot_spenders():
    original_random_checksig_style = taproot.random_checksig_style
    try:
        taproot.taproot_construct = taproot_construct_0xc2
        taproot.random_checksig_style = random_checksig_style_0xc2
        return [
            spender
            for spender in taproot.spenders_taproot_active()
            if is_tapleaf_0xc2_replay_spender(spender)
        ]
    finally:
        taproot.taproot_construct = _ORIGINAL_TAPROOT_CONSTRUCT
        taproot.random_checksig_style = original_random_checksig_style


class Tapleaf0xC2TaprootTest(taproot.TaprootTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [[TAPLEAF_0XC2_VBPARAMS]]

    def run_test(self):
        random.seed(442)
        self.nodesigner = NodeSigner(self.nodes[0])

        self.generatetoaddress(
            self.nodes[0],
            COINBASE_MATURITY + 1,
            self.nodesigner.getnewaddress(address_type="bech32")[2],
        )

        self.log.info("Activating Tapleaf 0xC2")
        self.activate_tapleaf_0xc2()

        self.log.info("Tapleaf 0xC2 Taproot replay tests")
        self.test_spenders(self.nodes[0], tapleaf_0xc2_taproot_spenders(), input_counts=[1, 2, 2, 2, 2, 3])

    def activate_tapleaf_0xc2(self):
        node = self.nodes[0]
        advance_tapleaf_0xc2_to_started(self, node)
        self.generate(node, 2 * tapleaf_0xc2_bip9(node)["statistics"]["period"])
        assert_equal(tapleaf_0xc2_bip9(node)["status"], "active")


if __name__ == "__main__":
    Tapleaf0xC2TaprootTest(__file__).main()
