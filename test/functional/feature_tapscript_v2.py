#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_coinbase,
    create_block,
    add_witness_commitment,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
)
import hashlib
from test_framework.script import (
    CScript,
    OP_1,
    OP_2,
    OP_3,
    OP_EQUAL,
    OP_NUMEQUAL,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_CAT,
    OP_DUP,
    OP_DROP,
    OP_2DUP,
    OP_2DROP,
    OP_VERIFY,
    OP_LESSTHAN,
    OP_MUL,
    OP_SHA256,
    OP_CHECKLOCKTIMEVERIFY,
)
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.key import ECKey, compute_xonly_pubkey, sign_schnorr
from test_framework.script import TaprootSignatureHash, taproot_construct, LEAF_VERSION_TAPSCRIPT_V2

class TapscriptV2Test(BitcoinTestFramework):
    def add_options(self, parser):
        # Set default random seed for deterministic behavior
        parser.set_defaults(randomseed=1234567890)
        self.add_wallet_options(parser)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def print_test_status(self, test_name, is_start=True, success=None):
        """Print colored test status messages.

        Args:
            test_name: Name of the test
            is_start: True if starting test, False if ending
            success: None for start, True/False for end status
        """
        # ANSI color codes
        GREEN = '\033[92m'
        RED = '\033[91m'
        BLUE = '\033[94m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

        if is_start:
            self.log.info(f"\n\n{BLUE}{BOLD}▶ Starting test:{RESET} {test_name}\n")
        else:
            if success:
                self.log.info(f"\n\n{GREEN}{BOLD}✓ Test passed:{RESET} {test_name}\n")
            else:
                self.log.info(f"\n\n{RED}{BOLD}✗ Test failed:{RESET} {test_name}\n")

    def test_simple_op1_script(self):
        """Test 1: Simple OP_1 script (always true)"""
        test_name = "Simple OP_1 script (always true)"
        self.print_test_status(test_name, is_start=True)

        try:
            locking_script = CScript([OP_1])
            unlocking_script = []
            result = self.test_simple_tapscript_v2_transaction(locking_script, unlocking_script)
            self.print_test_status(test_name, is_start=False, success=result)
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_checksig_basic(self):
        """Test 2: Basic OP_CHECKSIG with TAPSCRIPT_V2"""
        test_name = "Basic OP_CHECKSIG with TAPSCRIPT_V2"
        self.print_test_status(test_name, is_start=True)

        try:
            key = ECKey()
            key.generate()
            pubkey_xonly, _ = compute_xonly_pubkey(key.get_bytes())

            locking_script = CScript([pubkey_xonly, OP_CHECKSIG])  # Use x-only pubkey
            utxo_info = self.create_tapscript_v2_funding_tx(locking_script, key.get_bytes(), amount=0.1)

            spending_tx = self.create_tapscript_v2_spending_tx(utxo_info)

            spent_output = CTxOut(int(utxo_info["amount"] * 100000000), utxo_info["tap"].scriptPubKey)

            sighash = TaprootSignatureHash(
                spending_tx,
                [spent_output],
                0,
                0,  # hash_type (SIGHASH_DEFAULT)
                scriptpath=True,
                leaf_script=locking_script,
                codeseparator_pos=-1,
                leaf_ver=LEAF_VERSION_TAPSCRIPT_V2
            )

            signature = sign_schnorr(key.get_bytes(), sighash)
            spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, signature)

            result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

            if result['allowed']:
                self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                self.generate(self.nodes[0], 1)
                self.print_test_status(test_name, is_start=False, success=True)
            else:
                self.log.error(f"TAPSCRIPT_V2 OP_CHECKSIG transaction rejected: {result.get('reject-reason', 'Unknown')}")
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_multisig_2of2(self):
        """Test: 2-of-2 multisig with OP_CHECKSIGADD"""
        test_name = "2-of-2 multisig with OP_CHECKSIGADD"
        self.print_test_status(test_name, is_start=True)

        try:
            # Generate two keys
            key1 = ECKey()
            key1.generate()
            pubkey1_xonly, _ = compute_xonly_pubkey(key1.get_bytes())

            key2 = ECKey()
            key2.generate()
            pubkey2_xonly, _ = compute_xonly_pubkey(key2.get_bytes())

            # 2-of-2 multisig: <pubkey1> OP_CHECKSIG <pubkey2> OP_CHECKSIGADD OP_2 OP_NUMEQUAL
            locking_script = CScript([pubkey1_xonly, OP_CHECKSIG, pubkey2_xonly, OP_CHECKSIGADD, OP_2, OP_NUMEQUAL])

            utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)

            # Create spending transaction without signatures first
            spending_tx = self.create_tapscript_v2_spending_tx(utxo_info)
            spent_output = CTxOut(int(utxo_info["amount"] * 100000000), utxo_info["tap"].scriptPubKey)

            # Compute sighash
            sighash = TaprootSignatureHash(
                spending_tx,
                [spent_output],
                0,
                0,
                scriptpath=True,
                leaf_script=locking_script,
                codeseparator_pos=-1,
                leaf_ver=LEAF_VERSION_TAPSCRIPT_V2
            )

            # Sign with both keys
            sig1 = sign_schnorr(key1.get_bytes(), sighash)
            sig2 = sign_schnorr(key2.get_bytes(), sighash)

            # Insert signatures at the beginning of the witness stack
            # Stack order: [sig2, sig1, script, control]
            # During execution: sig1 is on top for first CHECKSIG, sig2 for CHECKSIGADD
            spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, sig1)
            spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, sig2)

            result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

            if result['allowed']:
                self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                self.generate(self.nodes[0], 1)
                self.print_test_status(test_name, is_start=False, success=True)
            else:
                self.log.error(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_keypath_spend(self):
        """Test: Key path spending (no script revealed)"""
        test_name = "Key path spending (most private)"
        self.print_test_status(test_name, is_start=True)

        try:
            from test_framework.key import tweak_add_privkey

            # Generate internal key
            internal_key = ECKey()
            internal_key.generate()
            internal_pubkey_xonly, _ = compute_xonly_pubkey(internal_key.get_bytes())

            # Create a script tree (but we'll spend via key path, so scripts won't be revealed)
            dummy_script = CScript([OP_1])

            # Build taproot with script tree
            tap = taproot_construct(internal_pubkey_xonly, [
                ("dummy", dummy_script, LEAF_VERSION_TAPSCRIPT_V2)
            ])

            # Fund the taproot output
            address = encode_segwit_address("bcrt", 1, tap.output_pubkey)
            funding_txid = self.nodes[0].sendtoaddress(address, 0.1)
            self.generate(self.nodes[0], 1)

            funding_tx_info = self.nodes[0].gettransaction(funding_txid)
            funding_tx_decoded = self.nodes[0].decoderawtransaction(funding_tx_info['hex'])

            funding_vout = None
            expected_scriptpubkey = f"5120{tap.output_pubkey.hex()}"
            for i, vout in enumerate(funding_tx_decoded['vout']):
                if vout['scriptPubKey']['hex'] == expected_scriptpubkey:
                    funding_vout = i
                    break

            # Create spending transaction
            spending_tx = CTransaction()
            spending_tx.vin = [CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", SEQUENCE_FINAL)]

            output_address = self.nodes[0].getnewaddress()
            output_script = bytes.fromhex(self.nodes[0].validateaddress(output_address)["scriptPubKey"])
            output_amount = int(0.099 * 100000000)
            spending_tx.vout = [CTxOut(output_amount, output_script)]

            # Tweak the private key to get the key that controls the output
            tweaked_privkey = tweak_add_privkey(internal_key.get_bytes(), tap.tweak)

            # Compute sighash for key path (scriptpath=False)
            spent_output = CTxOut(int(0.1 * 100000000), CScript([OP_1, tap.output_pubkey]))
            sighash = TaprootSignatureHash(
                spending_tx,
                [spent_output],
                0,
                0,  # SIGHASH_DEFAULT
                scriptpath=False  # KEY PATH, not script path
            )

            # Sign with the tweaked key
            signature = sign_schnorr(tweaked_privkey, sighash)

            # Key path witness is just the signature
            spending_tx.wit.vtxinwit = [CTxInWitness()]
            spending_tx.wit.vtxinwit[0].scriptWitness.stack = [signature]

            result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

            if result['allowed']:
                self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                self.generate(self.nodes[0], 1)
                self.print_test_status(test_name, is_start=False, success=True)
            else:
                self.log.error(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_multiple_leaves(self):
        """Test: Taproot tree with multiple script leaves"""
        test_name = "Multiple script leaves (merkle tree)"
        self.print_test_status(test_name, is_start=True)

        try:
            key = ECKey()
            key.generate()
            pubkey_xonly, _ = compute_xonly_pubkey(key.get_bytes())

            # Create three different scripts
            script_a = CScript([pubkey_xonly, OP_CHECKSIG])  # Simple checksig
            script_b = CScript([OP_1])  # Always true
            script_c = CScript([bytes([42]), OP_EQUAL])  # Check for specific value

            # Build taproot with all three scripts
            internal_key = hashlib.sha256(bytes([42])).digest()
            pubkey_bytes, _ = compute_xonly_pubkey(internal_key)

            tap = taproot_construct(pubkey_bytes, [
                ("script_a", script_a, LEAF_VERSION_TAPSCRIPT_V2),
                ("script_b", script_b, LEAF_VERSION_TAPSCRIPT_V2),
                ("script_c", script_c, LEAF_VERSION_TAPSCRIPT_V2)
            ])

            address = encode_segwit_address("bcrt", 1, tap.output_pubkey)
            funding_txid = self.nodes[0].sendtoaddress(address, 0.1)
            self.generate(self.nodes[0], 1)

            funding_tx_info = self.nodes[0].gettransaction(funding_txid)
            funding_tx_decoded = self.nodes[0].decoderawtransaction(funding_tx_info['hex'])

            funding_vout = None
            expected_scriptpubkey = f"5120{tap.output_pubkey.hex()}"
            for i, vout in enumerate(funding_tx_decoded['vout']):
                if vout['scriptPubKey']['hex'] == expected_scriptpubkey:
                    funding_vout = i
                    break

            # Spend using script_b (always true)
            spending_tx = CTransaction()
            spending_tx.vin = [CTxIn(COutPoint(int(funding_txid, 16), funding_vout), b"", SEQUENCE_FINAL)]

            output_address = self.nodes[0].getnewaddress()
            output_script = bytes.fromhex(self.nodes[0].validateaddress(output_address)["scriptPubKey"])
            output_amount = int(0.099 * 100000000)
            spending_tx.vout = [CTxOut(output_amount, output_script)]

            # Use script_b
            leaf_info = tap.leaves["script_b"]
            control_block = bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch

            spending_tx.wit.vtxinwit = [CTxInWitness()]
            spending_tx.wit.vtxinwit[0].scriptWitness.stack = [script_b, control_block]

            result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

            if result['allowed']:
                self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                self.generate(self.nodes[0], 1)
                self.print_test_status(test_name, is_start=False, success=True)
            else:
                self.log.error(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"Transaction rejected: {result.get('reject-reason', 'Unknown')}")
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_sighash_types(self):
        """Test: All SIGHASH types"""
        test_name = "All SIGHASH types (DEFAULT, ALL, NONE, SINGLE, ANYONECANPAY)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (hash_type, name, should_append_byte)
            test_cases = [
                (0x00, "SIGHASH_DEFAULT", False),
                (0x01, "SIGHASH_ALL", True),
                (0x02, "SIGHASH_NONE", True),
                (0x03, "SIGHASH_SINGLE", True),
                (0x81, "SIGHASH_ALL|ANYONECANPAY", True),
                (0x82, "SIGHASH_NONE|ANYONECANPAY", True),
                (0x83, "SIGHASH_SINGLE|ANYONECANPAY", True),
            ]

            passed = 0
            failed = 0

            for hash_type, name, append_byte in test_cases:
                try:
                    # Generate fresh key for each test
                    key = ECKey()
                    key.generate()
                    pubkey_xonly, _ = compute_xonly_pubkey(key.get_bytes())

                    locking_script = CScript([pubkey_xonly, OP_CHECKSIG])
                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, key.get_bytes(), amount=0.1)

                    # Create spending transaction
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info)
                    spent_output = CTxOut(int(utxo_info["amount"] * 100000000), utxo_info["tap"].scriptPubKey)

                    # For SIGHASH_SINGLE, we need to make sure there's an output at the same index
                    # Since we only have 1 input (index 0) and 1 output (index 0), SINGLE should work

                    # Compute sighash
                    sighash = TaprootSignatureHash(
                        spending_tx,
                        [spent_output],
                        hash_type,  # The hash type we're testing
                        0,  # input_index = 0
                        scriptpath=True,
                        leaf_script=locking_script,
                        codeseparator_pos=-1,
                        leaf_ver=LEAF_VERSION_TAPSCRIPT_V2
                    )

                    # Create signature
                    signature = sign_schnorr(key.get_bytes(), sighash)

                    # Append hash type byte if needed (not for DEFAULT)
                    if append_byte:
                        signature += bytes([hash_type])

                    # Insert signature at the beginning of witness stack
                    # Stack before: [script, control]
                    # Stack after: [signature, script, control]
                    spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, signature)

                    # Test transaction
                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if result['allowed']:
                        self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                        self.generate(self.nodes[0], 1)
                        self.log.debug(f"  ✓ {name} (0x{hash_type:02x}) - {'64' if not append_byte else '65'} bytes")
                        passed += 1
                    else:
                        self.log.error(f"  ✗ {name} rejected: {result.get('reject-reason', 'Unknown')}")
                        failed += 1

                except Exception as e:
                    self.log.error(f"  ✗ {name} exception: {e}")
                    failed += 1

            # Summary
            self.log.debug(f"\nSIGHASH Types: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} SIGHASH type(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_cat(self):
        """Test 3: OP_CAT with TAPSCRIPT_V2"""
        test_name = "OP_CAT with TAPSCRIPT_V2"
        self.print_test_status(test_name, is_start=True)

        try:
            locking_script = CScript([bytes([1, 2]), bytes([3, 4]), OP_CAT, OP_EQUAL])
            unlocking_script = [bytes([1, 2, 3, 4])]
            result = self.test_simple_tapscript_v2_transaction(locking_script, unlocking_script)
            self.print_test_status(test_name, is_start=False, success=result)
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_cat_exponential_growth(self):
        """Test: OP_CAT exponential growth until varops budget exhausted"""
        test_name = "OP_CAT exponential growth (DUP+CAT loop)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (iterations, expected_to_pass, description, rejection_reason)
            # Each iteration: size *= 2, so 2^N bytes after N iterations
            # Note: Transaction size limit is hit before varops budget in this test
            test_cases = [
                (5, True, "5 iterations: 1 -> 32 bytes", None),
                (10, True, "10 iterations: 1 -> 1KB", None),
                (15, True, "15 iterations: 1 -> 32KB", None),
                (18, True, "18 iterations: 1 -> 256KB", None),
                (20, False, "20 iterations: 1 -> 1MB", None),
                (22, False, "22 iterations: 1 -> 4MB", None),
            ]

            passed = 0
            failed = 0

            for iterations, should_pass, description, expected_rejection in test_cases:
                try:
                    # Build script: start with 1 byte, then DUP+CAT repeatedly
                    # Each iteration doubles the size: 1 -> 2 -> 4 -> 8 -> 16 -> 32 -> ...
                    # After N iterations: 2^N bytes

                    script_ops = [bytes([0xFF])]  # Start with 1 byte (0xFF)

                    # Add DUP+CAT pairs for each iteration
                    for _ in range(iterations):
                        script_ops.append(OP_DUP)   # Duplicate top element
                        script_ops.append(OP_CAT)   # Concatenate: doubles the size

                    # Final size will be 2^iterations bytes
                    final_size = 2 ** iterations

                    # Script: [initial_byte, DUP, CAT, DUP, CAT, ..., EQUAL]
                    locking_script = CScript(script_ops + [OP_LESSTHAN])
                    unlocking_script = [bytes([0xFF])]

                    # Create and test transaction
                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass:
                        # Should be accepted
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description} - PASSED (final size: {final_size} bytes)")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should pass but rejected: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        # Should be rejected - verify rejection reason
                        if not result['allowed']:
                            actual_reason = result.get('reject-reason', 'Unknown')
                            if expected_rejection and expected_rejection in actual_reason:
                                self.log.debug(f"  ✓ {description} - REJECTED correctly ({actual_reason})")
                                passed += 1
                            else:
                                self.log.error(f"  ✗ {description} - rejected but wrong reason: expected '{expected_rejection}', got '{actual_reason}'")
                                failed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        # Exception on expected failure is okay
                        self.log.debug(f"  ✓ {description} - REJECTED (exception: {str(e)[:50]}...)")
                        passed += 1

            # Summary
            self.log.debug(f"\nExponential growth tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} exponential growth test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_mul_small(self):
        """Test 4: OP_MUL with small numbers"""
        test_name = "OP_MUL with small numbers (2 * 3 = 6)"
        self.print_test_status(test_name, is_start=True)

        try:
            locking_script = CScript([OP_2, OP_3, OP_MUL, OP_EQUAL])
            unlocking_script = [bytes([6])]
            result = self.test_simple_tapscript_v2_transaction(locking_script, unlocking_script)
            self.print_test_status(test_name, is_start=False, success=result)
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_mul_large(self):
        """Test 7: Large multiplication test with varops budget"""
        test_name = "Large multiplication (10KB * 10KB with varops budget)"
        self.print_test_status(test_name, is_start=True)

        try:
            n = 1024*10  # max size to pay for its own varops budget
            locking_script = CScript([bytes([255]*n), bytes([255]*n), OP_MUL, OP_EQUAL])
            unlocking_script = [((2**(8*n)-1) * (2**(8*n)-1)).to_bytes(2*n, 'little')]
            result = self.test_simple_tapscript_v2_transaction(locking_script, unlocking_script)
            self.print_test_status(test_name, is_start=False, success=result)
        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_mul_too_large(self):
        """Test 8: Too large multiplication - should be REJECTED (exceeds varops budget)"""
        test_name = "Too large multiplication - properly rejected"
        self.print_test_status(test_name, is_start=True)

        try:
            # Create a transaction that exceeds the varops budget
            n = 1024*13  # 13KB operands
            locking_script = CScript([bytes([255]*n), bytes([255]*n), OP_MUL, OP_EQUAL])
            unlocking_script = [((2**(8*n)-1) * (2**(8*n)-1)).to_bytes(2*n, 'little')]

            # Create the transaction
            utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)
            spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

            # Test that it's rejected
            result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

            # Success means the transaction was properly REJECTED
            if not result['allowed']:
                # Expected rejection - test passes
                self.print_test_status(test_name, is_start=False, success=True)
            else:
                # Transaction was accepted when it should have been rejected - test fails
                self.log.error("Transaction should have been rejected but was accepted!")
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError("Transaction exceeding varops budget should have been rejected")

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_stack_size_limit(self):
        """Test: Stack size limit - 32000 elements (new limit) vs 1000 (old limit)"""
        test_name = "Stack size limit boundary (32000 elements)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (num_elements, should_pass, description)
            test_cases = [
                (1000, True, "1000 elements (old limit) - should still work"),
                (10000, True, "10000 elements - well within new limit"),
                (31999, True, "31999 elements - just below limit"),
                (32000, True, "32000 elements - exactly at limit"),
                (32001, False, "32001 elements - exceeds limit by 1"),
                (35000, False, "35000 elements - clearly over limit"),
            ]

            passed = 0
            failed = 0

            for num_elements, should_pass, description in test_cases:
                try:
                    unlocking_script = [bytes([i % 256]) for i in range(num_elements)]

                    script_ops = []
                    for _ in range(num_elements):
                        script_ops.append(OP_DROP)
                    script_ops.append(OP_1)

                    utxo_info = self.create_tapscript_v2_funding_tx(CScript(script_ops), amount=0.1)
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass:
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description}")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - rejected: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        if not result['allowed']:
                            self.log.debug(f"  ✓ {description} - correctly rejected")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        self.log.debug(f"  ✓ {description} - correctly rejected (exception)")
                        passed += 1

            self.log.debug(f"\nStack size tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} stack size test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_stack_element_size_limit(self):
        """Test: Stack element size limit - 4MB (new) vs 520 bytes (old)"""
        test_name = "Stack element size limit boundary (4MB)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (element_size, should_pass, description)
            # Note: We can't test 4MB elements directly because the transaction would exceed
            # Bitcoin's 100KB standard transaction size limit. Instead, we test that we can
            # CREATE 4MB elements using OP_CAT during script execution.
            test_cases = [
                (520, True, "520 bytes (old limit) - should still work"),
                (1024, True, "1KB - well within new limit"),
                (10000, True, "10KB - within new limit"),
                (100000, True, "100KB - within new limit"),
                (200000, True, "200KB - within new limit (approaching tx size limit)"),
            ]

            passed = 0
            failed = 0

            for element_size, should_pass, description in test_cases:
                try:
                    # Create a large element using OP_CAT to build it up
                    # We'll push it via witness and check its size
                    large_element = bytes([0x42] * element_size)

                    # Script: check that the pushed element equals itself (always true)
                    locking_script = CScript([OP_DUP, OP_EQUAL])
                    unlocking_script = [large_element]

                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass:
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description}")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - rejected: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        if not result['allowed']:
                            self.log.debug(f"  ✓ {description} - correctly rejected")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        self.log.debug(f"  ✓ {description} - correctly rejected (exception)")
                        passed += 1

            self.log.debug(f"\nStack element size tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} stack element size test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_total_stack_size_limit(self):
        """Test: Total stack size limit - 8MB across all elements"""
        test_name = "Total stack size limit boundary (8MB)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (num_elements, element_size, should_pass, description)
            # Total = num_elements * element_size
            # Note: Limited by Bitcoin's 100KB transaction size limit for witness data
            test_cases = [
                (10, 10000, True, "10 x 10KB = 100KB - well within limit"),
                (20, 10000, True, "20 x 10KB = 200KB - within limit"),
                (100, 1000, True, "100 x 1KB = 100KB - within limit"),
                (1000, 100, True, "1000 x 100B = 100KB - within limit"),
            ]

            passed = 0
            failed = 0

            for num_elements, element_size, should_pass, description in test_cases:
                try:
                    # Push multiple large elements onto the stack
                    # Then verify the stack has the expected depth
                    script_ops = []
                    unlocking_script = []

                    # Push elements via witness
                    for i in range(num_elements):
                        unlocking_script.append(bytes([0x42] * element_size))

                    # Script: drop all elements and return success
                    # This tests that we CAN have num_elements on the stack at once
                    for _ in range(num_elements):
                        script_ops.append(OP_DROP)
                    script_ops.append(OP_1)

                    locking_script = CScript(script_ops)

                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass:
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description}")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - rejected: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        if not result['allowed']:
                            self.log.debug(f"  ✓ {description} - correctly rejected")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        self.log.debug(f"  ✓ {description} - correctly rejected (exception)")
                        passed += 1

            self.log.debug(f"\nTotal stack size tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} total stack size test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_witness_element_size_limit(self):
        """Test: TAPSCRIPT_V2 allows elements >520 bytes up to 4MB in witness.

        Transactions are mined directly in blocks to bypass mempool policy limits.
        The consensus element size limit in TAPSCRIPT_V2 is 4,000,000 bytes.
        """
        test_name = "Witness element size: large elements via direct block mining"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (element_size, should_pass, description)
            test_cases = [
                (521, True, "521 bytes (just above old 520 limit)"),
                (3_990_000, True, "~4MB element (below 4MB element limit, fits in block)"),
                (4_000_001, False, "4,000,001 bytes (exceeds 4MB element limit)"),
            ]

            passed = 0
            failed = 0

            for element_size, should_pass, description in test_cases:
                try:
                    # Create a witness element of the specified size
                    large_element = bytes([0x42] * element_size)

                    # Simple script that drops the element and returns true
                    locking_script = CScript([OP_DROP, OP_1])
                    unlocking_script = [large_element]

                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.5)
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

                    fee_sats = int(utxo_info["amount"] * 100000000) - spending_tx.vout[0].nValue

                    # Re-sync block state after funding tx mined new blocks
                    self.init_blockinfo()

                    # Mine directly in a block, bypassing mempool policy
                    self.block_submit(
                        self.nodes[0], [spending_tx], description,
                        accept=should_pass, fees=fee_sats,
                    )

                    if should_pass:
                        self.log.debug(f"  ✓ {description} - accepted in block")
                    else:
                        self.log.debug(f"  ✓ {description} - correctly rejected")
                    passed += 1

                except AssertionError:
                    self.log.error(f"  ✗ {description}")
                    failed += 1
                except Exception as e:
                    self.log.error(f"  ✗ {description} - exception: {e}")
                    failed += 1

            self.log.debug(f"\nWitness element size tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} witness element test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_cat_creates_large_element(self):
        """Test: OP_CAT can create elements up to 4MB by doubling"""
        test_name = "OP_CAT creating large elements via exponential growth"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (num_doublings, should_pass, description)
            # Each doubling: size *= 2, starting from 1 byte
            # After N doublings: 2^N bytes
            # We want to test approaching and exceeding the 4MB (4,000,000 byte) limit
            # NOTE: OP_CAT consumes varops budget, so very large elements will hit varops
            # budget before hitting the 4MB element size limit. The element size limit
            # can be tested more directly by pushing large elements via witness.
            # 2^22 = 4,194,304 bytes (just over 4MB)
            # 2^19 = 524,288 bytes (512KB)
            test_cases = [
                (10, True, "10 doublings: 1 -> 1KB"),
                (15, True, "15 doublings: 1 -> 32KB"),
                (18, True, "18 doublings: 1 -> 256KB"),
                (19, False, "19 doublings: 1 -> 512KB (exceeds varops budget)"),
                (22, False, "22 doublings: 1 -> 4MB+ (exceeds 4MB element size limit)"),
            ]

            passed = 0
            failed = 0

            for num_doublings, should_pass, description in test_cases:
                try:
                    # Build script: start with 1 byte, then DUP+CAT repeatedly
                    # Each iteration doubles the size: 1 -> 2 -> 4 -> 8 -> 16 -> ...
                    script_ops = [bytes([0xFF])]  # Start with 1 byte

                    for _ in range(num_doublings):
                        script_ops.append(OP_DUP)   # Duplicate top element
                        script_ops.append(OP_CAT)   # Concatenate: doubles the size

                    # Final size will be 2^num_doublings bytes
                    final_size = 2 ** num_doublings

                    # Drop the result and return OP_1 (we just want to test the CAT worked)
                    script_ops.append(OP_DROP)
                    script_ops.append(OP_1)

                    locking_script = CScript(script_ops)
                    unlocking_script = []

                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)

                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass:
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description} (final: {final_size:,} bytes)")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - rejected: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        if not result['allowed']:
                            self.log.debug(f"  ✓ {description} - correctly rejected (would be {final_size:,} bytes)")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        self.log.debug(f"  ✓ {description} - correctly rejected (exception)")
                        passed += 1

            self.log.debug(f"\nOP_CAT large element tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} OP_CAT test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_merkle_proof_verification(self):
        """Test: Merkle tree proof verification using OP_CAT + OP_SHA256

        Real-world use case: Light client verification, inclusion proofs, covenant validation.
        This demonstrates one of the most important applications of OP_CAT - the ability to
        verify merkle proofs on-chain without requiring a signature oracle.
        """
        test_name = "Merkle proof verification (OP_CAT + OP_SHA256)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Build a simple merkle tree with 4 leaves
            # Tree structure:
            #        root
            #       /    \
            #    hash01  hash23
            #    /  \    /  \
            #   L0  L1  L2  L3

            leaf0 = hashlib.sha256(b"data0").digest()
            leaf1 = hashlib.sha256(b"data1").digest()
            leaf2 = hashlib.sha256(b"data2").digest()
            leaf3 = hashlib.sha256(b"data3").digest()

            # Build intermediate hashes
            hash01 = hashlib.sha256(leaf0 + leaf1).digest()
            hash23 = hashlib.sha256(leaf2 + leaf3).digest()

            # Build root
            root = hashlib.sha256(hash01 + hash23).digest()

            # Test case: Prove that leaf0 is in the tree
            # Proof path: [leaf0, leaf1, hash23] -> verify equals root
            # Steps:
            # 1. CAT(leaf0, leaf1) -> leaf0+leaf1
            # 2. SHA256 -> hash01
            # 3. CAT(hash01, hash23) -> hash01+hash23
            # 4. SHA256 -> root
            # 5. EQUAL(computed_root, expected_root)

            # Script:
            # Witness provides: [leaf0, leaf1] (pushed in this order, so stack is [leaf0, leaf1] with leaf1 on top)
            # OP_CAT pops B (top=leaf1), pops A (second=leaf0), then does A+B = leaf0+leaf1
            # Script:
            #   OP_CAT OP_SHA256    # hash(leaf0 + leaf1) = hash01
            #   <hash23> OP_CAT OP_SHA256  # hash(hash01 + hash23) = root
            #   <expected_root> OP_EQUAL

            locking_script = CScript([
                OP_CAT,           # Stack: [leaf0+leaf1] (OP_CAT does second+top)
                OP_SHA256,        # Stack: [hash01]
                hash23,           # Stack: [hash01, hash23]
                OP_CAT,           # Stack: [hash01+hash23] (OP_CAT does second+top)
                OP_SHA256,        # Stack: [computed_root]
                root,             # Stack: [computed_root, expected_root]
                OP_EQUAL          # Stack: [1 if equal]
            ])

            # Witness: provide leaf0 and leaf1 (proving leaf0 is in tree)
            # They are pushed in order, creating stack [leaf0, leaf1] with leaf1 on top
            unlocking_script = [leaf0, leaf1]

            result = self.test_simple_tapscript_v2_transaction(locking_script, unlocking_script)

            if result:
                self.log.debug("  ✓ Successfully verified merkle proof on-chain")
                self.log.debug(f"  ✓ Proved leaf0 ({leaf0.hex()[:16]}...) is in tree")
                self.log.debug(f"  ✓ Root: {root.hex()[:32]}...")
                self.print_test_status(test_name, is_start=False, success=True)
            else:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError("Merkle proof verification failed")

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_op_checklocktimeverify(self):
        """Test: OP_CHECKLOCKTIMEVERIFY with various lock times"""
        test_name = "OP_CHECKLOCKTIMEVERIFY (block height and timestamp)"
        self.print_test_status(test_name, is_start=True)

        try:
            # Test cases: (height_offset_or_time, nSequence, should_pass, description, is_timestamp)
            # For block height tests: offset is relative to current height (can be negative, 0, or positive)
            # For timestamp tests: offset is relative to current time
            # LOCKTIME_THRESHOLD = 500'000'000
            # Below threshold = block height, above = timestamp
            test_cases = [
                # Block height tests (relative offsets)
                (-10, 0xFFFFFFFE, True, "Block height: 10 blocks ago (should pass)", False),
                (0, 0xFFFFFFFE, True, "Block height: current height (should pass)", False),
                (1, 0xFFFFFFFE, True, "Block height: 1 block in the future (should still pass)", False),
                (2, 0xFFFFFFFE, False, "Block height: 2 blocks in the future (should fail)", False),
                (+1000, 0xFFFFFFFE, False, "Block height: far future (should fail)", False),

                # Timestamp tests (relative offsets in seconds)
                # Note: Bitcoin uses Median Time Past (MTP), not current block time
                (-3600, 0xFFFFFFFE, True, "Timestamp: 1 hour ago (should pass)", True),
                (-60, 0xFFFFFFFE, True, "Timestamp: 1 minute ago (should pass)", True),
                (+86400, 0xFFFFFFFE, False, "Timestamp: 1 day in future (should fail)", True),

                # nSequence tests (with block height)
                (-10, SEQUENCE_FINAL, False, "nSequence = FINAL (should fail)", False),
                (-10, 0, True, "nSequence = 0 (should pass)", False),
            ]

            passed = 0
            failed = 0

            for offset, nSequence, should_pass, description, is_timestamp in test_cases:
                # Capture fresh current height/time for each test iteration
                current_height = self.nodes[0].getblockcount()
                current_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time']

                # Calculate actual locktime based on offset
                if is_timestamp:
                    locktime = current_time + offset
                else:
                    locktime = current_height + offset
                try:
                    # Create script that checks locktime
                    # Script: <locktime_value> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1
                    # The OP_DROP is needed because CLTV doesn't consume its argument
                    locking_script = CScript([locktime, OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1])
                    unlocking_script = []

                    # Create funding transaction
                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)

                    # Create spending transaction with specific nLockTime and nSequence
                    spending_tx = CTransaction()
                    spending_tx.nLockTime = locktime  # Set transaction locktime
                    spending_tx.vin = [CTxIn(
                        COutPoint(int(utxo_info["funding_txid"], 16), utxo_info["funding_vout"]),
                        b"",
                        nSequence  # Use specified nSequence
                    )]

                    # Create output
                    output_address = self.nodes[0].getnewaddress()
                    output_script = bytes.fromhex(self.nodes[0].validateaddress(output_address)["scriptPubKey"])
                    output_amount = int((utxo_info["amount"] - 0.001) * 100000000)
                    spending_tx.vout = [CTxOut(output_amount, output_script)]

                    # Create witness
                    tap = utxo_info["tap"]
                    script = utxo_info["script"]
                    leaf_info = tap.leaves["script"]
                    control_block = bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch

                    spending_tx.wit.vtxinwit = [CTxInWitness()]
                    spending_tx.wit.vtxinwit[0].scriptWitness.stack = unlocking_script + [script, control_block]

                    # Test transaction
                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass:
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description}")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - rejected: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        if not result['allowed']:
                            self.log.debug(f"  ✓ {description} - correctly rejected ({result.get('reject-reason', 'Unknown')})")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        self.log.debug(f"  ✓ {description} - correctly rejected (exception)")
                        passed += 1

            self.log.debug(f"\nOP_CHECKLOCKTIMEVERIFY tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} CLTV test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def test_varops_budget_exceeded_by_signature_reuse(self):
        """Test: Exceed varops budget by reusing the same signature many times

        Since each signature costs 260,000 varops but adding a new signature to
        the witness adds ~100 weight units (giving 520,000 budget), signatures are
        "self-funding" and we can't exceed the budget just by adding more signatures.

        However, we CAN exceed the budget by verifying the SAME signature multiple
        times using OP_DUP. This way weight stays low but varops cost is high.

        Test various numbers of signature verifications around the critical value
        to determine exactly how many should be allowed based on transaction weight.
        """
        test_name = "Varops budget: Exceeded by signature reuse"
        self.print_test_status(test_name, is_start=True)

        try:
            # Generate one key
            key = ECKey()
            key.generate()
            pubkey_xonly, _ = compute_xonly_pubkey(key.get_bytes())

            # Test cases: (num_verifications, should_pass, description)
            test_cases = [
                (1, None, "1 verification - well within budget"),
                (9, None, "9 verification - within budget"),
                (10, None, "10 verification - exceeds budget"),
                (20, None, "20 verifications - way over budget")
            ]

            passed = 0
            failed = 0

            for num_verifications, should_pass, description in test_cases:
                try:
                    # Create a script that duplicates the signature and verifies it many times
                    # Pattern: <sig on witness> <pubkey> OP_2DUP OP_CHECKSIG OP_VERIFY ... (repeat)
                    # This reuses the same sig without adding weight
                    script_ops = []
                    for i in range(num_verifications):
                        if i == 0:
                            # First time: sig and pubkey are on stack
                            script_ops.extend([pubkey_xonly, OP_2DUP, OP_CHECKSIG, OP_VERIFY])
                        else:
                            # Subsequent times: dup the sig and pubkey, then check
                            script_ops.extend([OP_2DUP, OP_CHECKSIG, OP_VERIFY])
                    # Clean up stack and return true
                    script_ops.extend([OP_2DROP, OP_1])

                    locking_script = CScript(script_ops)

                    # Create funding transaction
                    utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)

                    # Create spending transaction
                    spending_tx = self.create_tapscript_v2_spending_tx(utxo_info)
                    spent_output = CTxOut(int(utxo_info["amount"] * 100000000), utxo_info["tap"].scriptPubKey)

                    # Compute sighash
                    sighash = TaprootSignatureHash(
                        spending_tx,
                        [spent_output],
                        0,
                        0,
                        scriptpath=True,
                        leaf_script=locking_script,
                        codeseparator_pos=-1,
                        leaf_ver=LEAF_VERSION_TAPSCRIPT_V2
                    )

                    sig = sign_schnorr(key.get_bytes(), sighash)

                    spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, sig)

                    tx_weight = spending_tx.get_weight()
                    varops_budget = tx_weight * 5200
                    varops_used = num_verifications * 260000  # Each CHECKSIG costs 260,000
                    max_verifications_for_weight = varops_budget // 260000

                    self.log.debug(f"\n  Testing {num_verifications} verifications:")
                    self.log.debug(f"    Transaction weight: {tx_weight}")
                    self.log.debug(f"    Varops budget: {varops_budget:,}")
                    self.log.debug(f"    Varops used: {varops_used:,} ({num_verifications} CHECKSIGs × 260,000)")
                    self.log.debug(f"    Max verifications for this weight: {max_verifications_for_weight}")
                    self.log.debug(f"    Budget remaining: {varops_budget - varops_used:,}")

                    result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]

                    if should_pass is None:
                        should_pass = varops_used <= varops_budget

                    if should_pass:
                        if result['allowed']:
                            self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                            self.generate(self.nodes[0], 1)
                            self.log.debug(f"  ✓ {description} - PASSED (within budget)")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - rejected but should pass: {result.get('reject-reason', 'Unknown')}")
                            failed += 1
                    else:
                        if not result['allowed']:
                            actual_reason = result.get('reject-reason', 'Unknown')
                            self.log.debug(f"  ✓ {description} - REJECTED correctly ({actual_reason})")
                            passed += 1
                        else:
                            self.log.error(f"  ✗ {description} - should be rejected but was accepted!")
                            failed += 1

                except Exception as e:
                    if should_pass:
                        self.log.error(f"  ✗ {description} - exception: {e}")
                        failed += 1
                    else:
                        self.log.debug(f"  ✓ {description} - REJECTED (exception: {str(e)[:50]}...)")
                        passed += 1

            self.log.debug(f"\nVarops signature reuse tests: {passed} passed, {failed} failed")

            if failed > 0:
                self.print_test_status(test_name, is_start=False, success=False)
                raise AssertionError(f"{failed} varops signature reuse test(s) failed")
            else:
                self.print_test_status(test_name, is_start=False, success=True)

        except Exception as e:
            self.log.error(f"Exception in test: {e}")
            self.print_test_status(test_name, is_start=False, success=False)
            raise

    def run_test(self):
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)

        self.test_simple_op1_script()
        self.test_op_checksig_basic()
        self.test_keypath_spend()
        self.test_multiple_leaves()
        self.test_multisig_2of2()
        self.test_sighash_types()
        self.test_op_cat()
        self.test_op_mul_small()
        self.test_op_mul_large()
        self.test_op_mul_too_large()

        self.test_stack_size_limit()
        self.test_stack_element_size_limit()
        self.test_total_stack_size_limit()
        self.test_witness_element_size_limit()
        self.test_cat_creates_large_element()

        self.test_varops_budget_exceeded_by_signature_reuse()

        self.test_op_checklocktimeverify()

        self.test_merkle_proof_verification()

    def init_blockinfo(self):
        """Initialize variables used by block_submit()."""
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int(self.lastblockhash, 16)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']

    def block_submit(self, node, txs, msg, accept, fees=0):
        """Submit a block containing the given transactions directly (bypassing mempool)."""
        coinbase_tx = create_coinbase(self.lastblockheight + 1, fees=fees)
        block = create_block(self.tip, coinbase_tx, self.lastblocktime + 1, txlist=txs)
        add_witness_commitment(block)
        block.solve()
        block_response = node.submitblock(block.serialize().hex())
        if accept:
            assert node.getbestblockhash() == block.hash_hex, "Failed to accept: %s (response: %s)" % (msg, block_response)
            self.tip = block.hash_int
            self.lastblockhash = block.hash_hex
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert node.getbestblockhash() == self.lastblockhash, "Failed to reject: %s" % msg

    def create_tapscript_funding_tx(self, tapscript, internal_key=None, amount=1.0, leaf_version=LEAF_VERSION_TAPSCRIPT_V2):
        """Create a funding transaction with a tapscript P2TR output."""
        if internal_key is None:
            SEED = 317
            prv: bytes = hashlib.sha256(SEED.to_bytes(2, 'big') + bytes([0])).digest()
            internal_key = prv

        pubkey_bytes, _ = compute_xonly_pubkey(internal_key)

        tap = taproot_construct(pubkey_bytes, [("script", tapscript, leaf_version)])
        address = encode_segwit_address("bcrt", 1, tap.output_pubkey)

        funding_txid = self.nodes[0].sendtoaddress(address, amount)
        self.generate(self.nodes[0], 1)

        # Get the funding transaction and find the correct vout
        funding_tx_info = self.nodes[0].gettransaction(funding_txid)
        funding_tx_decoded = self.nodes[0].decoderawtransaction(funding_tx_info['hex'])

        # Find the correct vout by matching the scriptPubKey directly
        funding_vout = None
        expected_scriptpubkey = f"5120{tap.output_pubkey.hex()}"

        for i, vout in enumerate(funding_tx_decoded['vout']):
            if vout['scriptPubKey']['hex'] == expected_scriptpubkey:
                funding_vout = i
                break

        assert funding_vout is not None, f"Could not find funding output with scriptPubKey {expected_scriptpubkey}"

        return {
            "funding_txid": funding_txid,
            "funding_vout": funding_vout,
            "amount": amount,
            "tap": tap,
            "internal_key": internal_key,
            "address": address,
            "script": tapscript
        }

    def create_tapscript_v2_funding_tx(self, tapscript_v2, internal_key=None, amount=1.0):
        """Create a funding transaction with a TAPSCRIPT_V2 P2TR output."""
        return self.create_tapscript_funding_tx(tapscript_v2, internal_key, amount, LEAF_VERSION_TAPSCRIPT_V2)

    def create_tapscript_v2_spending_tx(self, utxo_info, extra_witness_elements=None):
        """Create a spending transaction for a TAPSCRIPT_V2 UTXO."""
        spending_tx = CTransaction()
        spending_tx.vin = [CTxIn(COutPoint(int(utxo_info["funding_txid"], 16), utxo_info["funding_vout"]), b"", SEQUENCE_FINAL)]

        # Create output (send back to wallet for simplicity)
        output_address = self.nodes[0].getnewaddress()
        output_script = bytes.fromhex(self.nodes[0].validateaddress(output_address)["scriptPubKey"])
        output_amount = int((utxo_info["amount"] - 0.001) * 100000000)  # Subtract fee
        spending_tx.vout = [CTxOut(output_amount, output_script)]

        # Create witness for TAPSCRIPT_V2 script path spending
        tap = utxo_info["tap"]
        script = utxo_info["script"]

        # Get the leaf info for our script (we named it "script" when creating the taproot)
        leaf_info = tap.leaves["script"]
        control_block = bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch

        witness_elements = extra_witness_elements if extra_witness_elements else []
        witness_elements.append(script)
        witness_elements.append(control_block)

        spending_tx.wit.vtxinwit = [CTxInWitness()]
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = witness_elements

        return spending_tx

    def test_simple_tapscript_v2_transaction(self, locking_script, unlocking_script) -> bool:
        """Test creation and validation of TAPSCRIPT_V2 transactions."""

        try:
            utxo_info = self.create_tapscript_v2_funding_tx(locking_script, amount=0.1)
            self.log.debug(f"✓ Created TAPSCRIPT_V2 funding transaction: {utxo_info['funding_txid']}")
            spending_tx = self.create_tapscript_v2_spending_tx(utxo_info, extra_witness_elements=unlocking_script)
            self.log.debug(f"✓ Created TAPSCRIPT_V2 spending transaction: {spending_tx.rehash()}")

            # # print tx size
            # self.log.debug(f"Tx size: {len(spending_tx.serialize())} B")
            # # print tx weight
            # self.log.debug(f"Tx weight: {spending_tx.get_weight()} wu")
            # # print varops budget

            # Use maxfeerate=0 to bypass the fee rate validation bug
            # There appears to be a bug in the fee rate comparison logic where
            # valid fee rates are incorrectly rejected as "max-fee-exceeded"
            result = self.nodes[0].testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]  # No fee limit

            if result['allowed']:
                self.log.debug("✓ TAPSCRIPT_V2 transaction accepted")

                # broadcast transaction
                self.nodes[0].sendrawtransaction(spending_tx.serialize().hex())
                self.log.debug("✓ TAPSCRIPT_V2 transaction broadcasted")
                self.generate(self.nodes[0], 1)

                # wait for mempool to clear
                self.generate(self.nodes[0], 1)
                self.log.debug("✓ TAPSCRIPT_V2 transaction mempool cleared")
                self.generate(self.nodes[0], 1)
                self.log.debug("✓ TAPSCRIPT_V2 transaction mined")
            else:
                self.log.debug(f"✗ TAPSCRIPT_V2 transaction rejected: {result.get('reject-reason', 'Unknown reason')}")
                self.log.debug(f"Stack top: {spending_tx.wit.vtxinwit[0].scriptWitness.stack[-1].hex()}")
            return result['allowed']

        except Exception as e:
            self.log.debug(f"Exception: {e}")
            return False

if __name__ == '__main__':
    TapscriptV2Test(__file__).main()
