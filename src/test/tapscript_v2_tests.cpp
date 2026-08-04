// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <key.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/util/setup_common.h>
#include <test/util/tapscript_v2.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using valtype = std::vector<unsigned char>;
using namespace test::tapscript_v2;

static constexpr uint64_t AMPLE_VAROPS_BUDGET{1'000'000'000};

struct EvalOutcome {
    bool ok{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t remaining_budget{0};
};

static CScript OneOp(opcodetype opcode)
{
    CScript script;
    script << opcode;
    return script;
}

static EvalOutcome RunTapscriptV2WithFlagsAndChecker(const CScript& script, const Stack& initial_stack, script_verify_flags flags, const BaseSignatureChecker& checker, uint64_t budget)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    ValtypeStack stack{initial_stack};
    const bool ok{::EvalTapscriptV2(stack, script, flags, checker, execdata, varops_budget, &error)};
    return {ok, error, varops_budget.Remaining()};
}

static EvalOutcome RunTapscriptV2(const CScript& script, const Stack& initial_stack, uint64_t budget)
{
    return RunTapscriptV2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, budget);
}

static void CheckEval(const CScript& script, const Stack& initial_stack, const Stack& expected_stack)
{
    // These cases check opcode semantics; the reference vectors check costs.
    const EvalOutcome outcome{RunTapscriptV2(script, initial_stack, std::numeric_limits<uint64_t>::max())};
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK(outcome.stack == expected_stack);
}

static void CheckError(const CScript& script, const Stack& initial_stack, ScriptError expected_error)
{
    const EvalOutcome outcome{RunTapscriptV2(script, initial_stack, std::numeric_limits<uint64_t>::max())};
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, expected_error);
}

struct FinalizedTapscriptV2Spend {
    CTxOut spent_output;
    CMutableTransaction tx;
};

static FinalizedTapscriptV2Spend BuildFinalizedTapscriptV2Spend(const CScript& leaf_script, const Stack& initial_stack)
{
    CScript script_pub_key;
    CScriptWitness witness{BuildTapscriptV2Witness(leaf_script, initial_stack, script_pub_key)};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin[0].scriptWitness = std::move(witness);
    tx.vout.emplace_back(500, CScript{} << OP_TRUE);

    return {CTxOut{1000, script_pub_key}, std::move(tx)};
}

static EvalOutcome VerifyTapscriptV2WithFlags(const CScript& leaf_script, const Stack& initial_stack, script_verify_flags flags, uint64_t budget)
{
    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(leaf_script, initial_stack, script_pub_key)};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, flags, BaseSignatureChecker{}, &error, varops_budget)};
    return EvalOutcome{ok, error, varops_budget.Remaining()};
}

static EvalOutcome VerifyTapscriptV2(const CScript& leaf_script, const Stack& initial_stack, uint64_t budget)
{
    return VerifyTapscriptV2WithFlags(leaf_script, initial_stack, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, budget);
}

BOOST_FIXTURE_TEST_SUITE(tapscript_v2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(op_success_classification)
{
    constexpr auto tapscript_v2_op_success = std::to_array<uint8_t>({
        79, 80, 98, 137, 138, 143, 144,
        187, 188, 189, 190, 192, 193, 194, 195, 196, 197, 198, 199,
        200, 201, 202, 203, 205, 206, 207, 208, 209, 210, 211, 212,
        213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254,
    });

    for (unsigned int opcode_value{0}; opcode_value <= 0xff; ++opcode_value) {
        const bool expected{std::ranges::find(tapscript_v2_op_success, static_cast<uint8_t>(opcode_value)) != tapscript_v2_op_success.end()};
        BOOST_TEST_CONTEXT("opcode " << opcode_value) {
            BOOST_CHECK_EQUAL(IsTapscriptV2OpSuccess(static_cast<opcodetype>(opcode_value)), expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(verification_without_a_budget_is_capped)
{
    const auto verify{[](const CScript& script) {
        CScript script_pub_key;
        const CScriptWitness witness{BuildTapscriptV2Witness(script, {}, script_pub_key)};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error)};
        BOOST_CHECK_EQUAL(ok, error == SCRIPT_ERR_OK);
        return error;
    }};
    BOOST_CHECK_EQUAL(verify(CScript{} << OP_1), SCRIPT_ERR_OK);

    // Doubling one byte 20 times gives a 1 MiB value, whose square costs more
    // than the budget of a transaction of maximum block weight.
    CScript script;
    script << valtype{0xff};
    for (int i{0}; i < 20; ++i) script << OP_DUP << OP_CAT;
    script << OP_DUP << OP_MUL;
    const uint64_t limbs{varops::WordCount(1 << 20)};
    BOOST_REQUIRE_GT(varops::MulCost(limbs, limbs), varops::TxBudget(MAX_BLOCK_WEIGHT));
    BOOST_CHECK_EQUAL(verify(script), SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(pushes_use_the_expanded_stack_element_limit)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_push;
    max_push << max_element;
    EvalOutcome outcome{VerifyTapscriptV2(max_push, {}, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript too_large_push;
    too_large_push << too_large_element;
    outcome = VerifyTapscriptV2(too_large_push, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(skipped_branches_validate_pushes)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_skipped_push;
    max_skipped_push << OP_0 << OP_IF << max_element << OP_ENDIF;
    CheckEval(max_skipped_push, {}, {});

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript oversized_skipped_push;
    oversized_skipped_push << OP_0 << OP_IF << too_large_element << OP_ENDIF;
    CheckError(oversized_skipped_push, {}, SCRIPT_ERR_PUSH_SIZE);

    CScript truncated_skipped_push;
    truncated_skipped_push << OP_0 << OP_IF;
    truncated_skipped_push.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
    CheckError(truncated_skipped_push, {}, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(signature_checks_run_after_their_charges)
{
    // CHECKSIG and CHECKSIGVERIFY deduct their whole charge before the signature
    // check runs, and CHECKSIGADD everything but its result, so a budget that
    // cannot pay for a check never reaches it.
    class BudgetRecordingChecker final : public BaseSignatureChecker
    {
        const varops::Budget& m_budget;

    public:
        mutable std::optional<uint64_t> remaining_at_check;

        explicit BudgetRecordingChecker(const varops::Budget& budget) : m_budget{budget} {}

        bool CheckSchnorrSignature(std::span<const unsigned char>, std::span<const unsigned char>, SigVersion,
                                   ScriptExecutionData&, ScriptError*) const override
        {
            remaining_at_check = m_budget.Remaining();
            return true;
        }
    };

    const valtype sig(64, 0x01);
    const valtype pubkey(32, 0x02);
    const std::vector<std::tuple<opcodetype, Stack, uint64_t>> cases{
        {OP_CHECKSIG, {sig, pubkey}, 0},
        {OP_CHECKSIGVERIFY, {sig, pubkey}, 0},
        // The incremented number, 0x06, is produced after the check.
        {OP_CHECKSIGADD, {sig, {0x05}, pubkey}, varops::OutputCost(1)},
    };
    for (const auto& [opcode, initial_stack, charged_after_check] : cases) {
        BOOST_TEST_CONTEXT(GetOpName(opcode)) {
            ScriptExecutionData execdata;
            execdata.m_annex_present = false;
            execdata.m_annex_init = true;
            varops::Budget budget{AMPLE_VAROPS_BUDGET};
            const BudgetRecordingChecker checker{budget};
            ValtypeStack stack{initial_stack};
            ScriptError error;
            BOOST_CHECK(::EvalTapscriptV2(stack, OneOp(opcode), SCRIPT_VERIFY_NONE, checker, execdata, budget, &error));
            BOOST_REQUIRE(checker.remaining_at_check);
            BOOST_CHECK_EQUAL(*checker.remaining_at_check - budget.Remaining(), charged_after_check);
        }
    }
}

BOOST_AUTO_TEST_CASE(nop4_is_upgradable_nop)
{
    const valtype ctv_hash(32, 0x01);
    CScript script;
    script << ctv_hash << OP_NOP4;

    const script_verify_flags flags{TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS};
    EvalOutcome outcome{VerifyTapscriptV2WithFlags(script, {}, flags, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2WithFlags(script, {}, flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
                                         AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(checksigfromstack)
{
    // The extended primitives vectors cover OP_CHECKSIGFROMSTACK itself.
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey xonly_pubkey{key.GetPubKey()};
    const valtype pubkey{xonly_pubkey.begin(), xonly_pubkey.end()};
    const uint256 message_hash{uint256::ONE};
    const valtype message{message_hash.begin(), message_hash.end()};
    std::array<unsigned char, 64> signature;
    BOOST_REQUIRE(key.SignSchnorr(message_hash, signature, /*merkle_root=*/nullptr, uint256::ZERO));
    const valtype sig{signature.begin(), signature.end()};
    const CScript script{OneOp(OP_CHECKSIGFROMSTACK)};

    const EvalOutcome discouraged{RunTapscriptV2WithFlagsAndChecker(
        script, {sig, message, valtype(33, 0x02)}, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
        BaseSignatureChecker{}, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(!discouraged.ok);
    BOOST_CHECK_EQUAL(discouraged.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);

    // The whole charge is deducted before the signature check, so a budget
    // one short of a valid signature's cost fails before checking.
    const EvalOutcome valid{RunTapscriptV2(script, {sig, message, pubkey}, AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE(valid.ok);
    const uint64_t cost{AMPLE_VAROPS_BUDGET - valid.remaining_budget};
    valtype wrong_message{message};
    wrong_message.front() ^= 1;
    BOOST_CHECK_EQUAL(RunTapscriptV2(script, {sig, wrong_message, pubkey}, cost).error, SCRIPT_ERR_SCHNORR_SIG);
    BOOST_CHECK_EQUAL(RunTapscriptV2(script, {sig, wrong_message, pubkey}, cost - 1).error, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(leaf_signing)
{
    const CKey key{GenerateRandomKey()};
    const CScript leaf_script{CScript{} << ToByteVector(XOnlyPubKey{key.GetPubKey()}) << OP_CHECKSIG};
    TaprootBuilder builder;
    builder.Add(0, leaf_script, TAPROOT_LEAF_TAPSCRIPT_V2, /*track=*/true);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    const WitnessV1Taproot output{builder.GetOutput()};
    const CTxOut spent_output{100'000, GetScriptForDestination(output)};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(50'000, CScript{} << OP_TRUE);
    const std::map<COutPoint, Coin> coins{{tx.vin[0].prevout, Coin{spent_output, 1, /*fCoinBaseIn=*/false}}};

    // Without the key, the input stays unsigned.
    FlatSigningProvider provider;
    provider.tr_trees.emplace(output, builder);
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(tx, &provider, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(tx.vin[0].scriptWitness.IsNull());

    // With it, the leaf is signed, and SignTransaction verifies the spend.
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    input_errors.clear();
    BOOST_CHECK(SignTransaction(tx, &provider, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(input_errors.empty());
    BOOST_CHECK_EQUAL(tx.vin[0].scriptWitness.stack.size(), 3U);
}

BOOST_AUTO_TEST_CASE(psbt_verification_sees_finalized_witnesses)
{
    // OP_TX pushes the current input's witness item count, which is zero in the
    // PSBT's unsigned transaction and two once the input is finalized.
    const valtype witness_item_count_selector{0x00, 0x00, 0x00, 0x10, 0x40, 0x00};
    CScript script;
    script << witness_item_count_selector << OP_TX;
    FinalizedTapscriptV2Spend spend{BuildFinalizedTapscriptV2Spend(script, {})};

    CMutableTransaction unsigned_tx{spend.tx};
    unsigned_tx.vin[0].scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spend.spent_output;
    psbt.inputs[0].final_script_witness = spend.tx.vin[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{spend.tx}, std::vector<CTxOut>{spend.spent_output});

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(PSBTFitsVaropsBudget(psbt, txdata));
    BOOST_CHECK(FinalizePSBT(psbt));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend.tx.vin[0].prevout, Coin{spend.spent_output, 1, /*fCoinBaseIn=*/false});
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(spend.tx, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(input_errors.empty());
}

BOOST_AUTO_TEST_CASE(signing_checks_the_transaction_varops_budget)
{
    // Multiplying two 60,000-byte operands costs more than the budget of a
    // one-input spend, and fits once but not twice in that of a two-input one.
    const valtype operand(60'000, 0xff);
    CScript costly_script;
    costly_script << OP_MUL << OP_DROP << OP_1;
    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(costly_script, {operand, operand}, script_pub_key)};
    const CTxOut spent_output{100'000'000, script_pub_key};
    const auto spend{[&](uint32_t inputs) {
        CMutableTransaction tx;
        tx.version = 2;
        for (uint32_t n{0}; n < inputs; ++n) {
            tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), n});
            tx.vin.back().scriptWitness = witness;
        }
        tx.vout.emplace_back(50'000, CScript{} << OP_TRUE);
        return tx;
    }};
    const CMutableTransaction single{spend(1)};
    CMutableTransaction pair{spend(2)};
    const uint64_t limbs{varops::WordCount(operand.size())};
    const uint64_t input_cost{varops::MulCost(limbs, limbs)};
    const uint64_t pair_budget{varops::TxBudget(GetTransactionWeight(CTransaction{pair}))};
    BOOST_REQUIRE_GT(input_cost, varops::TxBudget(GetTransactionWeight(CTransaction{single})));
    BOOST_REQUIRE_LT(input_cost, pair_budget);
    BOOST_REQUIRE_LT(pair_budget, 2 * input_cost);

    // A PSBT input is verified against the budget of the finalized
    // transaction, whose witnesses are stored in the PSBT inputs.
    CMutableTransaction unsigned_tx{single};
    unsigned_tx.vin[0].scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spent_output;
    psbt.inputs[0].final_script_witness = witness;
    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{single}, std::vector<CTxOut>{spent_output});
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(!PSBTFitsVaropsBudget(psbt, txdata));
    BOOST_CHECK(!FinalizePSBT(psbt));

    // SignTransaction verifies all inputs against one shared budget.
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& in : pair.vin) coins.emplace(in.prevout, Coin{spent_output, 1, /*fCoinBaseIn=*/false});
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(pair, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1);
    BOOST_CHECK_EQUAL(input_errors.begin()->second.original, ScriptErrorString(SCRIPT_ERR_VAROP_COUNT));
}

BOOST_AUTO_TEST_SUITE_END()
