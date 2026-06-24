// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/consensus.h>
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
#include <test/util/tapleaf_0xc2.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using valtype = std::vector<unsigned char>;
using namespace test::tapleaf_0xc2;

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

static EvalOutcome RunTapleaf0xC2WithFlagsAndChecker(const CScript& script, const Stack& initial_stack, script_verify_flags flags, const BaseSignatureChecker& checker, uint64_t budget)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    ValtypeStack stack{initial_stack};
    const bool ok{::EvalTapleaf0xC2(stack, script, flags, checker, execdata, varops_budget, &error)};
    return {ok, error, varops_budget.Remaining()};
}

static EvalOutcome RunTapleaf0xC2(const CScript& script, const Stack& initial_stack, uint64_t budget)
{
    return RunTapleaf0xC2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, budget);
}

struct FinalizedTapleaf0xC2Spend {
    CTxOut spent_output;
    CMutableTransaction tx;
};

static FinalizedTapleaf0xC2Spend BuildFinalizedTapleaf0xC2Spend(const CScript& leaf_script, const Stack& initial_stack)
{
    CScript script_pub_key;
    CScriptWitness witness{BuildTapleaf0xC2Witness(leaf_script, initial_stack, script_pub_key)};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin[0].scriptWitness = std::move(witness);
    tx.vout.emplace_back(500, CScript{} << OP_TRUE);

    return {CTxOut{1000, script_pub_key}, std::move(tx)};
}

static EvalOutcome VerifyTapleaf0xC2WithFlags(const CScript& leaf_script, const Stack& initial_stack, script_verify_flags flags, uint64_t budget)
{
    CScript script_pub_key;
    const CScriptWitness witness{BuildTapleaf0xC2Witness(leaf_script, initial_stack, script_pub_key)};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, flags, BaseSignatureChecker{}, &error, varops_budget)};
    return EvalOutcome{ok, error, varops_budget.Remaining()};
}

static EvalOutcome VerifyTapleaf0xC2(const CScript& leaf_script, const Stack& initial_stack, uint64_t budget)
{
    return VerifyTapleaf0xC2WithFlags(leaf_script, initial_stack, TAPLEAF_0XC2_SCRIPT_VERIFY_FLAGS, budget);
}

BOOST_FIXTURE_TEST_SUITE(tapleaf_0xc2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(op_success_classification)
{
    constexpr auto tapleaf_0xc2_op_success = std::to_array<uint8_t>({
        79, 80, 98, 137, 138, 143, 144,
        187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
        200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
        213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254,
    });

    for (unsigned int opcode_value{0}; opcode_value <= 0xff; ++opcode_value) {
        const bool expected{std::ranges::find(tapleaf_0xc2_op_success, static_cast<uint8_t>(opcode_value)) != tapleaf_0xc2_op_success.end()};
        BOOST_TEST_CONTEXT("opcode " << opcode_value) {
            BOOST_CHECK_EQUAL(IsTapleaf0xC2OpSuccess(static_cast<opcodetype>(opcode_value)), expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(verification_without_a_budget_is_capped)
{
    const auto verify{[](const CScript& script) {
        CScript script_pub_key;
        const CScriptWitness witness{BuildTapleaf0xC2Witness(script, {}, script_pub_key)};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, TAPLEAF_0XC2_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error)};
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
    BOOST_REQUIRE_GT(varops::MulCost(1 << 20, 1 << 20), varops::TxBudget(MAX_BLOCK_WEIGHT));
    BOOST_CHECK_EQUAL(verify(script), SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(pushes_use_the_expanded_stack_element_limit)
{
    const valtype max_element(MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_push;
    max_push << max_element;
    EvalOutcome outcome{VerifyTapleaf0xC2(max_push, {}, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype too_large_element(MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript too_large_push;
    too_large_push << too_large_element;
    outcome = VerifyTapleaf0xC2(too_large_push, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(skipped_branches_validate_pushes)
{
    const valtype max_element(MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_skipped_push;
    max_skipped_push << OP_0 << OP_IF << max_element << OP_ENDIF;
    BOOST_CHECK_EQUAL(RunTapleaf0xC2(max_skipped_push, {}, AMPLE_VAROPS_BUDGET).error, SCRIPT_ERR_OK);

    const valtype too_large_element(MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript oversized_skipped_push;
    oversized_skipped_push << OP_0 << OP_IF << too_large_element << OP_ENDIF;
    BOOST_CHECK_EQUAL(RunTapleaf0xC2(oversized_skipped_push, {}, AMPLE_VAROPS_BUDGET).error, SCRIPT_ERR_PUSH_SIZE);

    CScript truncated_skipped_push;
    truncated_skipped_push << OP_0 << OP_IF;
    truncated_skipped_push.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
    BOOST_CHECK_EQUAL(RunTapleaf0xC2(truncated_skipped_push, {}, AMPLE_VAROPS_BUDGET).error, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(signature_checks_run_within_the_budget)
{
    // A signature check's charge is checked against the budget before the check
    // runs. The shared budget is deducted only when the script ends.
    class BudgetRecordingChecker final : public BaseSignatureChecker
    {
        const varops::Budget& m_budget;

    public:
        mutable std::vector<uint64_t> remaining_at_checks;

        explicit BudgetRecordingChecker(const varops::Budget& budget) : m_budget{budget} {}

        bool CheckSchnorrSignature(std::span<const unsigned char>, std::span<const unsigned char>, SigVersion,
                                   ScriptExecutionData&, ScriptError*) const override
        {
            remaining_at_checks.push_back(m_budget.Remaining());
            return true;
        }
    };

    const valtype sig(64, 0x01);
    const valtype pubkey(32, 0x02);
    constexpr size_t CHECKS{8};
    CScript script;
    for (size_t i{0}; i < CHECKS; ++i) script << OP_2DUP << OP_CHECKSIGVERIFY;
    struct Run {
        ScriptError error;
        uint64_t charged;
        std::vector<uint64_t> remaining_at_checks;
    };
    const auto run{[&](uint64_t budget_amount) {
        ScriptExecutionData execdata;
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        varops::Budget budget{budget_amount};
        const BudgetRecordingChecker checker{budget};
        ValtypeStack stack{Stack{sig, pubkey}};
        ScriptError error;
        ::EvalTapleaf0xC2(stack, script, SCRIPT_VERIFY_NONE, checker, execdata, budget, &error);
        return Run{error, budget_amount - budget.Remaining(), checker.remaining_at_checks};
    }};
    const Run paid{run(AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE_EQUAL(paid.error, SCRIPT_ERR_OK);
    BOOST_CHECK(paid.remaining_at_checks == std::vector<uint64_t>(CHECKS, AMPLE_VAROPS_BUDGET));
    // One varop short, the last check does not run, and nothing is deducted.
    const Run short_run{run(paid.charged - 1)};
    BOOST_CHECK_EQUAL(short_run.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK_EQUAL(short_run.charged, 0U);
    BOOST_CHECK_EQUAL(short_run.remaining_at_checks.size(), CHECKS - 1);
}

BOOST_AUTO_TEST_CASE(unpaid_work_does_not_run)
{
    // Evaluate with the given budget; return the error and the stack where evaluation stopped.
    const auto run{[](const CScript& script, const Stack& initial_stack, uint64_t budget) {
        ScriptExecutionData execdata;
        execdata.m_annex_present = false;
        execdata.m_annex_init = true;
        varops::Budget varops_budget{budget};
        ValtypeStack stack{initial_stack};
        ScriptError error{SCRIPT_ERR_OK};
        ::EvalTapleaf0xC2(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, varops_budget, &error);
        return std::pair{error, stack.GetStack()};
    }};

    const valtype x(2000, 0x01), y(2000, 0x02), dividend(4000, 0x03);
    // Witness values are funded by their weight, so they cost no varops.
    BOOST_CHECK_EQUAL(RunTapleaf0xC2(CScript{} << OP_1, {x, y}, AMPLE_VAROPS_BUDGET).remaining_budget,
                      RunTapleaf0xC2(CScript{} << OP_1, {}, AMPLE_VAROPS_BUDGET).remaining_budget);

    // With no budget, these opcodes fail for lack of budget. They check their
    // charges before their work, so their result never reaches the stack.
    struct Case {
        opcodetype opcode;
        Stack stack;
    };
    for (const auto& [opcode, stack] : std::vector<Case>{{OP_MUL, {x, y}}, {OP_DIV, {dividend, y}}, {OP_MOD, {dividend, y}}}) {
        BOOST_TEST_CONTEXT(GetOpName(opcode)) {
            const auto [error, stack_at_failure]{run(OneOp(opcode), stack, 0)};
            BOOST_CHECK_EQUAL(error, SCRIPT_ERR_VAROP_COUNT);
            // The operands were taken off the stack; no result replaced them.
            BOOST_CHECK(stack_at_failure.empty());
        }
    }

    // Other opcodes check their charges when they end, with their result on
    // the stack.
    const EvalOutcome paid{RunTapleaf0xC2(CScript{} << OP_1, {}, AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE(paid.ok);
    const auto [error, stack]{run(CScript{} << OP_1 << OP_DUP, {}, AMPLE_VAROPS_BUDGET - paid.remaining_budget)};
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK(stack == (Stack{{0x01}, {0x01}}));
}

BOOST_AUTO_TEST_CASE(minimal_push_of_0x81)
{
    // OP_1NEGATE is an OP_SUCCESSx in Tapleaf 0xC2, so a direct push is the
    // minimal push of 0x81. Other values keep the Tapscript rules.
    const auto run{[](const valtype& script) {
        return RunTapleaf0xC2WithFlagsAndChecker(CScript(script.begin(), script.end()), {}, SCRIPT_VERIFY_MINIMALDATA,
                                                 BaseSignatureChecker{}, AMPLE_VAROPS_BUDGET).error;
    }};
    BOOST_CHECK_EQUAL(run({0x01, 0x81}), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(run({OP_PUSHDATA1, 0x01, 0x81}), SCRIPT_ERR_MINIMALDATA);
    BOOST_CHECK_EQUAL(run({0x01, 0x05}), SCRIPT_ERR_MINIMALDATA);
}

BOOST_AUTO_TEST_CASE(nop4_is_upgradable_nop)
{
    const valtype ctv_hash(32, 0x01);
    CScript script;
    script << ctv_hash << OP_NOP4;

    const script_verify_flags flags{TAPLEAF_0XC2_SCRIPT_VERIFY_FLAGS};
    EvalOutcome outcome{VerifyTapleaf0xC2WithFlags(script, {}, flags, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapleaf0xC2WithFlags(script, {}, flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
                                         AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(psbt_finalized_witness_is_signed_and_verified)
{
    CScript normal_script;
    normal_script << OP_1;
    FinalizedTapleaf0xC2Spend spend{BuildFinalizedTapleaf0xC2Spend(normal_script, {})};

    CMutableTransaction unsigned_tx{spend.tx};
    unsigned_tx.vin[0].scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spend.spent_output;
    psbt.inputs[0].final_script_witness = spend.tx.vin[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{spend.tx}, std::vector<CTxOut>{spend.spent_output});

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(FinalizePSBT(psbt));

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend.tx.vin[0].prevout, Coin{spend.spent_output, 1, /*fCoinBaseIn=*/false});
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(spend.tx, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(input_errors.empty());
}

BOOST_AUTO_TEST_SUITE_END()
