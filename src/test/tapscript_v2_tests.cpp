// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/util/tapscript_v2_test_utils.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
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
#include <utility>
#include <vector>

using valtype = std::vector<unsigned char>;
using namespace test::tapscript_v2;

static constexpr uint64_t AMPLE_VAROPS_BUDGET{1'000'000'000};

static uint64_t InitialLifetimeCost(const Stack& stack)
{
    uint64_t cost{0};
    if constexpr (varops::PRODUCER_LIFETIME_EXPERIMENT) {
        for (const auto& value : stack) cost += varops::CopyCost(value.size());
    }
    return cost;
}

static valtype Bytes(std::string_view text)
{
    return valtype{text.begin(), text.end()};
}

static valtype Bytes(std::initializer_list<unsigned char> bytes)
{
    return valtype{bytes};
}

static valtype HexBytes(std::string_view hex)
{
    return ParseHex(hex);
}

static valtype Num(uint64_t value)
{
    Val64 num{value};
    return num.MoveToValtype();
}

static valtype LargerThanU64()
{
    return Bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
}

static void AppendCompactSize(CScript& script, uint64_t value)
{
    if (value < 253) {
        script.push_back(value);
        return;
    }
    const unsigned int width{value <= 0xffff ? 2U : value <= 0xffffffff ? 4U : 8U};
    script.push_back(width == 2 ? 0xfd : width == 4 ? 0xfe : 0xff);
    for (unsigned int i{0}; i < width; ++i) script.push_back(value >> (8 * i));
}

static void AppendDefinition(CScript& script, const CScript& body)
{
    script << OP_MACRO;
    AppendCompactSize(script, body.size());
    script.insert(script.end(), body.begin(), body.end());
}

static void AppendReference(CScript& script, uint64_t index)
{
    script << OP_CALLMACRO;
    AppendCompactSize(script, index);
}

static uint64_t LiteralPushCost(size_t size)
{
    return varops::FixedOpcodeCost() + varops::CopyCost(size);
}

static uint64_t MacroDefinitionCost(size_t body_size)
{
    return varops::MacroDecodeCost(body_size);
}

static uint64_t MacroCallCost(size_t body_size)
{
    return varops::FixedOpcodeCost() + MacroDefinitionCost(body_size);
}

class RecordingSignatureCreator final : public BaseSignatureCreator
{
public:
    mutable std::vector<SigVersion> schnorr_sigversions;

    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }

    bool CreateSig(const SigningProvider&, std::vector<unsigned char>&, const CKeyID&, const CScript&, SigVersion) const override
    {
        return false;
    }

    bool CreateSchnorrSig(const SigningProvider&, std::vector<unsigned char>& sig, const XOnlyPubKey&, const uint256* leaf_hash, const uint256*, SigVersion sigversion) const override
    {
        if (leaf_hash == nullptr) return false;
        schnorr_sigversions.push_back(sigversion);
        sig.assign(64, 0x01);
        return true;
    }

    std::vector<uint8_t> CreateMuSig2Nonce(const SigningProvider&, const CPubKey&, const CPubKey&, const CPubKey&, const uint256*, const uint256*, SigVersion, const SignatureData&) const override
    {
        return {};
    }

    bool CreateMuSig2PartialSig(const SigningProvider&, uint256&, const CPubKey&, const CPubKey&, const CPubKey&, const uint256*, const std::vector<std::pair<uint256, bool>>&, SigVersion, const SignatureData&) const override
    {
        return false;
    }

    bool CreateMuSig2AggregateSig(const std::vector<CPubKey>&, std::vector<uint8_t>&, const CPubKey&, const CPubKey&, const uint256*, const std::vector<std::pair<uint256, bool>>&, SigVersion, const SignatureData&) const override
    {
        return false;
    }
};

static uint64_t EncodedExecutionCost(const CScript& script)
{
    uint64_t count{0};
    CScript::const_iterator pc{script.begin()};
    while (pc < script.end() && *pc == OP_MACRO) {
        ++pc;
        uint64_t body_length{0};
        if (pc == script.end()) return 0;
        const uint8_t prefix{*pc++};
        const unsigned int width{prefix < 253 ? 0U : prefix == 253 ? 2U : prefix == 254 ? 4U : 8U};
        if (script.end() - pc < static_cast<CScript::difference_type>(width)) return 0;
        if (width == 0) body_length = prefix;
        else for (unsigned int i{0}; i < width; ++i) body_length |= uint64_t{*pc++} << (8 * i);
        if (body_length > static_cast<uint64_t>(script.end() - pc)) return 0;
        count += varops::MacroDecodeCost(body_length);
        pc += static_cast<CScript::difference_type>(body_length);
    }
    while (pc < script.end()) {
        opcodetype opcode;
        valtype data;
        if (!script.GetOp(pc, opcode, data)) return 0;
        count += varops::ExecutionCost(opcode);
        count += data.size() * varops::COST_COPYING;
        if (opcode == OP_CALLMACRO) {
            if (pc == script.end()) return 0;
            const uint8_t prefix{*pc++};
            const unsigned int width{prefix < 253 ? 0U : prefix == 253 ? 2U : prefix == 254 ? 4U : 8U};
            if (script.end() - pc < static_cast<CScript::difference_type>(width)) return 0;
            pc += width;
        }
    }
    return count;
}

static uint64_t InvokedBodyCost(const CScript& body)
{
    return varops::FixedOpcodeCost() + varops::MacroDecodeCost(body.size()) + EncodedExecutionCost(body);
}

static void CheckEval(const CScript& script, const Stack& initial_stack, const Stack& expected_stack,
                      uint64_t additional_cost, std::optional<uint64_t> direct_executions = std::nullopt)
{
    // These cases primarily check opcode semantics. Recover the observed cost
    // and replay at its boundary; independent formula checks live in bench_varops.
    (void)additional_cost;
    (void)direct_executions;
    constexpr uint64_t ample_budget{std::numeric_limits<uint64_t>::max()};
    const EvalOutcome probe{EvalTapscriptV2(script, initial_stack, ample_budget)};
    BOOST_CHECK_EQUAL(probe.error, SCRIPT_ERR_OK);
    BOOST_CHECK(probe.ok);
    if (!probe.ok) return;
    const uint64_t exact_cost{ample_budget - probe.remaining_budget};
    const EvalOutcome outcome{EvalTapscriptV2(script, initial_stack, exact_cost)};
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK(outcome.ok);
    if (!outcome.ok) return;
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
    BOOST_CHECK_EQUAL(outcome.stack.size(), expected_stack.size());
    if (outcome.stack.size() != expected_stack.size()) return;
    for (size_t i{0}; i < expected_stack.size(); ++i) {
        BOOST_TEST_CONTEXT("stack index " << i) {
            BOOST_CHECK(outcome.stack[i] == expected_stack[i]);
        }
    }
}

static void CheckError(const CScript& script, const Stack& initial_stack, uint64_t additional_budget,
                       ScriptError expected_error, std::optional<uint64_t> direct_executions = std::nullopt)
{
    uint64_t budget{additional_budget};
    if (expected_error == SCRIPT_ERR_VAROP_COUNT) {
        budget += direct_executions ? *direct_executions * varops::COST_PER_OPCODE : EncodedExecutionCost(script);
    } else {
        // Semantic-error tests are not intended to probe the accounting boundary.
        budget = std::numeric_limits<uint64_t>::max();
    }
    const EvalOutcome outcome{EvalTapscriptV2(script, initial_stack, budget)};
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

static EvalOutcome VerifyTaprootLeafWithFlags(const CScript& leaf_script, const Stack& initial_stack, uint8_t leaf_version, script_verify_flags flags, uint64_t budget)
{
    TaprootBuilder builder;
    builder.Add(0, leaf_script, leaf_version, /*track=*/true);
    builder.Finalize(XOnlyPubKey::NUMS_H);

    CScriptWitness witness;
    witness.stack = initial_stack;
    const std::vector<unsigned char> serialized_script{leaf_script.begin(), leaf_script.end()};
    witness.stack.push_back(serialized_script);
    const auto control_blocks{builder.GetSpendData().scripts.at({serialized_script, leaf_version})};
    witness.stack.push_back(*control_blocks.begin());
    const CScript script_pub_key{GetScriptForDestination(builder.GetOutput())};

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const uint64_t execution_cost{leaf_version == TAPROOT_LEAF_TAPSCRIPT_V2 ?
                                      EncodedExecutionCost(leaf_script) :
                                      0};
    varops::Budget varops_budget{budget + execution_cost};
    const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, flags, BaseSignatureChecker{}, &error, varops_budget)};
    return EvalOutcome{ok, error, *varops_budget.Remaining(), {}};
}

static EvalOutcome VerifyTapscriptV2WithFlags(const CScript& leaf_script, const Stack& initial_stack, script_verify_flags flags, uint64_t budget)
{
    return VerifyTaprootLeafWithFlags(leaf_script, initial_stack, TAPROOT_LEAF_TAPSCRIPT_V2, flags, budget);
}

static EvalOutcome VerifyTapscriptV2(const CScript& leaf_script, const Stack& initial_stack, uint64_t budget)
{
    return VerifyTapscriptV2WithFlags(leaf_script, initial_stack, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, budget);
}

static uint64_t SuccessfulWitnessAdditionalCost(const CScript& script, const Stack& initial_stack)
{
    const EvalOutcome probe{VerifyTapscriptV2(script, initial_stack, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK_EQUAL(probe.error, SCRIPT_ERR_OK);
    BOOST_CHECK(probe.ok);
    return AMPLE_VAROPS_BUDGET - probe.remaining_budget;
}

BOOST_FIXTURE_TEST_SUITE(tapscript_v2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(op_success_classification)
{
    constexpr auto tapscript_op_success = std::to_array<uint8_t>({
        80, 98,
        126, 127, 128, 129,
        131, 132, 133, 134,
        137, 138,
        141, 142,
        149, 150, 151, 152, 153,
        187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
        200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
        213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254,
    });
    constexpr auto tapscript_v2_op_success = std::to_array<uint8_t>({
        79, 80, 98, 137, 138, 143, 144,
        191, 192, 193, 194, 195, 196, 197, 198, 199,
        200, 201, 202, 203, 205, 206, 208, 209, 210, 211, 212,
        213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254,
    });

    const auto check_all_opcodes = [](SigVersion sigversion, const auto& expected_op_success) {
        for (unsigned int opcode_value{0}; opcode_value <= 0xff; ++opcode_value) {
            const opcodetype opcode{static_cast<opcodetype>(opcode_value)};
            const bool expected{std::ranges::find(expected_op_success, static_cast<uint8_t>(opcode_value)) != expected_op_success.end()};
            BOOST_TEST_CONTEXT("opcode " << opcode_value) {
                BOOST_CHECK_EQUAL(IsOpSuccess(opcode, sigversion), expected);
            }
        }
    };

    check_all_opcodes(SigVersion::TAPSCRIPT, tapscript_op_success);
    check_all_opcodes(SigVersion::TAPSCRIPT_V2, tapscript_v2_op_success);
}

BOOST_AUTO_TEST_CASE(meta_opcodes_are_tapscript_v2_only_redefinitions)
{
    for (const opcodetype opcode : {OP_MACRO, OP_CALLMACRO}) {
        CScript script{OneOp(opcode)};

        BOOST_CHECK(IsOpSuccess(opcode, SigVersion::TAPSCRIPT));
        BOOST_CHECK(!IsOpSuccess(opcode, SigVersion::TAPSCRIPT_V2));

        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const auto v2_result{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(v2_result.has_value());
        BOOST_CHECK(!*v2_result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_BAD_OPCODE);

        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const auto v1_result{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT, &error)};
        BOOST_REQUIRE(v1_result.has_value());
        BOOST_CHECK(*v1_result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(fragment_reference_executes_field_fragment)
{
    CScript body;
    body << OP_MUL << Num(13) << OP_MOD;
    CScript script;
    AppendDefinition(script, body);
    script << Num(7) << Num(11);
    AppendReference(script, 0);

    const uint64_t cost{varops::MulCost(1, 1) + varops::ModCost(1, 1) + InvokedBodyCost(body)};
    CheckEval(script, {}, {Num(12)}, cost);
}

BOOST_AUTO_TEST_CASE(fragment_unrolls_to_inline_sequence)
{
    const CScript inline_script{CScript{} << OP_1 << OP_2 << OP_ADD << OP_3 << OP_4 << OP_ADD
                                          << OP_ADD << OP_10 << OP_EQUAL};

    const CScript body{OneOp(OP_ADD)};
    CScript fragment_script;
    AppendDefinition(fragment_script, body);
    fragment_script << OP_1 << OP_2;
    AppendReference(fragment_script, 0);
    fragment_script << OP_3 << OP_4;
    AppendReference(fragment_script, 0);
    fragment_script << OP_ADD << OP_10 << OP_EQUAL;

    constexpr uint64_t budget{1'000'000};
    const EvalOutcome inlined{EvalTapscriptV2(inline_script, {}, budget)};
    const EvalOutcome fragmented{EvalTapscriptV2(fragment_script, {}, budget)};
    BOOST_REQUIRE(inlined.ok);
    BOOST_REQUIRE(fragmented.ok);
    BOOST_CHECK(inlined.stack == Stack{Num(1)});
    BOOST_CHECK(fragmented.stack == inlined.stack);

    const uint64_t overhead{MacroDefinitionCost(body.size()) + 2 * MacroCallCost(body.size())};
    BOOST_CHECK_EQUAL(inlined.remaining_budget - fragmented.remaining_budget, overhead);
}

BOOST_AUTO_TEST_CASE(nested_fragment_unrolls_to_inline_sequence)
{
    const CScript inline_script{CScript{} << OP_3 << OP_DUP << OP_ADD << OP_6 << OP_EQUAL};
    const CScript inner{OneOp(OP_ADD)};
    CScript outer;
    outer << OP_DUP;
    AppendReference(outer, 0);

    CScript nested_script;
    AppendDefinition(nested_script, inner);
    AppendDefinition(nested_script, outer);
    nested_script << OP_3;
    AppendReference(nested_script, 1);
    nested_script << OP_6 << OP_EQUAL;

    constexpr uint64_t budget{1'000'000};
    const EvalOutcome inlined{EvalTapscriptV2(inline_script, {}, budget)};
    const EvalOutcome nested{EvalTapscriptV2(nested_script, {}, budget)};
    BOOST_REQUIRE(inlined.ok);
    BOOST_REQUIRE(nested.ok);
    BOOST_CHECK(inlined.stack == Stack{Num(1)});
    BOOST_CHECK(nested.stack == inlined.stack);

    const uint64_t overhead{MacroDefinitionCost(inner.size()) + MacroDefinitionCost(outer.size()) +
                            MacroCallCost(inner.size()) + MacroCallCost(outer.size())};
    BOOST_CHECK_EQUAL(inlined.remaining_budget - nested.remaining_budget, overhead);
}

BOOST_AUTO_TEST_CASE(literal_push_copying_budget)
{
    for (const size_t size : {0U, 1U, 520U, 65'536U, 4'000'000U}) {
        const valtype value(size, 0x42);
        const CScript body{CScript{} << value};
        const uint64_t cost{LiteralPushCost(size)};
        const auto direct{EvalTapscriptV2(body, {}, cost)};
        BOOST_CHECK(direct.ok);
        BOOST_CHECK_EQUAL(direct.remaining_budget, 0);
        BOOST_CHECK(direct.stack == Stack{value});
        BOOST_CHECK_EQUAL(EvalTapscriptV2(body, {}, cost - 1).error, SCRIPT_ERR_VAROP_COUNT);

        if (size <= 65'536) {
            CScript script;
            AppendDefinition(script, body);
            AppendReference(script, 0);
            const uint64_t function_cost{MacroDefinitionCost(body.size()) +
                                         MacroCallCost(body.size()) + cost};
            const auto function{EvalTapscriptV2(script, {}, function_cost)};
            BOOST_CHECK(function.ok);
            BOOST_CHECK_EQUAL(function.remaining_budget, 0);
            BOOST_CHECK(function.stack == direct.stack);
            BOOST_CHECK_EQUAL(EvalTapscriptV2(script, {}, function_cost - 1).error, SCRIPT_ERR_VAROP_COUNT);
        }
    }
}

BOOST_AUTO_TEST_CASE(fragment_reference_shares_altstack)
{
    const CScript body{OneOp(OP_FROMALTSTACK)};
    CScript script;
    AppendDefinition(script, body);
    script << Num(7) << OP_TOALTSTACK;
    AppendReference(script, 0);

    CheckEval(script, {}, {Num(7)}, InvokedBodyCost(body));
}

BOOST_AUTO_TEST_CASE(fragment_indices_and_compactsize_are_canonical)
{
    const CScript body{OneOp(OP_1)};
    CScript script;
    for (unsigned int i{0}; i < 253; ++i) AppendDefinition(script, CScript{});
    AppendDefinition(script, body);
    AppendReference(script, 253);
    CheckEval(script, {}, {Num(1)}, InvokedBodyCost(body));

    CScript immediate_is_not_opcode;
    for (unsigned int i{0}; i <= 0x50; ++i) AppendDefinition(immediate_is_not_opcode, CScript{});
    AppendReference(immediate_is_not_opcode, 0x50);
    immediate_is_not_opcode << OP_RETURN;
    CheckError(immediate_is_not_opcode, {}, 0, SCRIPT_ERR_OP_RETURN);

    CScript noncanonical_index;
    AppendDefinition(noncanonical_index, body);
    noncanonical_index << OP_CALLMACRO;
    for (unsigned char byte : {0xfd, 0x00, 0x00}) noncanonical_index.push_back(byte);
    CheckError(noncanonical_index, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript out_of_range;
    AppendDefinition(out_of_range, body);
    AppendReference(out_of_range, 1);
    CheckError(out_of_range, {}, 0, SCRIPT_ERR_BAD_OPCODE);
    CheckError(OneOp(OP_CALLMACRO), {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript noncanonical_length;
    noncanonical_length << OP_MACRO;
    for (unsigned char byte : {0xfd, 0x00, 0x00}) noncanonical_length.push_back(byte);
    CheckError(noncanonical_length, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript truncated_body;
    truncated_body << OP_MACRO;
    truncated_body.push_back(0x02);
    truncated_body.push_back(OP_1);
    CheckError(truncated_body, {}, 0, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(fragment_bodies_are_validated_when_referenced)
{
    const CScript malformed_body{OneOp(OP_PUSHDATA1)};
    CScript define_only;
    AppendDefinition(define_only, malformed_body);
    define_only << OP_1;
    CheckEval(define_only, {}, {Num(1)}, 0);

    CScript invoke_malformed;
    AppendDefinition(invoke_malformed, malformed_body);
    AppendReference(invoke_malformed, 0);
    CheckError(invoke_malformed, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript conditional_body;
    conditional_body << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    CScript conditional;
    AppendDefinition(conditional, conditional_body);
    conditional << OP_1;
    AppendReference(conditional, 0);
    CheckEval(conditional, {}, {Num(2)},
              InvokedBodyCost(conditional_body) - varops::ExecutionCost(OP_3));

    const CScript codeseparator_body{OneOp(OP_CODESEPARATOR)};
    CScript codeseparator;
    AppendDefinition(codeseparator, codeseparator_body);
    AppendReference(codeseparator, 0);
    CheckEval(codeseparator, {}, {}, InvokedBodyCost(codeseparator_body));

    CScript nested_reference;
    AppendDefinition(nested_reference, OneOp(OP_CALLMACRO));
    AppendReference(nested_reference, 0);
    CheckError(nested_reference, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript self_body;
    AppendReference(self_body, 0);
    CScript self_reference;
    AppendDefinition(self_reference, self_body);
    AppendReference(self_reference, 0);
    CheckError(self_reference, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript forward_body;
    AppendReference(forward_body, 1);
    CScript forward_reference;
    AppendDefinition(forward_reference, forward_body);
    AppendDefinition(forward_reference, OneOp(OP_1));
    AppendReference(forward_reference, 0);
    CheckError(forward_reference, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript unreferenced_forward;
    AppendDefinition(unreferenced_forward, forward_body);
    AppendDefinition(unreferenced_forward, OneOp(OP_1));
    unreferenced_forward << OP_1;
    CheckEval(unreferenced_forward, {}, {Num(1)}, 0);

    CScript unbalanced;
    AppendDefinition(unbalanced, OneOp(OP_IF));
    unbalanced << OP_0 << OP_IF;
    AppendReference(unbalanced, 0);
    unbalanced << OP_ENDIF << OP_1;
    CheckError(unbalanced, {}, 0, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
}

BOOST_AUTO_TEST_CASE(fragment_prescan_reuses_body_summary_and_preserves_order)
{
    // Re-decoding this body for every reference would process over 2 GB of
    // pushed data before reaching the OP_SUCCESS in the main script.
    CScript body;
    body << valtype(256'000, 0x42) << OP_DROP;
    CScript repeated;
    AppendDefinition(repeated, body);
    repeated << OP_0 << OP_IF;
    for (int i{0}; i < 8'192; ++i) AppendReference(repeated, 0);
    repeated << OP_ENDIF << OP_RESERVED;

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const auto success{CheckTapscriptOpSuccess(repeated, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(success.has_value());
    BOOST_CHECK(*success);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    CScript malformed_body;
    malformed_body << OP_PUSHDATA4;
    CScript failure_first;
    AppendDefinition(failure_first, malformed_body);
    AppendReference(failure_first, 0);
    failure_first << OP_RESERVED;
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!CheckTapscriptOpSuccess(failure_first, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error).has_value());
    BOOST_CHECK_EQUAL(EvalTapscriptV2(failure_first, {}, 1'000'000).error, SCRIPT_ERR_BAD_OPCODE);

    CScript success_first;
    AppendDefinition(success_first, malformed_body);
    success_first << OP_RESERVED;
    AppendReference(success_first, 0);
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    const auto earlier_success{CheckTapscriptOpSuccess(success_first, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(earlier_success.has_value());
    BOOST_CHECK(*earlier_success);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    CScript success_before_malformed_body;
    success_before_malformed_body << OP_RESERVED << OP_PUSHDATA4;
    CScript success_inside_body;
    AppendDefinition(success_inside_body, success_before_malformed_body);
    AppendReference(success_inside_body, 0);
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    const auto body_success{CheckTapscriptOpSuccess(success_inside_body, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(body_success.has_value());
    BOOST_CHECK(*body_success);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(nested_fragment_prescan_is_linear_and_preserves_order)
{
    CScript branching;
    AppendDefinition(branching, OneOp(OP_NOP));
    for (uint64_t i{1}; i < 24; ++i) {
        CScript body;
        AppendReference(body, i - 1);
        AppendReference(body, i - 1);
        AppendDefinition(branching, body);
    }
    AppendReference(branching, 23);
    branching << OP_RESERVED;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const auto success{CheckTapscriptOpSuccess(branching, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(success.has_value());
    BOOST_CHECK(*success);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    CScript inner_success;
    inner_success << OP_RESERVED << OP_PUSHDATA4;
    CScript outer_success;
    AppendReference(outer_success, 0);
    outer_success << OP_PUSHDATA4;
    CScript nested_success;
    AppendDefinition(nested_success, inner_success);
    AppendDefinition(nested_success, outer_success);
    AppendReference(nested_success, 1);
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    const auto first_success{CheckTapscriptOpSuccess(nested_success, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(first_success.has_value());
    BOOST_CHECK(*first_success);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    CScript inner_failure;
    inner_failure << OP_PUSHDATA4;
    CScript outer_failure;
    AppendReference(outer_failure, 0);
    outer_failure << OP_RESERVED;
    CScript nested_failure;
    AppendDefinition(nested_failure, inner_failure);
    AppendDefinition(nested_failure, outer_failure);
    AppendReference(nested_failure, 1);
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    BOOST_CHECK(!CheckTapscriptOpSuccess(nested_failure, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error).has_value());
    BOOST_CHECK_EQUAL(EvalTapscriptV2(nested_failure, {}, 1'000'000).error, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(nested_fragment_depth_is_bounded_by_declarations)
{
    CScript script;
    AppendDefinition(script, OneOp(OP_1));
    for (uint64_t i{1}; i < 2'048; ++i) {
        CScript body;
        AppendReference(body, i - 1);
        AppendDefinition(script, body);
    }
    AppendReference(script, 2'047);
    const EvalOutcome outcome{EvalTapscriptV2(script, {}, 40'000'000)};
    BOOST_REQUIRE(outcome.ok);
    BOOST_CHECK(outcome.stack == Stack{Num(1)});
}

BOOST_AUTO_TEST_CASE(fragment_definitions_are_prefix_only)
{
    CScript script;
    AppendDefinition(script, OneOp(OP_1));
    script << OP_0 << OP_IF << OP_MACRO << OP_ENDIF << OP_1;
    CheckError(script, {}, 0, SCRIPT_ERR_BAD_OPCODE);

    CScript body_with_definition;
    body_with_definition << OP_MACRO << OP_0;
    CScript referenced;
    AppendDefinition(referenced, body_with_definition);
    AppendReference(referenced, 0);
    CheckError(referenced, {}, 0, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(inactive_fragment_charges_reference_and_conditional_control)
{
    const CScript body{CScript{} << OP_0 << OP_IF << OP_1 << OP_ENDIF};
    CScript script;
    AppendDefinition(script, body);
    script << OP_0 << OP_IF;
    AppendReference(script, 0);
    script << OP_ENDIF << OP_1;

    const uint64_t body_control_cost{varops::ExecutionCost(OP_IF) + varops::ExecutionCost(OP_ENDIF)};
    const uint64_t additional{varops::MacroDecodeCost(body.size()) + body_control_cost};
    CheckEval(script, {}, {Num(1)}, additional);
    CheckError(script, {}, additional - 1, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(fragment_conditionals_cross_boundaries)
{
    const CScript opening{CScript{} << OP_IF << OP_DUP};
    CScript script;
    AppendDefinition(script, opening);
    script << Num(9) << OP_1;
    AppendReference(script, 0);
    script << OP_ENDIF;
    CheckEval(script, {}, {Num(9), Num(9)}, InvokedBodyCost(opening) +
              varops::COST_COPYING * Num(9).size());

    const CScript flipping{CScript{} << OP_ELSE << OP_2};
    CScript inactive;
    AppendDefinition(inactive, flipping);
    inactive << OP_0 << OP_IF;
    AppendReference(inactive, 0);
    inactive << OP_ENDIF;
    CheckEval(inactive, {}, {Num(2)}, InvokedBodyCost(flipping));

    CScript nested_flipping;
    AppendReference(nested_flipping, 0);
    CScript nested_inactive;
    AppendDefinition(nested_inactive, flipping);
    AppendDefinition(nested_inactive, nested_flipping);
    nested_inactive << OP_0 << OP_IF;
    AppendReference(nested_inactive, 1);
    nested_inactive << OP_ENDIF;
    CheckEval(nested_inactive, {}, {Num(2)}, InvokedBodyCost(nested_flipping) + InvokedBodyCost(flipping));
}

BOOST_AUTO_TEST_CASE(fragment_signature_uses_callers_codeseparator)
{
    const CScript body{OneOp(OP_CHECKSIG)};
    CScript script;
    AppendDefinition(script, body);
    script << OP_CODESEPARATOR;
    AppendReference(script, 0);

    RecordingChecker checker;
    const Stack stack{valtype(64, 0x01), valtype(32, 0x02)};
    const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(
        script, stack, SCRIPT_VERIFY_NONE, checker, AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE(outcome.ok);
    BOOST_CHECK_EQUAL(checker.schnorr_calls, 1);
    BOOST_CHECK_EQUAL(checker.last_codeseparator_pos, 0);
}

BOOST_AUTO_TEST_CASE(fragment_codeseparator_uses_unrolled_position)
{
    const CScript body{OneOp(OP_CODESEPARATOR)};
    CScript script;
    AppendDefinition(script, body);
    script << OP_NOP;
    AppendReference(script, 0);
    script << OP_CHECKSIG;

    RecordingChecker checker;
    const Stack stack{valtype(64, 0x01), valtype(32, 0x02)};
    const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(
        script, stack, SCRIPT_VERIFY_NONE, checker, AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE(outcome.ok);
    BOOST_CHECK_EQUAL(checker.last_codeseparator_pos, 1);

    CScript nested_body;
    nested_body << OP_NOP;
    AppendReference(nested_body, 0);
    CScript nested;
    AppendDefinition(nested, body);
    AppendDefinition(nested, nested_body);
    nested << OP_NOP;
    AppendReference(nested, 1);
    nested << OP_CHECKSIG;
    RecordingChecker nested_checker;
    const EvalOutcome nested_outcome{EvalTapscriptV2WithFlagsAndChecker(
        nested, stack, SCRIPT_VERIFY_NONE, nested_checker, AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE(nested_outcome.ok);
    BOOST_CHECK_EQUAL(nested_checker.last_codeseparator_pos, 2);

    CScript skipped_body;
    for (int i{0}; i < 128; ++i) skipped_body << OP_NOP;
    CScript skipped;
    AppendDefinition(skipped, skipped_body);
    skipped << OP_0 << OP_IF;
    AppendReference(skipped, 0);
    skipped << OP_ENDIF << OP_CODESEPARATOR << OP_CHECKSIG;
    RecordingChecker skipped_checker;
    const EvalOutcome skipped_outcome{EvalTapscriptV2WithFlagsAndChecker(
        skipped, stack, SCRIPT_VERIFY_NONE, skipped_checker, AMPLE_VAROPS_BUDGET)};
    BOOST_REQUIRE(skipped_outcome.ok);
    BOOST_CHECK_EQUAL(skipped_checker.last_codeseparator_pos, 131);
}

BOOST_AUTO_TEST_CASE(fragment_codeseparator_position_does_not_wrap)
{
    // 4096 references to 2^20 skipped opcodes place the next opcode beyond uint32.
    CScript body;
    body.insert(body.end(), 1 << 20, static_cast<unsigned char>(OP_NOP));
    CScript script;
    AppendDefinition(script, body);
    script << OP_0 << OP_IF;
    for (int i{0}; i < 4096; ++i) AppendReference(script, 0);
    script << OP_ENDIF;

    CScript without_separator{script};
    without_separator << OP_1;
    CheckEval(without_separator, {}, {Num(1)},
              uint64_t{4096} * (varops::FixedOpcodeCost() + varops::MacroDecodeCost(body.size())));

    script << OP_CODESEPARATOR << OP_1;
    CheckError(script, {}, 0, SCRIPT_ERR_OP_CODESEPARATOR);
}

BOOST_AUTO_TEST_CASE(referenced_op_success_is_terminal)
{
    CScript body;
    body << OP_1NEGATE;
    body.push_back(static_cast<unsigned char>(OP_PUSHDATA4));

    CScript script;
    AppendDefinition(script, body);
    AppendReference(script, 0);
    script << OP_RETURN;

    EvalOutcome outcome{VerifyTapscriptV2WithFlags(
        script, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2WithFlags(
        script, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
        0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

    CScript uninvoked;
    AppendDefinition(uninvoked, body);
    uninvoked << OP_1;
    outcome = VerifyTapscriptV2(uninvoked, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(outcome.ok);

    CScript inactive;
    AppendDefinition(inactive, body);
    inactive << OP_0 << OP_IF;
    AppendReference(inactive, 0);
    inactive << OP_ENDIF << OP_RETURN;
    outcome = VerifyTapscriptV2WithFlags(
        inactive, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(outcome.ok);
}

BOOST_AUTO_TEST_CASE(witness_data_cannot_define_fragment_body)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey xonly_pubkey{key.GetPubKey()};
    const valtype pubkey{xonly_pubkey.begin(), xonly_pubkey.end()};

    CScript leaf_script;
    AppendDefinition(leaf_script, OneOp(OP_DROP));
    AppendReference(leaf_script, 0);
    leaf_script << pubkey << OP_CHECKSIGVERIFY << OP_1;

    const auto verify_body{[&](opcodetype body_opcode, script_verify_flags flags) {
        // The first witness item is an empty signature; the second resembles a body opcode.
        const FinalizedTapscriptV2Spend spend{BuildFinalizedTapscriptV2Spend(
            leaf_script, {valtype{}, valtype{static_cast<unsigned char>(body_opcode)}})};
        const CTransaction tx{spend.tx};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spend.spent_output});
        const TransactionSignatureChecker checker{&tx, 0, spend.spent_output.nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        varops::Budget budget{varops::TxBudget(GetTransactionWeight(tx))};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool ok{VerifyScript(CScript{}, spend.spent_output.scriptPubKey, &tx.vin[0].scriptWitness,
                                   flags, checker, &error, budget)};
        return std::pair{ok, error};
    }};

    const auto [ordinary_ok, ordinary_error]{verify_body(OP_NOP, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!ordinary_ok);
    BOOST_CHECK_EQUAL(ordinary_error, SCRIPT_ERR_CHECKSIGVERIFY);

    const auto [success_ok, success_error]{verify_body(OP_1NEGATE, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS)};
    BOOST_CHECK(!success_ok);
    BOOST_CHECK_EQUAL(success_error, SCRIPT_ERR_CHECKSIGVERIFY);

    const auto [discouraged_ok, discouraged_error]{verify_body(
        OP_1NEGATE, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)};
    BOOST_CHECK(!discouraged_ok);
    BOOST_CHECK_EQUAL(discouraged_error, SCRIPT_ERR_CHECKSIGVERIFY);
}

BOOST_AUTO_TEST_CASE(fragment_declarations_do_not_use_stack_limits)
{
    const valtype maximum_body(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x00);
    const valtype maximum_live_value(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    const Stack byte_limit_stack{maximum_live_value};
    CScript define_maximum_body;
    AppendDefinition(define_maximum_body, CScript{maximum_body.begin(), maximum_body.end()});
    define_maximum_body << OP_1;
    CheckEval(define_maximum_body, byte_limit_stack, {maximum_live_value, Num(1)}, 0);

    CScript exceed_byte_limit{define_maximum_body};
    exceed_byte_limit << OP_SWAP << OP_DUP;
    CheckError(exceed_byte_limit, byte_limit_stack, 0, SCRIPT_ERR_TOTAL_STACK_SIZE);

    Stack entry_limit_stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{});
    CScript exact_entry_limit;
    AppendDefinition(exact_entry_limit, CScript{});
    exact_entry_limit << OP_0;
    const EvalOutcome exact_entries{EvalTapscriptV2(
        exact_entry_limit, entry_limit_stack, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(exact_entries.ok);

    CScript exceed_entry_limit;
    AppendDefinition(exceed_entry_limit, CScript{});
    exceed_entry_limit << OP_0 << OP_0;
    CheckError(exceed_entry_limit, entry_limit_stack, 0, SCRIPT_ERR_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(base_evalscript_rejects_tapscript_v2)
{
    Stack stack;
    CScript script;
    script << OP_TRUE;
    ScriptExecutionData execdata;
    ScriptError error{SCRIPT_ERR_OK};

    BOOST_CHECK(!::EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::TAPSCRIPT_V2, execdata, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_UNKNOWN_ERROR);
    BOOST_CHECK(stack.empty());
}

BOOST_AUTO_TEST_CASE(tapscript_v2_leaf_requires_script_restoration_flag)
{
    CScript false_script;
    false_script << OP_0;

    EvalOutcome outcome{VerifyTapscriptV2WithFlags(false_script, {}, TAPROOT_SCRIPT_VERIFY_FLAGS, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2WithFlags(false_script, {},
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
                                         0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION);

    outcome = VerifyTapscriptV2WithFlags(false_script, {},
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_SCRIPT_RESTORATION,
                                         0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_SCRIPT_RESTORATION);

    outcome = VerifyTapscriptV2WithFlags(false_script, {},
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORATION,
                                         AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_EVAL_FALSE);

    CScript true_script;
    true_script << OP_1;
    outcome = VerifyTapscriptV2WithFlags(true_script, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(tapleaf_versions_isolate_restored_opcodes)
{
    const CScript restored_script{OneOp(OP_MUL)};

    EvalOutcome outcome{VerifyTaprootLeafWithFlags(restored_script, {}, TAPROOT_LEAF_TAPSCRIPT,
                                            TAPROOT_SCRIPT_VERIFY_FLAGS, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTaprootLeafWithFlags(restored_script, {}, TAPROOT_LEAF_TAPSCRIPT_V2,
                                         TAPROOT_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTaprootLeafWithFlags(restored_script, {}, TAPROOT_LEAF_TAPSCRIPT_V2,
                                         TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_INVALID_STACK_OPERATION);

    const CScript cat_script{OneOp(OP_CAT)};
    outcome = VerifyTaprootLeafWithFlags(cat_script, {}, TAPROOT_LEAF_TAPSCRIPT,
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

    outcome = VerifyTaprootLeafWithFlags(cat_script, {}, TAPROOT_LEAF_TAPSCRIPT,
                                         TAPROOT_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(final_result_costs)
{
    for (const size_t size : {0U, 1U, 8U, 9U, 521U, 65536U}) {
        for (const bool nonzero : {false, true}) {
            if (size == 0 && nonzero) continue;
            valtype value(size, 0);
            if (nonzero) value.back() = 1;
            const uint64_t cost{varops::PrepCost(size) + varops::ReadCost(size)};
            for (const bool sufficient : {false, true}) {
                ValtypeStack stack{Stack{value}};
                varops::Budget budget{cost - (sufficient ? 0 : 1)};
                ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
                BOOST_CHECK_EQUAL(CheckTapscriptV2ScriptResult(stack, budget, &error), sufficient && nonzero);
                BOOST_CHECK_EQUAL(error, !sufficient ? SCRIPT_ERR_VAROP_COUNT :
                                         nonzero ? SCRIPT_ERR_OK : SCRIPT_ERR_EVAL_FALSE);
                if (sufficient) BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(producer_lifetime_accounting)
{
    if constexpr (!varops::PRODUCER_LIFETIME_EXPERIMENT) return;
    for (size_t size : {0U, 1U, 521U, 65536U}) {
        const Stack initial{valtype(size, 0x42)};
        const uint64_t creation{varops::CopyCost(size)};
        const auto check = [&](const CScript& script, uint64_t cost) {
            const auto exact{test::tapscript_v2::EvalTapscriptV2(script, initial, cost)};
            BOOST_REQUIRE(exact.ok);
            BOOST_CHECK(exact.stack.empty());
            BOOST_CHECK_EQUAL(exact.remaining_budget, 0);
            const auto short_budget{test::tapscript_v2::EvalTapscriptV2(script, initial, cost - 1)};
            BOOST_CHECK(!short_budget.ok);
            BOOST_CHECK_EQUAL(short_budget.error, SCRIPT_ERR_VAROP_COUNT);
        };
        check(CScript{} << OP_DROP, creation + varops::FixedOpcodeCost());
        check(CScript{} << OP_TOALTSTACK << OP_FROMALTSTACK << OP_DROP,
              creation + 3 * varops::FixedOpcodeCost() + 2 * varops::MoveCost(1));
        check(CScript{} << OP_DUP << OP_2DROP, 2 * creation + 2 * varops::FixedOpcodeCost());
        const valtype zero;
        const Stack shrink_initial{initial.front(), zero};
        const uint64_t shrink_cost{creation + varops::CopyCost(0) + 2 * varops::FixedOpcodeCost() +
                                   varops::PrepCost(0) + varops::ReadCost(0)};
        const auto shrink{test::tapscript_v2::EvalTapscriptV2(CScript{} << OP_LEFT << OP_DROP, shrink_initial, shrink_cost)};
        BOOST_REQUIRE(shrink.ok);
        BOOST_CHECK_EQUAL(shrink.remaining_budget, 0);
    }
    // Multiplication constructs both a full-span result and a scratch row.
    // Their production is charged before the row kernel, not at final output size.
    const Stack operands{Num(2), Num(3)};
    const uint64_t preflight{2 * varops::CopyCost(1) + varops::FixedOpcodeCost() +
                             2 * varops::PrepCost(1) + varops::CopyCost(16) +
                             varops::PrepCost(16) + varops::CopyCost(16) +
                             varops::MulRowCost(1) + varops::ArithCost(16)};
    const uint64_t materialize{varops::OutputCost(1) - varops::CopyCost(8)};
    const auto exact{test::tapscript_v2::EvalTapscriptV2(OneOp(OP_MUL), operands, preflight + materialize)};
    BOOST_REQUIRE(exact.ok);
    BOOST_CHECK(exact.stack == Stack{Num(6)});
    BOOST_CHECK_EQUAL(exact.remaining_budget, 0);
    const auto insufficient{test::tapscript_v2::EvalTapscriptV2(OneOp(OP_MUL), operands, preflight - 1)};
    BOOST_CHECK(!insufficient.ok);
    BOOST_CHECK_EQUAL(insufficient.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK(insufficient.stack == operands);
}

BOOST_AUTO_TEST_CASE(producer_composition_boundaries)
{
    if constexpr (!varops::PRODUCER_LIFETIME_EXPERIMENT) return;
    const auto check = [](opcodetype opcode, const Stack& inputs, const valtype& output, uint64_t work) {
        const uint64_t total{InitialLifetimeCost(inputs) + varops::FixedOpcodeCost() + work};
        const auto exact{test::tapscript_v2::EvalTapscriptV2(OneOp(opcode), inputs, total)};
        BOOST_REQUIRE(exact.ok);
        BOOST_CHECK(exact.stack == Stack{output});
        BOOST_CHECK_EQUAL(exact.remaining_budget, 0);
        const auto short_budget{test::tapscript_v2::EvalTapscriptV2(OneOp(opcode), inputs, total - 1)};
        BOOST_CHECK(!short_budget.ok);
        BOOST_CHECK_EQUAL(short_budget.error, SCRIPT_ERR_VAROP_COUNT);
    };
    for (size_t size : {0U, 1U, 7U, 8U, 9U, 63U, 64U, 65U, 520U, 521U, 65535U, 65536U, 65537U}) {
        valtype source(size, 0xff);
        valtype joined{source};
        joined.push_back(1);
        check(OP_CAT, {source, Num(1)}, joined, varops::CopyCost(size + 1));
        const size_t kept{std::min<size_t>(1, size)};
        check(OP_SUBSTR, {source, Num(0), Num(1)}, valtype(kept, 0xff),
              varops::PrepCost(0) + varops::ReadCost(0) + varops::PrepCost(1) +
              varops::ReadCost(1) + varops::CopyCost(kept));
        // Carry growth crosses each byte/word boundary; the result's lifetime
        // is funded once, not separately again when its bytes are materialized.
        valtype sum(size + 1, 0);
        sum.back() = 1;
        check(OP_ADD, {source, Num(1)}, sum,
              varops::PrepCost(size) + varops::PrepCost(1) +
              varops::ArithCost(std::max(varops::WordSpan(size), uint64_t{8})) + varops::OutputCost(size + 1));
        if (size) {
            valtype power(size + 1, 0);
            power.back() = 1;
            check(OP_SUB, {power, Num(1)}, source,
                  varops::PrepCost(size + 1) + varops::PrepCost(1) +
                  varops::ArithCost(varops::WordSpan(size + 1)) + varops::OutputCost(size));
        }
    }
}

BOOST_AUTO_TEST_CASE(in_place_splice_costs)
{
    for (const size_t size : {8U, 521U, 65536U, 3950000U}) {
        for (const size_t retained : {size_t{0}, size_t{1}, size / 2, size}) {
            const valtype offset{Num(retained)};
            for (const opcodetype opcode : {OP_LEFT, OP_RIGHT}) {
                const uint64_t cost{(varops::PRODUCER_LIFETIME_EXPERIMENT ? varops::CopyCost(size) + varops::CopyCost(offset.size()) : 0) +
                                    varops::FixedOpcodeCost() + varops::PrepCost(offset.size()) +
                                    varops::ReadCost(offset.size()) +
                                    (opcode == OP_RIGHT ? varops::CopyCost(retained) - varops::CopyCost(0) : 0)};
                const Stack initial{valtype(size, 0x42), offset};
                const auto exact{test::tapscript_v2::EvalTapscriptV2(OneOp(opcode), initial, cost)};
                BOOST_REQUIRE(exact.ok);
                BOOST_CHECK_EQUAL(exact.error, SCRIPT_ERR_OK);
                BOOST_CHECK_EQUAL(exact.remaining_budget, 0);
                BOOST_CHECK(exact.stack == Stack{valtype(retained, 0x42)});
                const auto short_budget{test::tapscript_v2::EvalTapscriptV2(OneOp(opcode), initial, cost - 1)};
                BOOST_CHECK(!short_budget.ok);
                BOOST_CHECK_EQUAL(short_budget.error, SCRIPT_ERR_VAROP_COUNT);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(splice_opcodes_follow_bip441_byte_ranges)
{
    CheckEval(OneOp(OP_CAT), {Bytes("ab"), Bytes("cde")}, {Bytes("abcde")}, (2 + 3) * varops::COST_COPYING);

    CScript substr;
    substr << OP_SUBSTR;
    CheckEval(substr, {Bytes("abcdef"), Num(2), Num(3)}, {Bytes("cde")},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1) + 3 * varops::COST_COPYING);
    CheckError(substr, {Bytes("abcdef"), Num(2), Num(3)},
               varops::LengthConversionCost(1) + varops::LengthConversionCost(1) + 3 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(substr, {Bytes("abcdef"), Num(9), Num(3)}, {Bytes({})},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1));
    CheckEval(substr, {Bytes("abcdef"), Num(6), Num(3)}, {Bytes({})},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1));
    CheckEval(substr, {Bytes("abcdef"), Num(4), Num(9)}, {Bytes("ef")},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);
    CheckEval(substr, {Bytes("abcdef"), Num(2), LargerThanU64()}, {Bytes("cdef")},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(9) + 4 * varops::COST_COPYING);
    CheckEval(substr, {Bytes("abcdef"), LargerThanU64(), LargerThanU64()}, {Bytes({})},
              varops::LengthConversionCost(9) + varops::LengthConversionCost(9));

    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Num(0)}, {Bytes({})}, 0);
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Num(2)}, {Bytes("ab")}, varops::LengthConversionCost(1));
    CheckError(OneOp(OP_LEFT), {Bytes("abcdef"), Num(2)}, varops::LengthConversionCost(1) - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Num(9)}, {Bytes("abcdef")}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), LargerThanU64()}, {Bytes("abcdef")}, varops::LengthConversionCost(9));
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Bytes({0x02, 0x00, 0x00})}, {Bytes("ab")},
              varops::LengthConversionCost(3));

    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(0)}, {Bytes({})}, 0);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(2)}, {Bytes("ef")},
              varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(2)},
               varops::LengthConversionCost(1) + 2 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(9)}, {Bytes("abcdef")},
              varops::LengthConversionCost(1) + 6 * varops::COST_COPYING);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), LargerThanU64()}, {Bytes("abcdef")},
              varops::LengthConversionCost(9) + 6 * varops::COST_COPYING);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Bytes({0x02, 0x00, 0x00})}, {Bytes("ef")},
              varops::LengthConversionCost(3) + 2 * varops::COST_COPYING);
}

BOOST_AUTO_TEST_CASE(length_operands_charge_encoded_width_even_when_value_is_zero)
{
    const valtype padded_zero{Bytes({0x00, 0x00, 0x00})};
    const uint64_t padded_zero_cost{varops::LengthConversionCost(padded_zero.size())};

    CheckEval(OneOp(OP_SUBSTR), {Bytes("abcdef"), padded_zero, padded_zero}, {Bytes({})},
              padded_zero_cost + padded_zero_cost);
    CheckError(OneOp(OP_SUBSTR), {Bytes("abcdef"), padded_zero, padded_zero},
               padded_zero_cost + padded_zero_cost - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), padded_zero}, {Bytes({})}, padded_zero_cost);
    CheckError(OneOp(OP_LEFT), {Bytes("abcdef"), padded_zero}, padded_zero_cost - 1,
               SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), padded_zero}, {Bytes({})}, padded_zero_cost);
    CheckError(OneOp(OP_RIGHT), {Bytes("abcdef"), padded_zero}, padded_zero_cost - 1,
               SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x12, 0x34}), padded_zero}, {Bytes({0x12, 0x34})},
              padded_zero_cost + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x12, 0x34}), padded_zero},
               padded_zero_cost + 2 * varops::COST_COPYING - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), padded_zero}, {Bytes({0x12, 0x34})},
              padded_zero_cost + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), padded_zero},
               padded_zero_cost + 2 * varops::COST_COPYING - 1, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(restored_bit_opcodes_preserve_non_arithmetic_width)
{
    CheckEval(OneOp(OP_INVERT), {Bytes({0x00, 0xff})}, {Bytes({0xff, 0x00})}, varops::InvertCost(2));
    CheckEval(OneOp(OP_AND), {Bytes({0xff, 0xff}), Bytes({0x0f})}, {Bytes({0x0f, 0x00})}, varops::AndCost(2, 1));
    CheckEval(OneOp(OP_OR), {Bytes({0x00, 0x00}), Bytes({0x00})}, {Bytes({0x00, 0x00})}, varops::OrCost(2, 1));
    CheckEval(OneOp(OP_XOR), {Bytes({0x01, 0x00}), Bytes({0x01})}, {Bytes({0x00, 0x00})}, varops::XorCost(2, 1));

    CScript invert_then_add;
    invert_then_add << OP_INVERT << OP_1ADD;
    CheckEval(invert_then_add, {Bytes({0x00})}, {Bytes({0x00, 0x01})},
              varops::InvertCost(1) + varops::AddCost(1, 1));
}

BOOST_AUTO_TEST_CASE(restored_shift_opcodes_are_raw_bitshifts)
{
    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x12, 0x34}), Num(0)}, {Bytes({0x12, 0x34})},
              2 * varops::COST_COPYING);
    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(1)}, {Bytes({0x02, 0x00})},
              varops::LengthConversionCost(1) + 1 * varops::COST_COPYING + varops::UnalignedUpShiftCost(1, 0));
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(1)},
               varops::LengthConversionCost(1) + 1 * varops::COST_COPYING + varops::UnalignedUpShiftCost(1, 0) - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_LSHIFT), {Bytes({}), Num(1)}, {Bytes({0x00})}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(8)}, {Bytes({0x00, 0x01})},
              varops::LengthConversionCost(1) + 1 * varops::COST_FAST + 1 * varops::COST_COPYING);
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(8)},
               varops::LengthConversionCost(1) + 1 * varops::COST_FAST + 1 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), Num(0)}, {Bytes({0x12, 0x34})},
              2 * varops::COST_COPYING);
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x02, 0x00}), Num(1)}, {Bytes({0x01, 0x00})},
              varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_RSHIFT), {Bytes({0x02, 0x00}), Num(1)},
               varops::LengthConversionCost(1) + 2 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_RSHIFT), {Bytes({}), Num(1)}, {Bytes({})}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0xff}), Num(8)}, {Bytes({})}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), LargerThanU64()}, {Bytes({})},
              varops::LengthConversionCost(9));
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x01}), LargerThanU64()}, 0, SCRIPT_ERR_STACK_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_costed_opcodes_reject_missing_stack_elements)
{
    for (const auto& [opcode, stack] : {
             std::pair{OP_VERIFY, Stack{}},
             std::pair{OP_2DUP, Stack{Bytes("a")}},
             std::pair{OP_3DUP, Stack{Bytes("a"), Bytes("b")}},
             std::pair{OP_2OVER, Stack{Bytes("a"), Bytes("b"), Bytes("c")}},
             std::pair{OP_IFDUP, Stack{}},
             std::pair{OP_DUP, Stack{}},
             std::pair{OP_OVER, Stack{Bytes("a")}},
             std::pair{OP_PICK, Stack{Num(0)}},
             std::pair{OP_ROLL, Stack{Num(0)}},
             std::pair{OP_ROT, Stack{Bytes("a"), Bytes("b")}},
             std::pair{OP_SWAP, Stack{Bytes("a")}},
             std::pair{OP_TUCK, Stack{Bytes("a")}},
             std::pair{OP_SIZE, Stack{}},
             std::pair{OP_EQUAL, Stack{Bytes("a")}},
             std::pair{OP_EQUALVERIFY, Stack{Bytes("a")}},
             std::pair{OP_NOT, Stack{}},
             std::pair{OP_0NOTEQUAL, Stack{}},
             std::pair{OP_BOOLAND, Stack{Bytes("a")}},
             std::pair{OP_BOOLOR, Stack{Bytes("a")}},
             std::pair{OP_NUMEQUAL, Stack{Bytes("a")}},
             std::pair{OP_NUMEQUALVERIFY, Stack{Bytes("a")}},
             std::pair{OP_NUMNOTEQUAL, Stack{Bytes("a")}},
             std::pair{OP_LESSTHAN, Stack{Bytes("a")}},
             std::pair{OP_GREATERTHAN, Stack{Bytes("a")}},
             std::pair{OP_LESSTHANOREQUAL, Stack{Bytes("a")}},
             std::pair{OP_GREATERTHANOREQUAL, Stack{Bytes("a")}},
             std::pair{OP_WITHIN, Stack{Bytes("a"), Bytes("b")}},
             std::pair{OP_RIPEMD160, Stack{}},
             std::pair{OP_SHA1, Stack{}},
             std::pair{OP_SHA256, Stack{}},
             std::pair{OP_HASH160, Stack{}},
             std::pair{OP_HASH256, Stack{}},
             std::pair{OP_CAT, Stack{Bytes("a")}},
             std::pair{OP_SUBSTR, Stack{Bytes("a"), Num(0)}},
             std::pair{OP_LEFT, Stack{Bytes("a")}},
             std::pair{OP_RIGHT, Stack{Bytes("a")}},
             std::pair{OP_INVERT, Stack{}},
             std::pair{OP_AND, Stack{Bytes("a")}},
             std::pair{OP_OR, Stack{Bytes("a")}},
             std::pair{OP_XOR, Stack{Bytes("a")}},
             std::pair{OP_1ADD, Stack{}},
             std::pair{OP_1SUB, Stack{}},
             std::pair{OP_2MUL, Stack{}},
             std::pair{OP_2DIV, Stack{}},
             std::pair{OP_ADD, Stack{Bytes("a")}},
             std::pair{OP_SUB, Stack{Bytes("a")}},
             std::pair{OP_MUL, Stack{Bytes("a")}},
             std::pair{OP_DIV, Stack{Bytes("a")}},
             std::pair{OP_MOD, Stack{Bytes("a")}},
             std::pair{OP_MIN, Stack{Bytes("a")}},
             std::pair{OP_MAX, Stack{Bytes("a")}},
             std::pair{OP_LSHIFT, Stack{Bytes("a")}},
             std::pair{OP_RSHIFT, Stack{Bytes("a")}},
         }) {
        BOOST_TEST_CONTEXT("opcode " << static_cast<int>(opcode)) {
            CheckError(OneOp(opcode), stack, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);
        }
    }
}

BOOST_AUTO_TEST_CASE(bip342_restricted_opcodes_remain_restricted_in_tapscript_v2)
{
    CheckError(OneOp(OP_RETURN), {}, 0, SCRIPT_ERR_OP_RETURN);
    CheckError(OneOp(OP_CHECKMULTISIG), {}, 0, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
    CheckError(OneOp(OP_CHECKMULTISIGVERIFY), {}, 0, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
}

BOOST_AUTO_TEST_CASE(restored_multiply_divide_and_modulo_opcodes)
{
    CheckEval(OneOp(OP_2MUL), {Bytes({0x80})}, {Bytes({0x00, 0x01})}, varops::TwoMulCost(1));
    CheckEval(OneOp(OP_2DIV), {Bytes({0x01})}, {Bytes({})}, varops::TwoDivCost(1));

    CheckEval(OneOp(OP_MUL), {Bytes({0xff, 0xff}), Bytes({0x02})}, {Bytes({0xfe, 0xff, 0x01})}, varops::MulCost(2, 1));
    CheckEval(OneOp(OP_DIV), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x7b})}, varops::DivCost(2, 1));
    CheckEval(OneOp(OP_MOD), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x2d})}, varops::ModCost(2, 1));

    for (const valtype& divisor : {Bytes({}), Bytes({0x00, 0x00})}) {
        CheckError(OneOp(OP_DIV), {Bytes({0x01}), divisor}, varops::DivCost(1, divisor.size()), SCRIPT_ERR_DIVIDE_BY_ZERO);
        CheckError(OneOp(OP_MOD), {Bytes({0x01}), divisor}, varops::ModCost(1, divisor.size()), SCRIPT_ERR_DIVIDE_BY_ZERO);
    }
}

BOOST_AUTO_TEST_CASE(extended_arithmetic_is_unsigned_and_normalized)
{
    CheckEval(OneOp(OP_1ADD), {Bytes({0xff})}, {Bytes({0x00, 0x01})}, varops::AddCost(1, 1));
    CheckEval(OneOp(OP_1SUB), {Bytes({0x01})}, {Bytes({})}, varops::SubCost(1, 1));
    CheckEval(OneOp(OP_ADD), {Bytes({0x01, 0x00, 0x00}), Bytes({})}, {Bytes({0x01})}, varops::AddCost(3, 0));
    CheckEval(OneOp(OP_SUB), {Bytes({0x00, 0x01}), Bytes({0x01})}, {Bytes({0xff})}, varops::SubCost(2, 1));

    CheckError(OneOp(OP_1SUB), {Bytes({})}, varops::SubCost(0, 1), SCRIPT_ERR_SUB_UNDERFLOW);
    CheckError(OneOp(OP_1SUB), {Bytes({0x00})}, varops::SubCost(1, 1), SCRIPT_ERR_SUB_UNDERFLOW);
    CheckError(OneOp(OP_SUB), {Bytes({0x01}), Bytes({0x02})}, varops::SubCost(1, 1), SCRIPT_ERR_SUB_UNDERFLOW);
    CheckError(OneOp(OP_SUB), {Bytes({0x00}), Bytes({0x01})}, varops::SubCost(1, 1), SCRIPT_ERR_SUB_UNDERFLOW);

    CheckEval(OneOp(OP_MIN), {Bytes({0x01, 0x00}), Bytes({0x02})}, {Bytes({0x01})}, varops::MinMaxCost(2, 1));
    CheckEval(OneOp(OP_MAX), {Bytes({0x01, 0x00}), Bytes({0x02})}, {Bytes({0x02})}, varops::MinMaxCost(2, 1));
}

BOOST_AUTO_TEST_CASE(add_small_operand_matches_general_add)
{
    // Compare both operand orders, including empty/padded zero, high-bit values,
    // full-word overflow, and the first size that must use the general path.
    for (size_t long_size : {0U, 1U, 7U, 8U, 9U, 16U, 17U, 32U, 65U}) {
        for (size_t short_size{0}; short_size <= std::min<size_t>(long_size, 9); ++short_size) {
            for (unsigned char fill : {0x00, 0x80, 0xff}) {
                const valtype left(long_size, fill);
                valtype right(short_size, 0);
                if (!right.empty()) right[0] = 1;
                Val64 a{valtype{left}}, b{valtype{right}};
                uint64_t cost{0};
                Val64::OpAdd(a, b, cost);
                const valtype expected{a.MoveToValtype()};
                BOOST_CHECK_EQUAL(cost, varops::AddCost(long_size, short_size));
                CheckEval(OneOp(OP_ADD), {left, right}, {expected}, cost);
                CheckEval(OneOp(OP_ADD), {right, left}, {expected}, cost);
            }
        }
    }
    CheckEval(OneOp(OP_ADD), {valtype(8, 0xff), valtype(8, 0xff)},
              {Bytes({0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})}, varops::AddCost(8, 8));
}

BOOST_AUTO_TEST_CASE(checksigadd_failure_normalizes_numeric_operand)
{
    const valtype empty_sig{};
    const valtype nonminimal_one{Bytes({0x01, 0x00})};
    const valtype minimal_one{Bytes({0x01})};
    const valtype xonly_pubkey(32, 0x02);

    CScript script;
    script << OP_CHECKSIGADD << minimal_one << OP_EQUAL;

    const EvalOutcome outcome{VerifyTapscriptV2(script, {empty_sig, nonminimal_one, xonly_pubkey}, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(checksigadd_enforces_numeric_result_boundaries)
{
    const valtype empty_sig{};
    const valtype nonempty_sig(64, 0x01);
    const valtype xonly_pubkey(32, 0x02);
    const valtype all_zero(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x00);
    const valtype all_ff(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0xff);
    const CScript script{OneOp(OP_CHECKSIGADD)};

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {nonempty_sig, all_ff, xonly_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_STACK_ELEMENT_SIZE);
        BOOST_CHECK_EQUAL(checker.schnorr_calls, 1);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {nonempty_sig, all_zero, xonly_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, AMPLE_VAROPS_BUDGET)};
        BOOST_REQUIRE(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK(outcome.stack == Stack{{0x01}});
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {empty_sig, all_zero, xonly_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, AMPLE_VAROPS_BUDGET)};
        BOOST_REQUIRE(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK(outcome.stack == Stack{{}});
        BOOST_CHECK_EQUAL(checker.schnorr_calls, 0);
    }

    {
        RecordingChecker checker;
        const valtype empty_pubkey{};
        const valtype number{0xff};
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {nonempty_sig, number, empty_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);
        BOOST_CHECK_EQUAL(checker.schnorr_calls, 0);
    }
}

BOOST_AUTO_TEST_CASE(bip440_costed_legacy_ops_use_unsigned_values)
{
    CheckEval(OneOp(OP_EQUAL), {Bytes("same"), Bytes("same")}, {Bytes({0x01})}, 4 * varops::COST_FAST);
    CheckEval(OneOp(OP_EQUAL), {Bytes("a"), Bytes("bb")}, {Bytes({})}, 0);
    CheckEval(OneOp(OP_VERIFY), {Bytes({0x00, 0x01})}, {}, varops::LengthConversionCost(2));
    CheckError(OneOp(OP_VERIFY), {Bytes({})}, 0, SCRIPT_ERR_VERIFY);
    CheckError(OneOp(OP_VERIFY), {Bytes({0x00, 0x00})}, varops::CompareZeroCost(2), SCRIPT_ERR_VERIFY);

    CheckEval(OneOp(OP_NOT), {Bytes({0x00, 0x00})}, {Bytes({0x01})}, varops::CompareZeroCost(2));
    CheckEval(OneOp(OP_0NOTEQUAL), {Bytes({0x00, 0x01})}, {Bytes({0x01})}, varops::CompareZeroCost(2));
    CheckEval(OneOp(OP_NUMEQUAL), {Bytes({0x01}), Bytes({0x01, 0x00, 0x00})}, {Bytes({0x01})}, varops::ComparisonCost(1, 3));
    CheckEval(OneOp(OP_BOOLAND), {Bytes({0x01, 0x00}), Bytes({})}, {Bytes({})}, varops::BoolAndCost(2, 0));

    CheckEval(OneOp(OP_PICK), {Bytes("bottom"), Bytes("top"), Bytes({0x01, 0x00, 0x00})}, {Bytes("bottom"), Bytes("top"), Bytes("bottom")},
              varops::LengthConversionCost(3) + 6 * varops::COST_COPYING);
    CheckEval(OneOp(OP_ROLL), {Bytes("bottom"), Bytes("top"), Bytes({0x01, 0x00, 0x00})}, {Bytes("top"), Bytes("bottom")},
              varops::LengthConversionCost(3) + 1 * varops::COST_ROLL);
}

BOOST_AUTO_TEST_CASE(costed_legacy_ops_report_exact_semantic_failures)
{
    CheckError(OneOp(OP_EQUALVERIFY), {Bytes("ab"), Bytes("ac")},
               2 * varops::COST_FAST, SCRIPT_ERR_EQUALVERIFY);
    CheckError(OneOp(OP_NUMEQUALVERIFY), {Bytes({0x01}), Bytes({0x02})},
               varops::ComparisonCost(1, 1), SCRIPT_ERR_NUMEQUALVERIFY);

    CheckError(OneOp(OP_PICK), {Bytes("only"), Num(1)},
               varops::LengthConversionCost(1), SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckError(OneOp(OP_ROLL), {Bytes("only"), Bytes({0xff})},
               varops::LengthConversionCost(1), SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(locktime_sequence_operands_must_fit_transaction_fields)
{
    const CScript cltv_script{OneOp(OP_CHECKLOCKTIMEVERIFY)};
    const CScript csv_script{OneOp(OP_CHECKSEQUENCEVERIFY)};
    const valtype padded_uint32_max{Bytes({0xff, 0xff, 0xff, 0xff, 0x00})};
    const valtype padded_one{Bytes({0x01, 0x00, 0x00, 0x00, 0x00})};
    const valtype uint32_overflow{Bytes({0x00, 0x00, 0x00, 0x00, 0x01})};
    const valtype overflow_with_csv_disable_flag{Bytes({0x00, 0x00, 0x00, 0x80, 0x01})};

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(cltv_script, {padded_uint32_max},
                                                                     SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                                                     checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(checker.locktime_calls, 1);
        BOOST_CHECK_EQUAL(checker.last_locktime, 0xffffffff);
        BOOST_REQUIRE_EQUAL(outcome.stack.size(), 1);
        BOOST_CHECK(outcome.stack.back() == padded_uint32_max);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(cltv_script, {uint32_overflow},
                                                                     SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                                                     checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(checker.locktime_calls, 0);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(csv_script, {padded_one},
                                                                     SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                                                                     checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(checker.sequence_calls, 1);
        BOOST_CHECK_EQUAL(checker.last_sequence, 1);
        BOOST_REQUIRE_EQUAL(outcome.stack.size(), 1);
        BOOST_CHECK(outcome.stack.back() == padded_one);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(csv_script, {uint32_overflow},
                                                                     SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                                                                     checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(checker.sequence_calls, 0);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(csv_script, {overflow_with_csv_disable_flag},
                                                                     SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                                                                     checker, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(checker.sequence_calls, 0);
    }
}

BOOST_AUTO_TEST_CASE(hash_opcodes_follow_bip441_limits)
{
    const valtype large(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x42);
    const valtype maximum(MAX_SCRIPT_ELEMENT_SIZE, 0x42);

    CheckError(OneOp(OP_SHA1), {large}, 0, SCRIPT_ERR_HASH_OPERAND_SIZE);
    CheckError(OneOp(OP_RIPEMD160), {large}, 0, SCRIPT_ERR_HASH_OPERAND_SIZE);

    for (const opcodetype opcode : {OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256}) {
        const size_t digest_size{opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 ? 20U : 32U};
        const uint64_t hash_cost{InitialLifetimeCost({maximum}) + varops::FixedOpcodeCost() + varops::HashCost(opcode, maximum.size()) +
                                 varops::CopyCost(digest_size)};
        const EvalOutcome outcome{EvalTapscriptV2(OneOp(opcode), {maximum}, hash_cost)};
        BOOST_REQUIRE(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
        BOOST_REQUIRE_EQUAL(outcome.stack.size(), 1);
        BOOST_CHECK_EQUAL(outcome.stack[0].size(), digest_size);
        CheckError(OneOp(opcode), {maximum}, hash_cost - varops::FixedOpcodeCost() - 1,
                   SCRIPT_ERR_VAROP_COUNT);
    }

    const uint64_t sha256_cost{InitialLifetimeCost({large}) + varops::FixedOpcodeCost() + varops::HashCost(OP_SHA256, large.size()) +
                               varops::CopyCost(32)};
    const EvalOutcome sha256_out{EvalTapscriptV2(OneOp(OP_SHA256), {large}, sha256_cost)};
    BOOST_REQUIRE(sha256_out.ok);
    BOOST_CHECK_EQUAL(sha256_out.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(sha256_out.remaining_budget, 0);
    BOOST_REQUIRE_EQUAL(sha256_out.stack.size(), 1);
    BOOST_CHECK_EQUAL(sha256_out.stack[0].size(), 32);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_stack_limits_are_enforced)
{
    Stack max_count_stack(MAX_TAPSCRIPT_V2_STACK_SIZE, Bytes({}));
    CheckEval(OneOp(OP_NOP), max_count_stack, max_count_stack, 0);
    CheckError(OneOp(OP_1), max_count_stack, 0, SCRIPT_ERR_STACK_SIZE);
    CheckError(OneOp(OP_DUP), max_count_stack, 0, SCRIPT_ERR_STACK_SIZE);
    CheckError(OneOp(OP_DEPTH), max_count_stack, 0, SCRIPT_ERR_STACK_SIZE);

    Stack one_below_max_count(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, Bytes({}));
    CheckError(OneOp(OP_2DUP), one_below_max_count, 0, SCRIPT_ERR_STACK_SIZE);
    CheckError(OneOp(OP_2OVER), one_below_max_count, 0, SCRIPT_ERR_STACK_SIZE);

    Stack two_below_max_count(MAX_TAPSCRIPT_V2_STACK_SIZE - 2, Bytes({}));
    CheckError(OneOp(OP_3DUP), two_below_max_count, 0, SCRIPT_ERR_STACK_SIZE);

    const EvalOutcome one_below_depth{EvalTapscriptV2(OneOp(OP_DEPTH), one_below_max_count,
                                                      InitialLifetimeCost(one_below_max_count) + varops::FixedOpcodeCost() + varops::ScalarOutputCost())};
    BOOST_REQUIRE(one_below_depth.ok);
    BOOST_CHECK_EQUAL(one_below_depth.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(one_below_depth.remaining_budget, 0);
    BOOST_REQUIRE_EQUAL(one_below_depth.stack.size(), MAX_TAPSCRIPT_V2_STACK_SIZE);
    BOOST_CHECK(one_below_depth.stack.back() == Bytes({0xff, 0x7f}));

    Stack max_count_true_top(MAX_TAPSCRIPT_V2_STACK_SIZE, Bytes({}));
    max_count_true_top.back() = Bytes({0x01});
    CheckError(OneOp(OP_IFDUP), max_count_true_top,
               varops::CompareZeroCost(1) + varops::COST_COPYING,
               SCRIPT_ERR_STACK_SIZE);

    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CheckEval(OneOp(OP_NOP), {max_element}, {max_element}, 0);

    const EvalOutcome max_element_size{EvalTapscriptV2(OneOp(OP_SIZE), {max_element},
                                                       InitialLifetimeCost({max_element}) + varops::FixedOpcodeCost() + varops::ScalarOutputCost())};
    BOOST_REQUIRE(max_element_size.ok);
    BOOST_CHECK_EQUAL(max_element_size.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(max_element_size.remaining_budget, 0);
    BOOST_REQUIRE_EQUAL(max_element_size.stack.size(), 2);
    BOOST_CHECK(max_element_size.stack.back() == Bytes({0x00, 0x09, 0x3d}));

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CheckError(OneOp(OP_NOP), {too_large_element}, 0, SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype four_mb(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x02);
    CheckEval(OneOp(OP_NOP), {four_mb, four_mb}, {four_mb, four_mb}, 0);
    CheckError(OneOp(OP_NOP), {four_mb, four_mb, Bytes({0x01})}, 0, SCRIPT_ERR_TOTAL_STACK_SIZE);
    CheckEval(OneOp(OP_DUP), {four_mb}, {four_mb, four_mb}, four_mb.size() * varops::COST_COPYING);
    CheckError(OneOp(OP_DUP), {Bytes({0x01}), four_mb}, four_mb.size() * varops::COST_COPYING,
               SCRIPT_ERR_TOTAL_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(copying_opcodes_enforce_total_stack_size_with_altstack)
{
    constexpr uint64_t budget{250'000'000};
    const valtype one_byte(1, 0x01);
    const valtype almost_max(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1, 0x01);
    const valtype almost_max_minus_one(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 2, 0x01);
    const valtype almost_max_minus_two(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 3, 0x01);

    const auto check_boundary = [&](opcodetype opcode, const Stack& main_stack,
                                    size_t success_altstack_size, size_t failure_altstack_size) {
        CScript script;
        script << OP_TOALTSTACK << opcode;

        const auto evaluate = [&](size_t altstack_size) {
            Stack initial_stack{main_stack};
            initial_stack.emplace_back(altstack_size, 0x01);
            return EvalTapscriptV2(script, initial_stack, budget);
        };

        BOOST_TEST_CONTEXT("opcode " << static_cast<int>(opcode)) {
            const EvalOutcome success{evaluate(success_altstack_size)};
            BOOST_CHECK(success.ok);
            BOOST_CHECK_EQUAL(success.error, SCRIPT_ERR_OK);

            const EvalOutcome failure{evaluate(failure_altstack_size)};
            BOOST_CHECK(!failure.ok);
            BOOST_CHECK_EQUAL(failure.error, SCRIPT_ERR_TOTAL_STACK_SIZE);
        }
    };

    // Each successful execution ends with exactly 8,000,000 bytes across the
    // main and alt stacks. Increasing only the altstack element by one byte
    // makes the same opcode fail at 8,000,001 bytes.
    check_boundary(OP_2DUP, {one_byte, almost_max_minus_one}, 2, 3);
    check_boundary(OP_3DUP, {one_byte, one_byte, almost_max_minus_two}, 2, 3);
    check_boundary(OP_2OVER, {one_byte, almost_max_minus_one, Bytes({}), Bytes({})}, 2, 3);
    check_boundary(OP_IFDUP, {almost_max}, 2, 3);
    check_boundary(OP_DUP, {almost_max}, 2, 3);
    check_boundary(OP_OVER, {almost_max, one_byte}, 1, 2);
    check_boundary(OP_TUCK, {one_byte, almost_max}, 1, 2);
    check_boundary(OP_PICK, {almost_max, one_byte, Num(1)}, 1, 2);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_witness_initial_stack_limits_are_enforced)
{
    CScript true_script;
    true_script << OP_1;

    Stack too_many_stack(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    EvalOutcome outcome{VerifyTapscriptV2(true_script, too_many_stack, 1'000)};
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_STACK_SIZE);

    CScript nop_true_script;
    nop_true_script << OP_NOP << OP_1;
    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    outcome = VerifyTapscriptV2(nop_true_script, {too_large_element}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype four_mb(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    outcome = VerifyTapscriptV2(nop_true_script, {four_mb, four_mb, Bytes({0x01})}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_TOTAL_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_pushes_use_the_expanded_stack_element_limit)
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
    outcome = VerifyTapscriptV2(too_large_push, {}, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_skipped_branches_validate_pushes)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_skipped_push;
    max_skipped_push << OP_0 << OP_IF << max_element << OP_ENDIF;
    CheckEval(max_skipped_push, {}, {}, 0, 3);

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript oversized_skipped_push;
    oversized_skipped_push << OP_0 << OP_IF << too_large_element << OP_ENDIF;
    CheckError(oversized_skipped_push, {}, 0, SCRIPT_ERR_PUSH_SIZE);

    CScript truncated_skipped_push;
    truncated_skipped_push << OP_0 << OP_IF;
    truncated_skipped_push.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
    CheckError(truncated_skipped_push, {}, 0, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(restored_ops_enforce_stack_element_limit_edges)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    const valtype half_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / 2, 0x01);

    CheckEval(OneOp(OP_CAT), {half_element, half_element}, {max_element},
              MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE * varops::COST_COPYING);

    CheckError(OneOp(OP_CAT), {max_element, Bytes({0x01})},
               (max_element.size() + 1) * varops::COST_COPYING,
               SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype one_byte_below_max(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1, 0x01);
    valtype byte_shifted_to_max(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    byte_shifted_to_max.front() = 0x00;
    CheckEval(OneOp(OP_LSHIFT), {one_byte_below_max, Num(8)}, {byte_shifted_to_max},
              varops::LengthConversionCost(1) + varops::COST_FAST +
                  one_byte_below_max.size() * varops::COST_COPYING);

    CheckError(OneOp(OP_LSHIFT), {max_element, Num(1)}, 0, SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype max_ff_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0xff);
    CheckError(OneOp(OP_1ADD), {max_ff_element}, varops::AddCost(max_ff_element.size(), 1),
               SCRIPT_ERR_STACK_ELEMENT_SIZE);
    CheckError(OneOp(OP_2MUL), {max_ff_element}, varops::TwoMulCost(max_ff_element.size()),
               SCRIPT_ERR_STACK_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_CASE(varops_budget_must_cover_exact_bip_cost)
{
    CheckEval(OneOp(OP_CAT), {Bytes("a"), Bytes("b")}, {Bytes("ab")}, 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_CAT), {Bytes("a"), Bytes("b")}, 2 * varops::COST_COPYING - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_MUL), {Bytes({0xff}), Bytes({0xff})}, {Bytes({0x01, 0xfe})}, varops::MulCost(1, 1));
    CheckError(OneOp(OP_MUL), {Bytes({0xff}), Bytes({0xff})}, varops::MulCost(1, 1) - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_DIV), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x7b})}, varops::DivCost(2, 1));
    CheckError(OneOp(OP_DIV), {Bytes({0x39, 0x30}), Bytes({0x64})}, varops::DivCost(2, 1) - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_MOD), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x2d})}, varops::ModCost(2, 1));
    CheckError(OneOp(OP_MOD), {Bytes({0x39, 0x30}), Bytes({0x64})}, varops::ModCost(2, 1) - 1, SCRIPT_ERR_VAROP_COUNT);
    CheckError(OneOp(OP_MOD), {Bytes({0x01}), Bytes({})}, varops::ModCost(1, 0) - 1, SCRIPT_ERR_VAROP_COUNT);

    const valtype empty_sig{};
    const valtype nonempty_sig{Bytes({0x01})};
    const valtype nonminimal_one{Bytes({0x01, 0x00})};
    const valtype xonly_pubkey(32, 0x02);
    const valtype unknown_pubkey(33, 0x02);
    const uint64_t empty_checksigadd_cost{varops::ChecksigAddIncrementCost(nonminimal_one.size())};
    CheckEval(OneOp(OP_CHECKSIGADD), {empty_sig, nonminimal_one, xonly_pubkey}, {Bytes({0x01})}, empty_checksigadd_cost);
    CheckError(OneOp(OP_CHECKSIGADD), {empty_sig, nonminimal_one, xonly_pubkey}, empty_checksigadd_cost - 1, SCRIPT_ERR_VAROP_COUNT);

    const uint64_t nonempty_checksigadd_cost{
        varops::SigcheckCost(OP_CHECKSIGADD) +
        varops::ChecksigAddIncrementCost(nonminimal_one.size())};
    CheckEval(OneOp(OP_CHECKSIGADD), {nonempty_sig, nonminimal_one, unknown_pubkey}, {Bytes({0x02})}, nonempty_checksigadd_cost);
    CheckError(OneOp(OP_CHECKSIGADD), {nonempty_sig, nonminimal_one, unknown_pubkey}, nonempty_checksigadd_cost - 1, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(signature_varops_charge_depends_on_nonempty_signature)
{
    const valtype empty_sig{};
    const valtype nonempty_sig{Bytes({0x01})};
    const valtype zero{};
    const valtype xonly_pubkey(32, 0x02);
    const valtype unknown_pubkey(33, 0x02);

    CScript empty_checksig_script;
    empty_checksig_script << xonly_pubkey << OP_CHECKSIG << OP_NOT;
    const uint64_t empty_checksig_cost{SuccessfulWitnessAdditionalCost(empty_checksig_script, {empty_sig})};
    EvalOutcome outcome{VerifyTapscriptV2(empty_checksig_script, {empty_sig}, empty_checksig_cost)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript nonempty_checksig_script;
    nonempty_checksig_script << unknown_pubkey << OP_CHECKSIG;
    const uint64_t nonempty_checksig_cost{SuccessfulWitnessAdditionalCost(nonempty_checksig_script, {nonempty_sig})};
    outcome = VerifyTapscriptV2(nonempty_checksig_script, {nonempty_sig},
                                nonempty_checksig_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(nonempty_checksig_script, {nonempty_sig},
                                nonempty_checksig_cost);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript empty_checksigverify_script;
    empty_checksigverify_script << xonly_pubkey << OP_CHECKSIGVERIFY << OP_1;
    outcome = VerifyTapscriptV2(empty_checksigverify_script, {empty_sig}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_CHECKSIGVERIFY);

    CScript nonempty_checksigverify_script;
    nonempty_checksigverify_script << unknown_pubkey << OP_CHECKSIGVERIFY << OP_1;
    const uint64_t nonempty_checksigverify_cost{SuccessfulWitnessAdditionalCost(nonempty_checksigverify_script, {nonempty_sig})};
    outcome = VerifyTapscriptV2(nonempty_checksigverify_script, {nonempty_sig},
                                nonempty_checksigverify_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(nonempty_checksigverify_script, {nonempty_sig},
                                nonempty_checksigverify_cost);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript empty_checksigadd_script;
    empty_checksigadd_script << xonly_pubkey << OP_CHECKSIGADD << OP_NOT;

    const uint64_t checksigadd_cost{SuccessfulWitnessAdditionalCost(empty_checksigadd_script, {empty_sig, zero})};
    outcome = VerifyTapscriptV2(empty_checksigadd_script, {empty_sig, zero}, checksigadd_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(empty_checksigadd_script, {empty_sig, zero}, checksigadd_cost);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript nonempty_checksigadd_script;
    nonempty_checksigadd_script << unknown_pubkey << OP_CHECKSIGADD;
    const uint64_t nonempty_checksigadd_cost{SuccessfulWitnessAdditionalCost(nonempty_checksigadd_script, {nonempty_sig, zero})};
    outcome = VerifyTapscriptV2(nonempty_checksigadd_script, {nonempty_sig, zero}, nonempty_checksigadd_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(nonempty_checksigadd_script, {nonempty_sig, zero}, nonempty_checksigadd_cost);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
}

BOOST_AUTO_TEST_CASE(op_success_redefinitions_are_checked_before_execution)
{
    for (const opcodetype opcode : {OP_1NEGATE, OP_NEGATE, OP_ABS}) {
        CScript script;
        script << opcode << OP_RETURN;
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const std::optional<bool> result{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(result.has_value());
        BOOST_CHECK(*result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> discouraged{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(discouraged.has_value());
        BOOST_CHECK(!*discouraged);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

        CScript malformed_after;
        malformed_after << opcode;
        malformed_after.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> after_result{CheckTapscriptOpSuccess(malformed_after, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(after_result.has_value());
        BOOST_CHECK(*after_result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

        CScript malformed_before;
        malformed_before.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
        malformed_before << opcode;
        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> before_result{CheckTapscriptOpSuccess(malformed_before, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_CHECK(!before_result.has_value());
        const EvalOutcome before_outcome{VerifyTapscriptV2WithFlags(
            malformed_before, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0)};
        BOOST_CHECK(!before_outcome.ok);
        BOOST_CHECK_EQUAL(before_outcome.error, SCRIPT_ERR_BAD_OPCODE);
    }

    // OP_INTERNALKEY remains an OP_SUCCESS code point until it is specified for tapscript v2.
    for (const opcodetype opcode : {static_cast<opcodetype>(0xcb)}) {
        CScript script;
        script << opcode << OP_RETURN;
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const std::optional<bool> result{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(result.has_value());
        BOOST_CHECK(*result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> discouraged{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                                                       SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(discouraged.has_value());
        BOOST_CHECK(!*discouraged);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

        EvalOutcome outcome{VerifyTapscriptV2WithFlags(script, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0)};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    }

    EvalOutcome discouraged_witness{VerifyTapscriptV2WithFlags(OneOp(OP_1NEGATE), {},
                                                        TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                                                        0)};
    BOOST_CHECK(!discouraged_witness.ok);
    BOOST_CHECK_EQUAL(discouraged_witness.error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

    CScript unexecuted_success;
    unexecuted_success << OP_0 << OP_IF << OP_1NEGATE << OP_ENDIF << OP_RETURN;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const std::optional<bool> result{CheckTapscriptOpSuccess(unexecuted_success, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(*result);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    Stack too_many_stack(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    EvalOutcome outcome{VerifyTapscriptV2(OneOp(OP_1NEGATE), too_many_stack, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    outcome = VerifyTapscriptV2(OneOp(OP_1NEGATE), {too_large_element}, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype four_mb(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    outcome = VerifyTapscriptV2(OneOp(OP_1NEGATE), {four_mb, four_mb, Bytes({0x01})}, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(nop4_is_upgradable_nop_in_tapscript_v2)
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

BOOST_AUTO_TEST_CASE(tapscript_v2_treats_future_pubkeys_as_unknown_pubkey_type)
{
    constexpr unsigned char future_pubkey_prefix{0x01};
    valtype future_xonly_pubkey(33, 0x02);
    future_xonly_pubkey.front() = future_pubkey_prefix;
    const valtype invalid_signature(64, 0x01);
    const script_verify_flags flags{TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS};
    for (const valtype& pubkey : {Bytes({future_pubkey_prefix}), future_xonly_pubkey}) {
        CScript script;
        script << pubkey << OP_CHECKSIG;

        EvalOutcome outcome{VerifyTapscriptV2WithFlags(script, {invalid_signature}, flags, AMPLE_VAROPS_BUDGET)};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

        outcome = VerifyTapscriptV2WithFlags(script, {invalid_signature},
                                             flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                                             AMPLE_VAROPS_BUDGET);
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
    }
}

BOOST_AUTO_TEST_CASE(tapscript_v2_conditionals_require_minimal_inputs)
{
    CScript if_script;
    if_script << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    CheckEval(if_script, {Bytes({0x01})}, {Bytes({0x02})}, 0, 4);
    CheckEval(if_script, {Bytes({})}, {Bytes({0x03})}, 0, 4);
    CheckError(if_script, {Bytes({0x02})}, 0, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
    CheckError(if_script, {Bytes({0x00, 0x00})}, 0, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);

    CScript notif_script;
    notif_script << OP_NOTIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    CheckEval(notif_script, {Bytes({})}, {Bytes({0x02})}, 0, 4);
    CheckEval(notif_script, {Bytes({0x01})}, {Bytes({0x03})}, 0, 4);
}

BOOST_AUTO_TEST_CASE(unexecuted_branches_do_not_charge_or_execute_costed_ops)
{
    CScript skipped_then_else;
    skipped_then_else << OP_0 << OP_IF << OP_CAT << OP_MUL << OP_SHA256 << OP_ELSE << OP_2 << OP_ENDIF;
    CheckEval(skipped_then_else, {}, {Bytes({0x02})}, 0, 5);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_standard_verify_uses_unmetered_overload)
{
    CScript normal_script;
    normal_script << OP_1;

    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(normal_script, {}, script_pub_key)};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error)};
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(checksigfromstack)
{
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
    const auto signature_cost = [](size_t message_size) {
        return varops::Sha256Cost(message_size) + varops::Sha256Cost(96) +
               varops::SignatureCost() + varops::ScalarOutputCost();
    };
    const uint64_t sigcheck_cost{signature_cost(message.size())};

    CheckEval(script, {sig, message, pubkey}, {Bytes({0x01})}, sigcheck_cost);

    valtype wrong_message{message};
    wrong_message.front() ^= 1;
    CheckError(script, {sig, wrong_message, pubkey}, sigcheck_cost, SCRIPT_ERR_SCHNORR_SIG);
    CheckError(script, {valtype(63, 0x01), message, pubkey}, sigcheck_cost, SCRIPT_ERR_SCHNORR_SIG_SIZE);
    CheckEval(script, {{}, message, pubkey}, {{}}, 0);
    CheckError(script, {{}, message, {}}, 0, SCRIPT_ERR_PUBKEYTYPE);
    CheckError(script, {sig, message}, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);

    const valtype unknown_pubkey(33, 0x02);
    CheckEval(script, {sig, message, unknown_pubkey}, {Bytes({0x01})}, sigcheck_cost);
    const EvalOutcome discouraged{EvalTapscriptV2WithFlagsAndChecker(
        script, {sig, message, unknown_pubkey}, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
        BaseSignatureChecker{}, AMPLE_VAROPS_BUDGET)};
    BOOST_CHECK(!discouraged.ok);
    BOOST_CHECK_EQUAL(discouraged.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);

    CheckError(script, {sig, message, pubkey}, sigcheck_cost - 1, SCRIPT_ERR_VAROP_COUNT);

    const valtype long_message(4096, 0x42);
    const uint64_t long_message_cost{signature_cost(long_message.size())};
    CheckError(script, {sig, long_message, pubkey}, long_message_cost - 1, SCRIPT_ERR_VAROP_COUNT);
    const EvalOutcome invalid_long_message{EvalTapscriptV2(
        script, {sig, long_message, pubkey}, InitialLifetimeCost({sig, long_message, pubkey}) + varops::FixedOpcodeCost() + long_message_cost)};
    BOOST_CHECK(!invalid_long_message.ok);
    BOOST_CHECK_EQUAL(invalid_long_message.error, SCRIPT_ERR_SCHNORR_SIG);
    BOOST_CHECK_EQUAL(invalid_long_message.remaining_budget, 0);
    CheckEval(script, {sig, long_message, unknown_pubkey}, {Bytes({0x01})}, long_message_cost);
    CheckEval(script, {{}, long_message, pubkey}, {{}}, 0);
}

BOOST_AUTO_TEST_CASE(tweakadd)
{
    const CScript script{OneOp(OP_TWEAKADD)};
    struct TestVector {
        std::string_view pubkey;
        std::string_view tweak;
        std::string_view expected;
    };
    const auto vectors = std::to_array<TestVector>({
        {
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        },
        {
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        },
        {
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        },
        {
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        },
        {
            "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
            "0000000000000000000000000000000000000000000000000000000000000009",
            "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
        },
        {
            "d415b187c6e7ce9da46ac888d20df20737d6f16a41639e68ea055311e1535dd9",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "c6713b2ac2495d1a879dc136abc06129a7bf355da486cd25f757e0a5f6f40f74",
        },
    });
    const uint64_t tweak_cost{varops::TweakCost() + varops::CopyCost(32)};

    for (const auto& vector : vectors) {
        CheckEval(script, {HexBytes(vector.tweak), HexBytes(vector.pubkey)}, {HexBytes(vector.expected)}, tweak_cost);
    }

    const valtype generator{HexBytes(vectors[0].pubkey)};
    const valtype zero_tweak{HexBytes(vectors[0].tweak)};
    const valtype one_tweak{HexBytes(vectors[1].tweak)};
    const valtype two_g{HexBytes(vectors[1].expected)};
    const valtype curve_order{HexBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};
    const valtype curve_order_minus_one{HexBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")};

    CheckEval(script, {Bytes({0xaa}), one_tweak, generator}, {Bytes({0xaa}), two_g}, tweak_cost);
    CheckError(script, {}, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckError(script, {one_tweak}, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckError(script, {valtype(31), generator}, 0, SCRIPT_ERR_TWEAKADD);
    CheckError(script, {zero_tweak, valtype(31)}, 0, SCRIPT_ERR_TWEAKADD);
    CheckError(script, {curve_order, generator}, tweak_cost, SCRIPT_ERR_TWEAKADD);
    CheckError(script, {one_tweak, valtype(32)}, tweak_cost, SCRIPT_ERR_TWEAKADD);
    CheckError(script, {curve_order_minus_one, generator}, tweak_cost, SCRIPT_ERR_TWEAKADD);
    CheckError(script, {curve_order, generator}, tweak_cost - 1, SCRIPT_ERR_VAROP_COUNT);
    CheckError(script, {one_tweak, generator}, tweak_cost - 1, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(byterev)
{
    const CScript script{OneOp(OP_BYTEREV)};
    const valtype value{Bytes({0x00, 0x01, 0x02, 0x80, 0xff, 0x00, 0x42, 0x7f, 0x03})};
    const valtype reversed{value.rbegin(), value.rend()};
    const uint64_t cost{varops::ByteReverseCost(value.size())};

    CheckEval(script, {value}, {reversed}, cost);
    CheckEval(script, {{}}, {{}}, 0);
    CheckEval(script, {Bytes({0x42})}, {Bytes({0x42})}, varops::ByteReverseCost(1));
    CheckError(script, {}, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckError(script, {value}, cost - 1, SCRIPT_ERR_VAROP_COUNT);

    CScript involution;
    involution << OP_BYTEREV << OP_BYTEREV;
    CheckEval(involution, {value}, {value}, 2 * cost);

    // TapBranch orders its fixed-size child hashes lexicographically. Reversing
    // them makes restored little-endian numeric comparison produce that order.
    valtype lower(32, 0x00);
    valtype higher(32, 0x00);
    lower.front() = 0x01;
    higher.front() = 0x02;
    CScript tapbranch_order;
    tapbranch_order << OP_SWAP << OP_BYTEREV << OP_SWAP << OP_BYTEREV << OP_LESSTHAN;
    const uint64_t ordering_cost{2 * varops::ByteReverseCost(32) + varops::ComparisonCost(32, 32)};
    CheckEval(tapbranch_order, {lower, higher}, {Bytes({0x01})}, ordering_cost);
    CheckEval(tapbranch_order, {higher, lower}, {{}}, ordering_cost);
}

BOOST_AUTO_TEST_CASE(taproot_script_signing_propagates_leaf_sigversion)
{
    const CScript leaf_script{CScript{} << ToByteVector(XOnlyPubKey::NUMS_H) << OP_CHECKSIG};

    for (const auto& [leaf_version, expected_sigversion] : {
             std::pair{int{TAPROOT_LEAF_TAPSCRIPT}, SigVersion::TAPSCRIPT},
             std::pair{int{TAPROOT_LEAF_TAPSCRIPT_V2}, SigVersion::TAPSCRIPT_V2},
         }) {
        TaprootBuilder builder;
        builder.Add(0, leaf_script, leaf_version, /*track=*/true);
        builder.Finalize(XOnlyPubKey::NUMS_H);

        const WitnessV1Taproot output{builder.GetOutput()};
        FlatSigningProvider provider;
        provider.tr_trees.emplace(output, builder);

        RecordingSignatureCreator creator;
        SignatureData sigdata;
        BOOST_REQUIRE(ProduceSignature(provider, creator, GetScriptForDestination(output), sigdata));
        BOOST_REQUIRE(!creator.schnorr_sigversions.empty());
        for (const SigVersion sigversion : creator.schnorr_sigversions) {
            BOOST_CHECK(sigversion == expected_sigversion);
        }
    }
}

BOOST_AUTO_TEST_CASE(tapscript_v2_psbt_finalized_witness_is_signed_and_verified)
{
    CScript normal_script;
    normal_script << OP_1;
    FinalizedTapscriptV2Spend spend{BuildFinalizedTapscriptV2Spend(normal_script, {})};

    CMutableTransaction unsigned_tx{spend.tx};
    unsigned_tx.vin[0].scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spend.spent_output;
    psbt.inputs[0].final_script_witness = spend.tx.vin[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{spend.tx}, std::vector<CTxOut>{spend.spent_output});

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(PSBTInputsSignedAndVerified(psbt, txdata));
    BOOST_CHECK(FinalizePSBT(psbt));
}

BOOST_AUTO_TEST_CASE(tapscript_v2_psbt_and_signtransaction_use_transaction_wide_varops_budget)
{
    const size_t operand_size{40'000};
    const valtype operand(operand_size, 0xff);

    CScript costly_script;
    costly_script << OP_MUL << OP_DROP << OP_1;

    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(costly_script, {operand, operand}, script_pub_key)};
    const CTxOut spent_output{100'000'000, script_pub_key};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1});
    tx.vin[0].scriptWitness = witness;
    tx.vin[1].scriptWitness = witness;
    tx.vout.emplace_back(50'000, CScript{} << OP_TRUE);

    const CTransaction tx_const{tx};
    // The BIP441 multiply/accumulate core alone is enough to cross the shared budget twice.
    const uint64_t limbs{varops::detail::WordSize(operand_size) / 8};
    const uint64_t per_input_cost{limbs * (varops::MulRowCost(limbs) + varops::ArithCost(8 * (limbs + 1)))};
    const uint64_t tx_budget{varops::TxBudget(GetTransactionWeight(tx_const))};
    BOOST_REQUIRE_LT(per_input_cost, tx_budget);
    BOOST_REQUIRE_LT(tx_budget, 2 * per_input_cost);

    // Final witnesses are stored in the PSBT inputs, not its unsigned transaction.
    CMutableTransaction unsigned_tx{tx};
    for (CTxIn& in : unsigned_tx.vin) in.scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    for (size_t i{0}; i < psbt.inputs.size(); ++i) {
        psbt.inputs[i].witness_utxo = spent_output;
        psbt.inputs[i].final_script_witness = tx.vin[i].scriptWitness;
    }

    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, std::vector<CTxOut>{spent_output, spent_output});

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 1, &txdata));
    BOOST_CHECK(!PSBTInputsSignedAndVerified(psbt, txdata));
    BOOST_CHECK(!FinalizePSBT(psbt));

    std::map<COutPoint, Coin> coins;
    coins.emplace(tx.vin[0].prevout, Coin{spent_output, 1, /*fCoinBaseIn=*/false});
    coins.emplace(tx.vin[1].prevout, Coin{spent_output, 1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(tx, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1);
    BOOST_CHECK_EQUAL(input_errors.begin()->second.original, ScriptErrorString(SCRIPT_ERR_VAROP_COUNT));
}

BOOST_AUTO_TEST_CASE(tapscript_v2_psbt_single_input_over_finalized_budget_is_rejected)
{
    const size_t operand_size{40'000};
    const valtype operand(operand_size, 0xff);

    CScript costly_script;
    costly_script << OP_MUL << OP_DROP << OP_1;

    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(costly_script, {operand, operand}, script_pub_key)};
    const CTxOut spent_output{100'000'000, script_pub_key};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin[0].scriptWitness = witness;
    tx.vout.emplace_back(50'000, CScript{} << OP_TRUE);

    const uint64_t limbs{varops::detail::WordSize(operand_size) / 8};
    const uint64_t input_cost{limbs * (varops::MulRowCost(limbs) + varops::ArithCost(8 * (limbs + 1)))};
    const uint64_t finalized_budget{varops::TxBudget(GetTransactionWeight(CTransaction{tx}))};
    BOOST_REQUIRE_GT(input_cost, finalized_budget);

    CMutableTransaction unsigned_tx{tx};
    for (CTxIn& in : unsigned_tx.vin) in.scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spent_output;
    psbt.inputs[0].final_script_witness = tx.vin[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{tx}, std::vector<CTxOut>{spent_output});

    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(!PSBTInputsSignedAndVerified(psbt, txdata));
    BOOST_CHECK(!FinalizePSBT(psbt));
}

BOOST_AUTO_TEST_CASE(tapscript_v2_signtransaction_accepts_finalized_witness)
{
    CScript normal_script;
    normal_script << OP_1;
    FinalizedTapscriptV2Spend spend{BuildFinalizedTapscriptV2Spend(normal_script, {})};

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend.tx.vin[0].prevout, Coin{spend.spent_output, 1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(spend.tx, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(input_errors.empty());
}

BOOST_AUTO_TEST_CASE(witness_path_uses_tapscript_v2_final_success_rule)
{
    CScript negative_zero_like;
    negative_zero_like << Bytes({0x80});
    const uint64_t success_cost{SuccessfulWitnessAdditionalCost(negative_zero_like, {})};
    EvalOutcome outcome{VerifyTapscriptV2(negative_zero_like, {}, success_cost)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2(negative_zero_like, {}, success_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    CScript false_result;
    false_result << Bytes({});
    outcome = VerifyTapscriptV2(false_result, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_EVAL_FALSE);

    CScript all_zero_result;
    all_zero_result << Bytes({0x00, 0x00});
    outcome = VerifyTapscriptV2(all_zero_result, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_EVAL_FALSE);

    CScript high_byte_nonzero_result;
    high_byte_nonzero_result << Bytes({0x00, 0x01});
    outcome = VerifyTapscriptV2(high_byte_nonzero_result, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    CScript dirty_stack;
    dirty_stack << OP_1 << OP_1;
    outcome = VerifyTapscriptV2(dirty_stack, {}, AMPLE_VAROPS_BUDGET);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_CLEANSTACK);
}

BOOST_AUTO_TEST_SUITE_END()
