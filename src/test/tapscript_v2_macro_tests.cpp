// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Conformance with the reusable macros draft: static decoding, unrolling
// totals and the unrolled size limit, equivalence with the unrolled script,
// opcode positions in the unrolled script, and the charge relation
//     charge(committed script) = charge(unrolled script)
//                                + F * (substituted instructions + references visited).

#include <crypto/sha256.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/data/tapscript_v2_macros.json.h>
#include <test/util/setup_common.h>
#include <test/util/tapscript_v2_test_utils.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace test::tapscript_v2;

namespace {

constexpr uint64_t BUDGET{1'000'000'000'000};
constexpr uint32_t NO_CODESEPARATOR{0xFFFFFFFF};

struct Execution {
    bool ok{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t charge{0};
    Stack stack;
    uint32_t codeseparator_pos{NO_CODESEPARATOR};
    //! The script transaction introspection sees, if execution began.
    std::optional<CScript> tapscript;
};

Execution Execute(const CScript& script, const Stack& initial_stack, uint64_t budget = BUDGET)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    varops::Budget varops_budget{budget};
    ValtypeStack stack{initial_stack};
    Execution execution;
    execution.ok = EvalTapscriptV2(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, varops_budget, &execution.error);
    execution.charge = budget - *varops_budget.Remaining();
    execution.stack = stack.GetStack();
    if (execdata.m_codeseparator_pos_init) execution.codeseparator_pos = execdata.m_codeseparator_pos;
    if (execdata.m_tapscript_init) execution.tapscript = CScript(execdata.m_tapscript.begin(), execdata.m_tapscript.end());
    return execution;
}

CScript ScriptFromHex(std::string_view hex)
{
    const std::vector<unsigned char> bytes{ParseHex(hex)};
    return CScript{bytes.begin(), bytes.end()};
}

CScript ScriptFromJson(const UniValue& value)
{
    return ScriptFromHex(value.get_str());
}

UniValue ReadVectors()
{
    // The BIP vector file is an object with "decoding", "unrolling" and "execution" arrays.
    UniValue vectors;
    Assert(vectors.read(json_tests::tapscript_v2_macros) && vectors.isObject());
    return vectors;
}

Stack StackFromJson(const UniValue& array)
{
    Stack stack;
    for (const UniValue& item : array.getValues())
        stack.push_back(ParseHex(item.get_str()));
    return stack;
}

std::string Sha256Hex(const CScript& script)
{
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256{}.Write(script.data(), script.size()).Finalize(hash);
    return HexStr(hash);
}

ScriptError ErrorFromJson(const std::string& name)
{
    static const std::map<std::string, ScriptError> errors{
        {"unbalanced-conditional", SCRIPT_ERR_UNBALANCED_CONDITIONAL},
        {"bad-opcode", SCRIPT_ERR_BAD_OPCODE},
        {"minimalif", SCRIPT_ERR_TAPSCRIPT_MINIMALIF},
    };
    return errors.at(name);
}

void Define(CScript& script, const CScript& body)
{
    script << OP_MACRO;
    const uint64_t size{body.size()};
    if (size < 253) {
        script.push_back(size);
    } else {
        const unsigned int width{size <= 0xffff ? 2U : 4U};
        script.push_back(width == 2 ? 0xfd : 0xfe);
        for (unsigned int i{0}; i < width; ++i)
            script.push_back(size >> (8 * i));
    }
    script.insert(script.end(), body.begin(), body.end());
}

void Reference(CScript& script, uint64_t index)
{
    script << OP_CALLMACRO;
    script.push_back(index);
}

std::optional<bool> Decode(const CScript& script, script_verify_flags flags, ScriptError& error)
{
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    return CheckTapscriptOpSuccess(script, flags, SigVersion::TAPSCRIPT_V2, &error);
}

/**
 * Execute a well-formed committed script and its unrolled script. They must
 * agree on everything but the charge, which differs by exactly the unrolling
 * charge, and introspection must see the committed script.
 */
Execution CheckMatchesUnrolled(const CScript& script, const MacroDecoding& decoding, const Stack& initial_stack)
{
    BOOST_REQUIRE(decoding.result == MacroDecoding::Result::WELL_FORMED);
    BOOST_REQUIRE(decoding.WithinLimit());
    const Execution macro{Execute(script, initial_stack)};
    const Execution unrolled{Execute(decoding.unrolled, initial_stack)};
    BOOST_CHECK_EQUAL(macro.ok, unrolled.ok);
    BOOST_CHECK_EQUAL(macro.error, unrolled.error);
    BOOST_CHECK(macro.stack == unrolled.stack);
    BOOST_CHECK_EQUAL(macro.codeseparator_pos, unrolled.codeseparator_pos);
    BOOST_CHECK_EQUAL(macro.charge, unrolled.charge + decoding.UnrollCharge());
    BOOST_CHECK(macro.tapscript == script);
    return macro;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(tapscript_v2_macro_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(decoding_vectors)
{
    const UniValue vectors{ReadVectors()};
    for (const UniValue& vector : vectors["decoding"].getValues()) {
        const std::string comment{vector["comment"].get_str()};
        const std::string result{vector["result"].get_str()};
        const CScript script{ScriptFromJson(vector["script"])};
        BOOST_TEST_CONTEXT(comment)
        {
            ScriptError error;
            const std::optional<bool> decoded{Decode(script, SCRIPT_VERIFY_NONE, error)};
            const MacroDecoding test_decoding{DecodeMacros(script)};
            if (result == "well-formed") {
                BOOST_CHECK(!decoded.has_value());
                BOOST_CHECK(test_decoding.result == MacroDecoding::Result::WELL_FORMED);
                BOOST_CHECK_EQUAL(test_decoding.declarations, vector["declarations"].getInt<uint64_t>());
                // The unrolled script has no declarations or references.
                const MacroDecoding redecoded{DecodeMacros(test_decoding.unrolled)};
                BOOST_CHECK(redecoded.result == MacroDecoding::Result::WELL_FORMED);
                BOOST_CHECK_EQUAL(redecoded.declarations, 0);
                BOOST_CHECK_EQUAL(redecoded.references_visited, 0);
                CheckMatchesUnrolled(script, test_decoding, {});
            } else if (result == "success") {
                BOOST_CHECK(decoded == std::optional<bool>{true});
                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
                BOOST_CHECK(test_decoding.result == MacroDecoding::Result::SUCCESS);
                BOOST_CHECK(Decode(script, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, error) == std::optional<bool>{false});
                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
                // Execution reports the static result too, without unrolling.
                const Execution execution{Execute(script, {})};
                BOOST_CHECK(execution.ok);
                BOOST_CHECK_EQUAL(execution.charge, 0);
            } else {
                BOOST_REQUIRE_EQUAL(result, "failure");
                BOOST_CHECK(decoded == std::optional<bool>{false});
                BOOST_CHECK_EQUAL(error, SCRIPT_ERR_BAD_OPCODE);
                BOOST_CHECK(test_decoding.result == MacroDecoding::Result::FAILURE);
                const Execution execution{Execute(script, {})};
                BOOST_CHECK(!execution.ok);
                BOOST_CHECK_EQUAL(execution.error, SCRIPT_ERR_BAD_OPCODE);
                BOOST_CHECK_EQUAL(execution.charge, 0);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(unrolling_vectors)
{
    const UniValue vectors{ReadVectors()};
    BOOST_REQUIRE_EQUAL(vectors["max_unrolled_size"].getInt<uint64_t>(), MAX_TAPSCRIPT_V2_UNROLLED_SIZE);
    for (const UniValue& vector : vectors["unrolling"].getValues()) {
        BOOST_TEST_CONTEXT(vector["comment"].get_str())
        {
            const CScript script{ScriptFromJson(vector["script"])};
            ScriptError error;
            BOOST_REQUIRE(!Decode(script, SCRIPT_VERIFY_NONE, error).has_value());
            const MacroDecoding decoding{DecodeMacros(script)};
            BOOST_CHECK_EQUAL(decoding.unrolled_length, vector["unrolled_length"].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(decoding.substituted_instructions, vector["substituted_instructions"].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(decoding.references_visited, vector["references_visited"].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(decoding.WithinLimit(), vector["within_limit"].get_bool());

            if (!vector["within_limit"].get_bool()) {
                // The size limit is checked before the unrolling charge, so it
                // decides even with no budget at all.
                for (const uint64_t budget : {BUDGET, uint64_t{0}}) {
                    const Execution execution{Execute(script, {}, budget)};
                    BOOST_CHECK(!execution.ok);
                    BOOST_CHECK_EQUAL(execution.error, SCRIPT_ERR_SCRIPT_SIZE);
                    BOOST_CHECK_EQUAL(execution.charge, 0);
                }
                continue;
            }
            BOOST_CHECK_EQUAL(decoding.unrolled.size(), decoding.unrolled_length);
            BOOST_CHECK_EQUAL(Sha256Hex(decoding.unrolled), vector["unrolled_sha256"].get_str());
            if (vector.exists("unrolled")) BOOST_CHECK(decoding.unrolled == ScriptFromJson(vector["unrolled"]));
            CheckMatchesUnrolled(script, decoding, {});
        }
    }
}

BOOST_AUTO_TEST_CASE(execution_vectors)
{
    const UniValue vectors{ReadVectors()};
    for (const UniValue& vector : vectors["execution"].getValues()) {
        BOOST_TEST_CONTEXT(vector["comment"].get_str())
        {
            const CScript script{ScriptFromJson(vector["script"])};
            const Stack initial_stack{StackFromJson(vector["initial_stack"])};
            const MacroDecoding decoding{DecodeMacros(script)};
            BOOST_CHECK(decoding.unrolled == ScriptFromJson(vector["unrolled"]));
            BOOST_CHECK_EQUAL(decoding.unrolled_length, vector["unrolled_length"].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(decoding.substituted_instructions, vector["substituted_instructions"].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(decoding.references_visited, vector["references_visited"].getInt<uint64_t>());

            const Execution macro{CheckMatchesUnrolled(script, decoding, initial_stack)};
            BOOST_CHECK_EQUAL(macro.ok, vector["ok"].get_bool());
            if (!vector["ok"].get_bool()) {
                BOOST_CHECK_EQUAL(macro.error, ErrorFromJson(vector["error"].get_str()));
                continue;
            }
            BOOST_CHECK(macro.stack == StackFromJson(vector["final_stack"]));
            const UniValue& position{vector["codeseparator_position"]};
            BOOST_CHECK_EQUAL(macro.codeseparator_pos,
                              position.isNull() ? NO_CODESEPARATOR : position.getInt<uint32_t>());
        }
    }
}

BOOST_AUTO_TEST_CASE(charge_boundaries)
{
    // Body 0 is two instructions, referenced once from an inactive branch:
    // the unrolling charge is F * (2 + 1) and the budget is exact.
    CScript script{ScriptFromHex("bb027675")};
    script << OP_0 << OP_IF;
    Reference(script, 0);
    script << OP_ENDIF << OP_1;
    const MacroDecoding decoding{DecodeMacros(script)};
    BOOST_CHECK_EQUAL(decoding.UnrollCharge(), 3 * varops::FixedOpcodeCost());
    const Execution macro{CheckMatchesUnrolled(script, decoding, {})};
    BOOST_REQUIRE(macro.ok);

    for (const uint64_t budget : {macro.charge, macro.charge - 1}) {
        const Execution execution{Execute(script, {}, budget)};
        BOOST_CHECK_EQUAL(execution.ok, budget == macro.charge);
        BOOST_CHECK_EQUAL(execution.error, budget == macro.charge ? SCRIPT_ERR_OK : SCRIPT_ERR_VAROP_COUNT);
    }

    // The unrolling charge is paid in full before any instruction executes.
    const Execution short_unroll{Execute(script, {}, decoding.UnrollCharge() - 1)};
    BOOST_CHECK(!short_unroll.ok);
    BOOST_CHECK_EQUAL(short_unroll.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK_EQUAL(short_unroll.charge, 0);
    BOOST_CHECK(!short_unroll.tapscript.has_value());
    const Execution exact_unroll{Execute(script, {}, decoding.UnrollCharge())};
    BOOST_CHECK(!exact_unroll.ok);
    BOOST_CHECK_EQUAL(exact_unroll.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK_EQUAL(exact_unroll.charge, decoding.UnrollCharge());
    BOOST_CHECK(exact_unroll.tapscript == script);
}

BOOST_AUTO_TEST_CASE(declarations_are_free)
{
    // Declaring bodies, referenced or not, adds no charge; only references do.
    CScript declared{ScriptFromHex("bb03767675bb0151")};
    declared << OP_1;
    BOOST_CHECK_EQUAL(Execute(declared, {}).charge, Execute(CScript{} << OP_1, {}).charge);
}

BOOST_AUTO_TEST_CASE(unrolling_charge_is_payload_independent)
{
    // A push costs one unit to unroll whatever its payload size.
    for (const size_t size : {0U, 1U, 520U, 100'000U}) {
        CScript body;
        body << std::vector<unsigned char>(size, 0x42);
        CScript script;
        Define(script, body);
        script << OP_0 << OP_IF;
        Reference(script, 0);
        script << OP_ENDIF << OP_1;
        BOOST_TEST_CONTEXT("push size " << size)
        {
            const MacroDecoding decoding{DecodeMacros(script)};
            BOOST_CHECK_EQUAL(decoding.UnrollCharge(), 2 * varops::FixedOpcodeCost());
            BOOST_CHECK(CheckMatchesUnrolled(script, decoding, {}).ok);
        }
    }
}

BOOST_AUTO_TEST_CASE(unrolled_size_limit)
{
    // Body 0 is a 4,000-byte push and body 1 references it 1,000 times, so a
    // reference to body 1 unrolls to exactly the limit.
    CScript script;
    Define(script, CScript{} << std::vector<unsigned char>(3'997, 0x42));
    CScript body;
    for (int i{0}; i < 1'000; ++i)
        Reference(body, 0);
    Define(script, body);
    Reference(script, 1);
    const MacroDecoding at_limit{DecodeMacros(script)};
    BOOST_REQUIRE_EQUAL(at_limit.unrolled_length, MAX_TAPSCRIPT_V2_UNROLLED_SIZE);
    // A stack of 1,000 elements fails the final-stack check, but the unrolled script runs.
    BOOST_CHECK_EQUAL(CheckMatchesUnrolled(script, at_limit, {}).stack.size(), 1'000U);

    // One more byte, even in an inactive branch, is over the limit.
    CScript over{script};
    over << OP_0 << OP_IF << OP_ENDIF;
    BOOST_REQUIRE_GT(DecodeMacros(over).unrolled_length, MAX_TAPSCRIPT_V2_UNROLLED_SIZE);
    const Execution execution{Execute(over, {})};
    BOOST_CHECK(!execution.ok);
    BOOST_CHECK_EQUAL(execution.error, SCRIPT_ERR_SCRIPT_SIZE);
    BOOST_CHECK_EQUAL(execution.charge, 0);

    // A static decoding failure is reported before the size limit.
    CScript malformed{over};
    malformed.push_back(OP_PUSHDATA1);
    BOOST_CHECK_EQUAL(Execute(malformed, {}).error, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(unrolling_totals_saturate)
{
    // Doubling 70 times would overflow 64-bit totals, which must saturate to
    // over the limit rather than wrap to a small length.
    const auto doubling{[](const CScript& leaf) {
        CScript script;
        Define(script, leaf);
        for (uint64_t i{0}; i < 70; ++i) {
            CScript body;
            Reference(body, i);
            Reference(body, i);
            Define(script, body);
        }
        Reference(script, 70);
        script << OP_1;
        return script;
    }};
    const Execution execution{Execute(doubling(CScript{} << OP_NOP), {})};
    BOOST_CHECK(!execution.ok);
    BOOST_CHECK_EQUAL(execution.error, SCRIPT_ERR_SCRIPT_SIZE);
    BOOST_CHECK_EQUAL(execution.charge, 0);

    // With an empty leaf the length stays zero, but the references alone
    // saturate the unrolling charge beyond any budget.
    const Execution empty_leaf{Execute(doubling(CScript{}), {}, std::numeric_limits<uint64_t>::max())};
    BOOST_CHECK(!empty_leaf.ok);
    BOOST_CHECK_EQUAL(empty_leaf.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK_EQUAL(empty_leaf.charge, 0);
}

BOOST_AUTO_TEST_CASE(op_tx_success_cannot_rescue_decoding_failure)
{
    // <01> OP_TX is a reserved selector, which succeeds immediately when executed.
    const CScript reserved{CScript{} << std::vector<unsigned char>{0x01} << OP_TX};
    const std::vector<std::vector<unsigned char>> tails{
        {OP_PUSHDATA1},       // truncated push
        {OP_CALLMACRO, 0x05}, // undeclared body
        {OP_MACRO, 0x00},     // declaration outside the prefix
    };
    for (const auto& tail : tails) {
        CScript script{reserved};
        script.insert(script.end(), tail.begin(), tail.end());
        const Execution execution{Execute(script, {})};
        BOOST_CHECK(!execution.ok);
        BOOST_CHECK_EQUAL(execution.error, SCRIPT_ERR_BAD_OPCODE);
    }

    // A self-reference in a body referenced after the reserved selector.
    CScript self_reference{ScriptFromHex("bb02bc00")};
    self_reference.insert(self_reference.end(), reserved.begin(), reserved.end());
    Reference(self_reference, 0);
    const Execution execution{Execute(self_reference, {})};
    BOOST_CHECK(!execution.ok);
    BOOST_CHECK_EQUAL(execution.error, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_SUITE_END()
