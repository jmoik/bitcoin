// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_TAPSCRIPT_V2_TEST_UTILS_H
#define BITCOIN_TEST_UTIL_TAPSCRIPT_V2_TEST_UTILS_H

#include <addresstype.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <util/check.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace test::tapscript_v2 {

using Stack = std::vector<std::vector<unsigned char>>;

inline constexpr script_verify_flags TAPROOT_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
inline constexpr script_verify_flags TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS{TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORATION};

struct EvalOutcome {
    bool ok{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t remaining_budget{0};
    Stack stack;
};

class RecordingChecker final : public BaseSignatureChecker
{
public:
    bool locktime_result{true};
    bool sequence_result{true};
    mutable int locktime_calls{0};
    mutable int sequence_calls{0};
    mutable int schnorr_calls{0};
    mutable int64_t last_locktime{-1};
    mutable int64_t last_sequence{-1};
    mutable SigVersion last_sigversion{SigVersion::BASE};
    mutable uint32_t last_codeseparator_pos{0};

    RecordingChecker() = default;
    RecordingChecker(bool locktime_result, bool sequence_result)
        : locktime_result{locktime_result}, sequence_result{sequence_result}
    {
    }

    bool CheckSchnorrSignature(std::span<const unsigned char>, std::span<const unsigned char>, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError*) const override
    {
        ++schnorr_calls;
        last_sigversion = sigversion;
        Assert(execdata.m_codeseparator_pos_init);
        last_codeseparator_pos = execdata.m_codeseparator_pos;
        return true;
    }

    bool CheckLockTime(const CScriptNum& locktime) const override
    {
        ++locktime_calls;
        last_locktime = locktime.GetInt64();
        return locktime_result;
    }

    bool CheckSequence(const CScriptNum& sequence) const override
    {
        ++sequence_calls;
        last_sequence = sequence.GetInt64();
        return sequence_result;
    }
};

inline CScript OneOp(opcodetype opcode)
{
    CScript script;
    script << opcode;
    return script;
}

inline CScriptWitness BuildTapscriptV2Witness(const CScript& leaf_script, const Stack& initial_stack, CScript& script_pub_key)
{
    TaprootBuilder builder;
    builder.Add(0, leaf_script, TAPROOT_LEAF_TAPSCRIPT_V2, /*track=*/true);
    builder.Finalize(XOnlyPubKey::NUMS_H);

    CScriptWitness witness;
    witness.stack = initial_stack;
    const std::vector<unsigned char> serialized_script{leaf_script.begin(), leaf_script.end()};
    witness.stack.push_back(serialized_script);
    const auto control_blocks{builder.GetSpendData().scripts.at({serialized_script, TAPROOT_LEAF_TAPSCRIPT_V2})};
    witness.stack.push_back(*control_blocks.begin());

    script_pub_key = GetScriptForDestination(builder.GetOutput());
    return witness;
}

inline EvalOutcome EvalTapscriptV2WithFlagsAndChecker(const CScript& script, const Stack& initial_stack, script_verify_flags flags, const BaseSignatureChecker& checker, uint64_t budget)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    ValtypeStack stack{initial_stack};
    const bool ok{::EvalTapscriptV2(stack, script, flags, checker, execdata, varops_budget, &error)};
    return {ok, error, *varops_budget.Remaining(), stack.GetStack()};
}

inline EvalOutcome EvalTapscriptV2(const CScript& script, const Stack& initial_stack, uint64_t budget)
{
    return EvalTapscriptV2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, budget);
}

/** Result of test-side static decoding and unrolling of a Tapscript v2 script (reusable macros draft). */
struct MacroDecoding {
    enum class Result { WELL_FORMED,
                        SUCCESS,
                        FAILURE } result{Result::FAILURE};
    //! Number of declarations.
    uint64_t declarations{0};
    //! Unrolling totals of the main script.
    uint64_t unrolled_length{0};
    uint64_t substituted_instructions{0};
    uint64_t references_visited{0};
    //! The main script with every reference replaced by the unrolled body it
    //! names. Only built when unrolled_length is at most the unrolled size limit.
    CScript unrolled;

    bool WithinLimit() const { return unrolled_length <= MAX_TAPSCRIPT_V2_UNROLLED_SIZE; }
    //! Unrolling charge of a well-formed script.
    uint64_t UnrollCharge() const { return (substituted_instructions + references_visited) * varops::MacroUnrollCost(); }
};

/**
 * Test-side decoder and unroller, written independently of the interpreter's.
 * It decodes in serialized order and stops at the first OP_SUCCESSx or failure.
 */
inline MacroDecoding DecodeMacros(const CScript& script)
{
    using Result = MacroDecoding::Result;
    struct Body {
        //! Unrolled bytes; only built while length is within the limit.
        CScript unrolled;
        uint64_t length{0};
        uint64_t instructions{0};
        uint64_t references{0};
        //! Instructions contributed by references.
        uint64_t substituted{0};
    };
    std::vector<Body> bodies;

    const auto read_compact_size{[&](CScript::const_iterator& pc, CScript::const_iterator end, uint64_t& value) {
        if (pc == end) return false;
        const unsigned char prefix{*pc++};
        if (prefix < 253) {
            value = prefix;
            return true;
        }
        const size_t width{prefix == 253 ? 2U : prefix == 254 ? 4U :
                                                                8U};
        const uint64_t minimum{prefix == 253 ? 253U : prefix == 254 ? 0x10000U :
                                                                      0x100000000U};
        if (static_cast<size_t>(end - pc) < width) return false;
        value = 0;
        for (size_t i{0}; i < width; ++i)
            value |= uint64_t{*pc++} << (8 * i);
        return value >= minimum;
    }};

    // Decode [pc, end) with the given reference limit, accumulating into out.
    const auto decode_sequence{[&](CScript::const_iterator pc, CScript::const_iterator end, uint64_t limit, Body& out) {
        while (pc < end) {
            const CScript::const_iterator begin{pc};
            opcodetype opcode;
            std::vector<unsigned char> data;
            if (!GetScriptOp(pc, end, opcode, &data)) return Result::FAILURE;
            if (IsOpSuccess(opcode, SigVersion::TAPSCRIPT_V2)) return Result::SUCCESS;
            if (opcode == OP_MACRO) return Result::FAILURE;
            if (opcode == OP_CALLMACRO) {
                uint64_t index;
                if (!read_compact_size(pc, end, index) || index >= limit) return Result::FAILURE;
                const Body& body{bodies[index]};
                out.length += body.length;
                out.instructions += body.instructions;
                out.references += 1 + body.references;
                out.substituted += body.instructions;
                if (out.length <= MAX_TAPSCRIPT_V2_UNROLLED_SIZE) {
                    out.unrolled.insert(out.unrolled.end(), body.unrolled.begin(), body.unrolled.end());
                }
                continue;
            }
            out.length += pc - begin;
            ++out.instructions;
            if (out.length <= MAX_TAPSCRIPT_V2_UNROLLED_SIZE) out.unrolled.insert(out.unrolled.end(), begin, pc);
        }
        return Result::WELL_FORMED;
    }};

    MacroDecoding decoding;
    CScript::const_iterator pc{script.begin()};
    while (pc != script.end() && *pc == OP_MACRO) {
        ++pc;
        uint64_t length;
        if (!read_compact_size(pc, script.end(), length) || length > static_cast<uint64_t>(script.end() - pc)) {
            decoding.result = Result::FAILURE;
            return decoding;
        }
        const CScript::const_iterator body_end{pc + static_cast<CScript::difference_type>(length)};
        Body body;
        decoding.result = decode_sequence(pc, body_end, bodies.size(), body);
        if (decoding.result != Result::WELL_FORMED) return decoding;
        bodies.push_back(std::move(body));
        pc = body_end;
    }
    Body main;
    decoding.result = decode_sequence(pc, script.end(), bodies.size(), main);
    if (decoding.result != Result::WELL_FORMED) return decoding;
    decoding.declarations = bodies.size();
    decoding.unrolled_length = main.length;
    decoding.substituted_instructions = main.substituted;
    decoding.references_visited = main.references;
    if (decoding.WithinLimit()) decoding.unrolled = std::move(main.unrolled);
    return decoding;
}

} // namespace test::tapscript_v2

#endif // BITCOIN_TEST_UTIL_TAPSCRIPT_V2_TEST_UTILS_H
