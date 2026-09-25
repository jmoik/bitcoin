// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Differential check of reusable macros. The interpreter's static decoding and
// unrolling must agree with the test decoder below, written independently, on
// arbitrary (mutated) scripts: the result, the unrolling totals, the unrolled
// script and its charge.

#include <script/reusable_macros.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/check.h>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace {

/** Result of the test decoder: static decoding and unrolling of a Tapscript v2 script. */
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
    //! Unrolling charge of a well-formed script: BASE per substituted
    //! instruction and visited reference, plus WRITE of the unrolled script
    //! when it declares any macro.
    uint64_t UnrollCharge() const
    {
        const uint64_t script_charge{declarations > 0 ? varops::WriteCost(unrolled_length) : 0};
        return (substituted_instructions + references_visited) * varops::BaseCost() + script_charge;
    }
};

/**
 * Test-side decoder and unroller, written independently of the interpreter's.
 * It decodes in serialized order and stops at the first OP_SUCCESSx or failure.
 */
MacroDecoding DecodeMacros(const CScript& script)
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
            if (IsTapscriptV2OpSuccess(opcode)) return Result::SUCCESS;
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

void AppendCompactSize(CScript& script, uint64_t value)
{
    if (value < 253) {
        script.push_back(static_cast<unsigned char>(value));
        return;
    }
    script.push_back(0xfd);
    script.push_back(static_cast<unsigned char>(value & 0xff));
    script.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
}

CScript ConsumeSequence(FuzzedDataProvider& provider, uint64_t reference_limit, size_t max_items)
{
    CScript sequence;
    const size_t items{provider.ConsumeIntegralInRange<size_t>(0, max_items)};
    for (size_t i{0}; i < items; ++i) {
        if (reference_limit > 0 && provider.ConsumeIntegralInRange<uint8_t>(0, 3) == 0) {
            sequence << OP_CALLMACRO;
            AppendCompactSize(sequence, provider.ConsumeIntegralInRange<uint64_t>(0, reference_limit - 1));
        } else if (provider.ConsumeIntegralInRange<uint8_t>(0, 4) == 0) {
            sequence << ConsumeRandomLengthByteVector(provider, 4);
        } else {
            sequence << provider.PickValueInArray<opcodetype>({
                OP_0, OP_1, OP_2, OP_16, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_DUP, OP_DROP,
                OP_SWAP, OP_ADD, OP_EQUAL, OP_VERIFY, OP_NOP, OP_CODESEPARATOR, OP_TOALTSTACK,
                OP_FROMALTSTACK, OP_CAT, OP_SIZE});
        }
    }
    return sequence;
}

CScript ConsumeMacroScript(FuzzedDataProvider& provider)
{
    CScript script;
    const uint64_t declarations{provider.ConsumeIntegralInRange<uint64_t>(0, 5)};
    for (uint64_t i{0}; i < declarations; ++i) {
        const CScript body{ConsumeSequence(provider, i, 8)};
        script << OP_MACRO;
        AppendCompactSize(script, body.size());
        script.insert(script.end(), body.begin(), body.end());
    }
    const CScript main{ConsumeSequence(provider, declarations, 24)};
    script.insert(script.end(), main.begin(), main.end());

    if (!script.empty() && provider.ConsumeIntegralInRange<uint8_t>(0, 3) == 0) {
        const size_t position{provider.ConsumeIntegralInRange<size_t>(0, script.size() - 1)};
        switch (provider.ConsumeIntegralInRange<uint8_t>(0, 2)) {
        case 0: script[position] = provider.ConsumeIntegral<uint8_t>(); break;
        case 1: script.insert(script.begin() + position, provider.ConsumeIntegral<uint8_t>()); break;
        case 2: script.erase(script.begin() + position); break;
        }
    }
    return script;
}

} // namespace

FUZZ_TARGET(tapscript_v2_macro_equivalence)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const CScript script{ConsumeMacroScript(provider)};

    const MacroDecoding expected{DecodeMacros(script)};
    MacroProgram program{script};
    const MacroDecodeResult result{DecodeTapscriptV2(program)};
    switch (expected.result) {
    case MacroDecoding::Result::WELL_FORMED: Assert(result == MacroDecodeResult::WELL_FORMED); break;
    case MacroDecoding::Result::SUCCESS: Assert(result == MacroDecodeResult::OP_SUCCESS); break;
    case MacroDecoding::Result::FAILURE: Assert(result == MacroDecodeResult::MALFORMED); break;
    }
    if (result != MacroDecodeResult::WELL_FORMED) return;
    Assert(program.bodies.size() == expected.declarations);
    Assert(program.main_totals.length == expected.unrolled_length);
    Assert(program.main_totals.substituted == expected.substituted_instructions);
    Assert(program.main_totals.references == expected.references_visited);

    // The size limit is checked before the charge; within it, unrolling charges
    // exactly the unrolling charge.
    const uint64_t charge{expected.UnrollCharge()};
    CScript unrolled;
    ScriptError error{SCRIPT_ERR_OK};
    varops::Budget budget{charge};
    if (!expected.WithinLimit()) {
        Assert(!UnrollTapscriptV2(program, budget, unrolled, &error));
        Assert(error == SCRIPT_ERR_SCRIPT_SIZE);
        return;
    }
    Assert(UnrollTapscriptV2(program, budget, unrolled, &error));
    Assert(budget.Remaining() == 0);
    // Without declarations the committed script is executed as it is.
    Assert(program.bodies.empty() ? unrolled.empty() && script == expected.unrolled : unrolled == expected.unrolled);
    if (charge > 0) {
        varops::Budget short_budget{charge - 1};
        Assert(!UnrollTapscriptV2(program, short_budget, unrolled, &error));
        Assert(error == SCRIPT_ERR_VAROP_COUNT);
    }
}
