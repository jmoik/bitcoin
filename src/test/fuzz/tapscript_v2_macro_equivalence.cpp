// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Differential check of reusable macros. The interpreter's static decoding
// must agree with an independent test decoder on arbitrary (mutated) scripts,
// and a well-formed committed script must behave exactly like its unrolled
// script, charging exactly F * (substituted instructions + references visited)
// more.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/tapscript_v2_test_utils.h>
#include <util/check.h>

#include <cstdint>
#include <optional>
#include <vector>

using namespace test::tapscript_v2;

namespace {

constexpr uint64_t BUDGET{1'000'000'000'000};
constexpr size_t MAX_UNROLLED_SIZE{100'000};

void AppendCompactSize(CScript& script, uint64_t value)
{
    if (value < 253) {
        script.push_back(value);
        return;
    }
    script.push_back(0xfd);
    script.push_back(value & 0xff);
    script.push_back(value >> 8);
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
                OP_0,
                OP_1,
                OP_2,
                OP_16,
                OP_IF,
                OP_NOTIF,
                OP_ELSE,
                OP_ENDIF,
                OP_DUP,
                OP_DROP,
                OP_SWAP,
                OP_ADD,
                OP_EQUAL,
                OP_VERIFY,
                OP_NOP,
                OP_CODESEPARATOR,
                OP_TOALTSTACK,
                OP_FROMALTSTACK,
                OP_CAT,
                OP_SIZE,
            });
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

struct Execution {
    bool ok{false};
    //! Execution stopped early at an upgradeable success, such as a reserved OP_TX selector.
    bool immediate_success{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t charge{0};
    Stack stack;
    std::optional<uint32_t> codeseparator_pos;
};

Execution Execute(const CScript& script, const Stack& initial_stack, uint64_t budget)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    varops::Budget varops_budget{budget};
    ValtypeStack stack{initial_stack};
    Execution execution;
    execution.ok = EvalTapscriptV2(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata,
                                   varops_budget, &execution.error, &execution.immediate_success);
    execution.charge = budget - *varops_budget.Remaining();
    execution.stack = stack.GetStack();
    if (execdata.m_codeseparator_pos_init) execution.codeseparator_pos = execdata.m_codeseparator_pos;
    return execution;
}

} // namespace

FUZZ_TARGET(tapscript_v2_macro_equivalence)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const CScript script{ConsumeMacroScript(provider)};

    // Both decoders must agree on every script.
    const MacroDecoding decoding{DecodeMacros(script)};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const std::optional<bool> decoded{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    switch (decoding.result) {
    case MacroDecoding::Result::WELL_FORMED: Assert(!decoded.has_value()); break;
    case MacroDecoding::Result::SUCCESS: Assert(decoded == std::optional<bool>{true}); break;
    case MacroDecoding::Result::FAILURE:
        Assert(decoded == std::optional<bool>{false});
        Assert(error == SCRIPT_ERR_BAD_OPCODE);
        break;
    }
    if (decoding.result != MacroDecoding::Result::WELL_FORMED) return;
    if (decoding.unrolled_length > MAX_UNROLLED_SIZE) return;
    Assert(decoding.unrolled.size() == decoding.unrolled_length);
    // The unrolled script has no declarations and no references.
    Assert(!CheckTapscriptOpSuccess(decoding.unrolled, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error).has_value());

    Stack initial_stack;
    const size_t items{provider.ConsumeIntegralInRange<size_t>(0, 3)};
    for (size_t i{0}; i < items; ++i)
        initial_stack.push_back(ConsumeRandomLengthByteVector(provider, 2));

    const Execution macro{Execute(script, initial_stack, BUDGET)};
    const Execution inlined{Execute(decoding.unrolled, initial_stack, BUDGET)};
    Assert(macro.ok == inlined.ok);
    Assert(macro.immediate_success == inlined.immediate_success);
    Assert(macro.error == inlined.error);
    Assert(macro.stack == inlined.stack);
    Assert(macro.codeseparator_pos == inlined.codeseparator_pos);

    // Only the unrolling charge, paid up front, separates the two executions.
    Assert(macro.charge == inlined.charge + decoding.UnrollCharge());

    // The exact charge suffices and one less does not.
    if (macro.ok && macro.charge > 0) {
        const Execution exact{Execute(script, initial_stack, macro.charge)};
        Assert(exact.ok);
        Assert(exact.stack == macro.stack);
        const Execution short_budget{Execute(script, initial_stack, macro.charge - 1)};
        Assert(!short_budget.ok);
        Assert(short_budget.error == SCRIPT_ERR_VAROP_COUNT);
    }
}
