// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/interpreter.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/tapscript_v2_fuzz_util.h>
#include <util/check.h>

#include <algorithm>
#include <cstdint>

namespace {
using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

void CheckInitialLimits(FuzzedDataProvider& provider)
{
    Stack stack;
    ScriptError expected_error{SCRIPT_ERR_OK};
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 2)) {
    case 0: {
        const size_t count{provider.PickValueInArray<size_t>({MAX_TAPSCRIPT_V2_STACK_SIZE - 1,
                                                              MAX_TAPSCRIPT_V2_STACK_SIZE,
                                                              MAX_TAPSCRIPT_V2_STACK_SIZE + 1})};
        stack.resize(count);
        if (count > MAX_TAPSCRIPT_V2_STACK_SIZE) expected_error = SCRIPT_ERR_STACK_SIZE;
        break;
    }
    case 1: {
        const size_t size{provider.PickValueInArray<size_t>({MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1,
                                                             MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE,
                                                             MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1})};
        stack.emplace_back(size, 0x01);
        if (size > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) expected_error = SCRIPT_ERR_STACK_ELEMENT_SIZE;
        break;
    }
    case 2: {
        const size_t total{provider.PickValueInArray<size_t>({MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - 1,
                                                              MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE,
                                                              MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE + 1})};
        const size_t first{std::min<size_t>(total, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)};
        const size_t second{std::min<size_t>(total - first, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)};
        stack.emplace_back(first, 0x01);
        stack.emplace_back(second, 0x02);
        if (total > first + second) stack.emplace_back(total - first - second, 0x03);
        if (total > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE) expected_error = SCRIPT_ERR_TOTAL_STACK_SIZE;
        break;
    }
    }

    const BaseSignatureChecker checker;
    const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(OneOp(OP_NOP), stack, SCRIPT_VERIFY_NONE, checker, 0)};
    Assert(outcome.ok == (expected_error == SCRIPT_ERR_OK));
    Assert(outcome.error == expected_error);
}

void CheckAltstackCopyLimit(FuzzedDataProvider& provider)
{
    const size_t value_size{provider.PickValueInArray<size_t>({1, 2, 7, 8, 9, 64, 128, 256})};
    const int64_t offset{provider.PickValueInArray<int64_t>({-1, 0, 1})};
    const size_t final_total{static_cast<size_t>(static_cast<int64_t>(MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE) + offset)};
    const size_t filler_total{final_total - 2 * value_size};
    const size_t first_size{std::min<size_t>(filler_total, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)};
    const size_t second_size{filler_total - first_size};
    Assert(second_size <= MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE);

    const Bytes value(value_size, 0x11);
    Stack stack{value, Bytes(first_size, 0x22), Bytes(second_size, 0x33)};
    CScript script;
    script << OP_TOALTSTACK << OP_TOALTSTACK << OP_DUP;
    const uint64_t cost{CopyCost(value_size)};

    if (final_total <= MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE) {
        CheckExactEval(script, stack, {value, value}, cost);
    } else {
        CheckEvalErrorBudget(script, stack, cost, SCRIPT_ERR_TOTAL_STACK_SIZE, cost);
    }
}

void CheckDeepRoll(FuzzedDataProvider& provider)
{
    const size_t depth{provider.PickValueInArray<size_t>({0, 1, 16, 63, 255, 1'023, 4'095, 8'191,
                                                          MAX_TAPSCRIPT_V2_STACK_SIZE - 2})};
    Stack stack(depth + 1);
    for (size_t i{0}; i < stack.size(); ++i) {
        stack[i] = {static_cast<unsigned char>(i), static_cast<unsigned char>(i >> 8)};
    }

    Bytes encoded{ToLittleEndian(depth)};
    if (provider.ConsumeBool()) encoded.resize(provider.ConsumeIntegralInRange<size_t>(encoded.size(), encoded.size() + 16));
    CScript script;
    script << encoded << OP_ROLL;

    Stack expected{stack};
    const Bytes selected{expected.front()};
    expected.erase(expected.begin());
    expected.push_back(selected);
    CheckExactEval(script, stack, expected, RollCost(encoded.size(), depth));
}

void CheckPickRollBounds(FuzzedDataProvider& provider)
{
    const opcodetype opcode{provider.ConsumeBool() ? OP_PICK : OP_ROLL};
    const size_t count{provider.PickValueInArray<size_t>({1, 2, 8, 64, 256})};
    Stack stack(count);
    for (size_t i{0}; i < count; ++i)
        stack[i] = {static_cast<unsigned char>(i)};

    const uint64_t depth{count + provider.ConsumeIntegralInRange<uint64_t>(0, 8)};
    Bytes encoded{ToLittleEndian(depth)};
    if (provider.ConsumeBool()) encoded.resize(provider.ConsumeIntegralInRange<size_t>(encoded.size(), encoded.size() + 16));
    CScript script;
    script << encoded << opcode;
    const uint64_t budget{provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000)};
    CheckEvalErrorBudget(script, stack, budget, SCRIPT_ERR_INVALID_STACK_OPERATION, budget);
}

void CheckCombinedElementCount(FuzzedDataProvider& provider)
{
    const size_t initial_count{provider.PickValueInArray<size_t>({MAX_TAPSCRIPT_V2_STACK_SIZE - 3,
                                                                  MAX_TAPSCRIPT_V2_STACK_SIZE - 2,
                                                                  MAX_TAPSCRIPT_V2_STACK_SIZE - 1,
                                                                  MAX_TAPSCRIPT_V2_STACK_SIZE})};
    const size_t moved_count{provider.ConsumeIntegralInRange<size_t>(1, 3)};
    const size_t growth{provider.ConsumeIntegralInRange<size_t>(0, 3)};

    Stack stack(initial_count);
    for (size_t i{0}; i < moved_count; ++i) {
        stack[initial_count - moved_count + i] = {static_cast<unsigned char>(0x80 + i)};
    }

    CScript script;
    for (size_t i{0}; i < moved_count; ++i)
        script << OP_TOALTSTACK;
    switch (growth) {
    case 0: script << OP_NOP; break;
    case 1: script << OP_DUP; break;
    case 2: script << OP_2DUP; break;
    case 3: script << OP_3DUP; break;
    }
    for (size_t i{0}; i < moved_count; ++i)
        script << OP_FROMALTSTACK;

    if (initial_count + growth > MAX_TAPSCRIPT_V2_STACK_SIZE) {
        CheckEvalErrorBudget(script, stack, 0, SCRIPT_ERR_STACK_SIZE, 0);
        return;
    }

    const Stack::iterator moved_begin{stack.begin() + initial_count - moved_count};
    Stack expected{stack.begin(), moved_begin};
    expected.insert(expected.end(), growth, Bytes{});
    expected.insert(expected.end(), moved_begin, stack.end());
    CheckExactEval(script, stack, expected, 0);
}
} // namespace

FUZZ_TARGET(tapscript_v2_stack_resource_limits)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 4)) {
    case 0: CheckInitialLimits(provider); break;
    case 1: CheckAltstackCopyLimit(provider); break;
    case 2: CheckDeepRoll(provider); break;
    case 3: CheckPickRollBounds(provider); break;
    case 4: CheckCombinedElementCount(provider); break;
    }
}
