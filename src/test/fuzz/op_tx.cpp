// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/op_tx.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/check.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;
using Stack = std::vector<valtype>;

class OpTxChecker final : public BaseSignatureChecker
{
    const CTransaction& m_tx;
    const uint32_t m_input_index;
    const std::span<const CTxOut> m_spent_outputs;

public:
    OpTxChecker(const CTransaction& tx, uint32_t input_index, std::span<const CTxOut> spent_outputs)
        : m_tx{tx}, m_input_index{input_index}, m_spent_outputs{spent_outputs}
    {
    }

    std::optional<ScriptTransactionData> GetTransactionData() const override
    {
        return ScriptTransactionData{
            m_tx.version,
            m_tx.vin,
            m_tx.vout,
            m_tx.nLockTime,
            m_input_index,
            m_spent_outputs,
        };
    }
};

valtype MinimalUint(uint32_t value)
{
    valtype result;
    while (value != 0) {
        result.push_back(static_cast<unsigned char>(value));
        value >>= 8;
    }
    return result;
}

uint8_t ConsumeScope(FuzzedDataProvider& provider, Stack& operands, uint32_t total)
{
    const uint8_t scope{provider.ConsumeIntegralInRange<uint8_t>(0, 4)};
    if (scope == 3) {
        const uint32_t index{
            total == 0 ? 0 : provider.ConsumeIntegralInRange<uint32_t>(0, total - 1)};
        operands.push_back(MinimalUint(index));
    } else if (scope == 4) {
        const uint32_t start{total == 0 ? 0 : provider.ConsumeIntegralInRange<uint32_t>(0, total - 1)};
        const uint32_t count{total == 0 ? 1 : provider.ConsumeIntegralInRange<uint32_t>(1, total - start)};
        operands.push_back(MinimalUint(start));
        operands.push_back(MinimalUint(count));
    }
    return scope;
}

struct Invocation {
    valtype selector;
    Stack scope_operands;
};

Invocation ConsumeInvocation(FuzzedDataProvider& provider, uint32_t input_count, uint32_t output_count)
{
    if (!provider.ConsumeBool()) return {ConsumeRandomLengthByteVector(provider, 32), {}};
    if (provider.ConsumeIntegralInRange<uint8_t>(0, 15) == 0) {
        valtype selector{provider.ConsumeIntegralInRange<uint8_t>(1, 0xff)};
        const valtype trailing{ConsumeRandomLengthByteVector(provider, 16)};
        selector.insert(selector.end(), trailing.begin(), trailing.end());
        return {std::move(selector), {}};
    }
    if (provider.ConsumeIntegralInRange<uint8_t>(0, 7) == 0) {
        return {
            provider.ConsumeBool() ? valtype{0, 0, 0, 1, 0, 4}
                                   : valtype{0, 0, 0, 0x50, 1, 0},
            {},
        };
    }

    Stack scope_operands;
    const uint8_t input_scope{ConsumeScope(provider, scope_operands, input_count)};
    const uint8_t output_scope{ConsumeScope(provider, scope_operands, output_count)};
    uint8_t input_fields{0};
    uint8_t output_fields{0};
    if (input_scope != 0) {
        input_fields = provider.ConsumeIntegralInRange<uint8_t>(1, 0xff);
    }
    if (output_scope != 0) {
        output_fields = provider.ConsumeIntegralInRange<uint8_t>(1, 3);
    }
    uint8_t globals{provider.ConsumeIntegral<uint8_t>()};
    uint8_t context{provider.ConsumeIntegral<uint8_t>()};
    if (globals == 0 && context == 0 && input_fields == 0 && output_fields == 0) {
        globals = 0x02;
    }

    return {
        {0, globals, context, static_cast<uint8_t>(input_scope << 4 | output_scope),
         input_fields, output_fields},
        std::move(scope_operands),
    };
}

std::optional<size_t> ScopeOperandCount(const valtype& selector)
{
    if (selector.size() != 6 || selector[0] != 0) return std::nullopt;
    const auto count{[](uint8_t scope) -> std::optional<size_t> {
        if (scope <= 2) return 0;
        if (scope == 3) return 1;
        if (scope == 4) return 2;
        return std::nullopt;
    }};
    const auto inputs{count(selector[3] >> 4)};
    const auto outputs{count(selector[3] & 0x0f)};
    if (!inputs || !outputs) return std::nullopt;
    return *inputs + *outputs;
}

Stack ConsumeStack(FuzzedDataProvider& provider)
{
    Stack stack;
    const size_t count{provider.ConsumeIntegralInRange<size_t>(0, 8)};
    stack.reserve(count);
    for (size_t i{0}; i < count; ++i)
        stack.push_back(ConsumeRandomLengthByteVector(provider, 256));
    return stack;
}

struct Outcome {
    OpTxResult result;
    ScriptError error;
    uint64_t remaining;
    Stack stack;
};

Outcome Evaluate(const Stack& initial_stack, const Stack& initial_altstack,
                 const BaseSignatureChecker& checker, const ScriptExecutionData& execdata,
                 uint64_t budget)
{
    ValtypeStack stack{initial_stack};
    ValtypeStack altstack{initial_altstack};
    varops::Budget varops_budget{budget};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const OpTxResult result{EvalOpTx(stack, altstack, checker, execdata, varops_budget, &error)};
    return {result, error, *varops_budget.Remaining(), stack.GetStack()};
}

} // namespace

FUZZ_TARGET(op_tx)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    CMutableTransaction mutable_tx{ConsumeTransaction(provider, std::nullopt, 8, 8)};
    if (mutable_tx.vin.empty()) mutable_tx.vin.emplace_back();
    for (CTxOut& output : mutable_tx.vout)
        output.nValue = std::clamp<CAmount>(output.nValue, 0, MAX_MONEY);
    const CTransaction tx{mutable_tx};

    std::vector<CTxOut> spent_outputs;
    spent_outputs.reserve(tx.vin.size());
    for (size_t i{0}; i < tx.vin.size(); ++i) {
        spent_outputs.emplace_back(ConsumeMoney(provider), ConsumeScript(provider));
    }
    const uint32_t input_index{provider.ConsumeIntegralInRange<uint32_t>(0, tx.vin.size() - 1)};
    const OpTxChecker checker{tx, input_index, spent_outputs};

    const valtype annex{ConsumeRandomLengthByteVector(provider, 256)};
    const valtype tapscript{ConsumeRandomLengthByteVector(provider, 1024)};
    const valtype control_block{ConsumeRandomLengthByteVector(provider, 256)};
    ScriptExecutionData execdata;
    execdata.m_annex_init = provider.ConsumeBool();
    execdata.m_annex_present = execdata.m_annex_init && provider.ConsumeBool();
    if (execdata.m_annex_present) {
        execdata.m_annex = annex;
    }
    execdata.m_tapscript_init = provider.ConsumeBool();
    if (execdata.m_tapscript_init) execdata.m_tapscript = tapscript;
    execdata.m_tapleaf_hash_init = provider.ConsumeBool();
    execdata.m_tapleaf_hash = ConsumeUInt256(provider);
    execdata.m_taptree_root_init = provider.ConsumeBool();
    execdata.m_taptree_root = ConsumeUInt256(provider);
    execdata.m_control_block_init = provider.ConsumeBool();
    if (execdata.m_control_block_init) execdata.m_control_block = control_block;
    execdata.m_codeseparator_pos_init = provider.ConsumeBool();
    execdata.m_codeseparator_pos = provider.ConsumeIntegral<uint32_t>();

    Stack stack{ConsumeStack(provider)};
    Invocation invocation{ConsumeInvocation(provider, tx.vin.size(), tx.vout.size())};
    stack.insert(stack.end(), invocation.scope_operands.begin(), invocation.scope_operands.end());
    stack.push_back(std::move(invocation.selector));
    const Stack altstack{ConsumeStack(provider)};
    const uint64_t budget{provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000)};
    const Outcome outcome{Evaluate(stack, altstack, checker, execdata, budget)};
    Assert(outcome.remaining <= budget);
    Stack stack_without_selector{stack};
    stack_without_selector.pop_back();
    const auto scope_operand_count{ScopeOperandCount(stack.back())};
    Stack stack_without_scope_operands{stack_without_selector};
    if (scope_operand_count && *scope_operand_count <= stack_without_scope_operands.size()) {
        stack_without_scope_operands.resize(stack_without_scope_operands.size() - *scope_operand_count);
    }

    if (outcome.result == OpTxResult::ERROR) {
        Assert(outcome.stack == stack_without_selector ||
               (scope_operand_count && outcome.stack == stack_without_scope_operands));
        Assert(outcome.remaining == budget);
        return;
    }

    if (outcome.result == OpTxResult::IMMEDIATE_SUCCESS) {
        Assert(outcome.stack == stack_without_selector);
        Assert(outcome.remaining == budget);
        return;
    }

    Assert(outcome.stack.size() + altstack.size() <= MAX_TAPSCRIPT_V2_STACK_SIZE);
    size_t total_size{0};
    for (const valtype& element : outcome.stack) {
        Assert(element.size() <= MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE);
        total_size += element.size();
    }
    for (const valtype& element : altstack)
        total_size += element.size();
    Assert(total_size <= MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE);
    Assert(scope_operand_count);
    Assert(*scope_operand_count <= stack_without_selector.size());
    Assert(outcome.stack.size() >= stack_without_scope_operands.size());
    Assert(std::equal(stack_without_scope_operands.begin(), stack_without_scope_operands.end(),
                      outcome.stack.begin()));

    const uint64_t cost{budget - outcome.remaining};
    const Outcome exact{Evaluate(stack, altstack, checker, execdata, cost)};
    Assert(exact.result == OpTxResult::NORMAL);
    Assert(exact.remaining == 0);
    Assert(exact.stack == outcome.stack);
    if (cost != 0) {
        const Outcome insufficient{Evaluate(stack, altstack, checker, execdata, cost - 1)};
        Assert(insufficient.result == OpTxResult::ERROR);
        Assert(insufficient.error == SCRIPT_ERR_VAROP_COUNT);
        Assert(insufficient.remaining == cost - 1);
        Assert(insufficient.stack == stack_without_scope_operands);
    }
}
