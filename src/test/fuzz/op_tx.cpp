// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Runs OP_TX on structured selectors and scope operands over fuzzed
// transactions, reaching states that arbitrary scripts rarely do. Its values are
// checked by the BIP's reference vectors; this target checks the budget and
// that the stack below the operands is kept.

#include <script/op_tx.h>

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/tapleaf_0xc2.h>
#include <util/check.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

using namespace test::tapleaf_0xc2::fuzz;

namespace {

using valtype = std::vector<unsigned char>;

//! A scope operand, possibly padded with trailing zero bytes.
valtype ConsumeOperand(FuzzedDataProvider& provider, uint32_t value)
{
    valtype operand{biguint::ScalarValue(value)};
    operand.resize(operand.size() + provider.ConsumeIntegralInRange<size_t>(0, 9));
    return operand;
}

uint8_t ConsumeScope(FuzzedDataProvider& provider, Stack& operands, uint32_t total)
{
    const uint8_t scope{provider.ConsumeIntegralInRange<uint8_t>(0, 4)};
    if (scope == 3) {
        const uint32_t index{
            total == 0 ? 0 : provider.ConsumeIntegralInRange<uint32_t>(0, total - 1)};
        operands.push_back(ConsumeOperand(provider, index));
    } else if (scope == 4) {
        const uint32_t start{total == 0 ? 0 : provider.ConsumeIntegralInRange<uint32_t>(0, total - 1)};
        const uint32_t count{total == 0 ? 1 : provider.ConsumeIntegralInRange<uint32_t>(1, total - start)};
        operands.push_back(ConsumeOperand(provider, start));
        operands.push_back(ConsumeOperand(provider, count));
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
    // Only participating inputs are funded, so the budget is at most that of the whole weight.
    const uint64_t cap{varops::TxBudget(GetTransactionWeight(tx))};
    Assert(GetTransactionVaropsBudget(tx, spent_outputs) <= cap);
    const uint32_t input_index{provider.ConsumeIntegralInRange<uint32_t>(0, tx.vin.size() - 1)};
    const op_tx::TxView tx_data{tx.version, tx.vin, tx.vout, tx.nLockTime, input_index, spent_outputs};

    const valtype annex{ConsumeRandomLengthByteVector(provider, 256)};
    const valtype tapscript{ConsumeRandomLengthByteVector(provider, 1024)};
    const valtype control_block{ConsumeRandomLengthByteVector(provider, 256)};
    std::optional<op_tx::ScriptContext> context;
    if (provider.ConsumeBool()) {
        context = op_tx::ScriptContext{
            .annex = annex,
            .tapscript = tapscript,
            .tapleaf_hash = ConsumeUInt256(provider),
            .control_block = control_block,
            .taptree_root = ConsumeUInt256(provider),
            .codeseparator_pos = provider.ConsumeIntegral<uint32_t>(),
        };
    }

    Stack stack{ConsumeStack(provider)};
    Invocation invocation{ConsumeInvocation(provider, tx.vin.size(), tx.vout.size())};
    stack.insert(stack.end(), invocation.scope_operands.begin(), invocation.scope_operands.end());
    stack.push_back(std::move(invocation.selector));
    const Stack altstack{ConsumeStack(provider)};
    const uint64_t budget_seed{provider.ConsumeIntegral<uint64_t>()};

    const auto run{[&](uint64_t budget) {
        ValtypeStack eval_stack{stack};
        const ValtypeStack eval_altstack{altstack};
        varops::Budget varops_budget{budget};
        varops::Meter meter{varops_budget};
        Outcome outcome;
        outcome.error = SCRIPT_ERR_OK;
        op_tx::Result result{op_tx::Eval(eval_stack, eval_altstack, tx_data, context, meter, &outcome.error)};
        // A script deducts its charges before it completes.
        if (result != op_tx::Result::SCRIPT_ERROR && !meter.Spend(varops_budget)) {
            result = op_tx::Result::SCRIPT_ERROR;
            outcome.error = SCRIPT_ERR_VAROP_COUNT;
        }
        outcome.ok = result != op_tx::Result::SCRIPT_ERROR;
        outcome.immediate_success = result == op_tx::Result::IMMEDIATE_SUCCESS;
        if (outcome.ok) CheckStackAccounting(eval_stack);
        outcome.consumed = budget - varops_budget.Remaining();
        outcome.stack = eval_stack.GetStack();
        return outcome;
    }};
    const Outcome outcome{CheckBudget(run, cap, budget_seed % (cap + 1))};
    if (!outcome.ok) return;

    const Stack below_selector(stack.begin(), stack.end() - 1);
    if (outcome.immediate_success) {
        // Reserved selector versions succeed at once, paying BASE alone.
        Assert(outcome.stack == below_selector);
        Assert(outcome.consumed == varops::BaseCost());
        return;
    }
    // The selector and scope operands are replaced by the results.
    const auto scope_operand_count{ScopeOperandCount(stack.back())};
    Assert(scope_operand_count && *scope_operand_count <= below_selector.size());
    const size_t kept{below_selector.size() - *scope_operand_count};
    Assert(outcome.stack.size() >= kept);
    Assert(std::equal(below_selector.begin(), below_selector.begin() + kept, outcome.stack.begin()));
}
