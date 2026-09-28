// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Exercises shared varops budgets, conditional charging, partial failures, and
// final stack truthiness at exact and insufficient budget boundaries.

#include <script/script.h>
#include <script/script_error.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/tapscript_v2_fuzz_util.h>
#include <util/check.h>

#include <cstdint>

namespace {
using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

void VerifyPair(const LeafSpend& first, uint64_t first_cost, const LeafSpend& second, uint64_t second_cost)
{
    const BaseSignatureChecker checker;
    {
        varops::Budget budget{first_cost + second_cost};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        Assert(VerifySpend(first, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_OK);
        Assert(*budget.Remaining() == second_cost);
        Assert(VerifySpend(second, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_OK);
        Assert(*budget.Remaining() == 0);
    }
    {
        varops::Budget budget{first_cost + second_cost - 1};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        Assert(VerifySpend(first, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_OK);
        Assert(*budget.Remaining() == second_cost - 1);
        Assert(!VerifySpend(second, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_VAROP_COUNT);
    }
}

void CheckSharedBudget(FuzzedDataProvider& provider)
{
    Bytes a{ConsumeElement(provider)};
    Bytes b{ConsumeElement(provider)};
    if (a.empty()) a.push_back(1);
    if (b.empty()) b.push_back(2);

    CScript script;
    script << OP_DUP << OP_EQUAL;
    const LeafSpend spend_a{BuildLeafSpend(script, {a})};
    const LeafSpend spend_b{BuildLeafSpend(script, {b})};
    // Witness item, DUP, EQUAL and the final check of the one-byte true result.
    const auto spend_cost = [](const Bytes& item) {
        return InitialStackCost({item}) + CopyingCost({item.size()}) + EqualCost(item.size(), item.size()) +
               FinalCheckCost(1);
    };
    const uint64_t cost_a{spend_cost(a)};
    const uint64_t cost_b{spend_cost(b)};
    VerifyPair(spend_a, cost_a, spend_b, cost_b);
    VerifyPair(spend_b, cost_b, spend_a, cost_a);
}

void CheckConditionalBudget(FuzzedDataProvider& provider)
{
    const Bytes element{ConsumeElement(provider)};
    const bool condition{provider.ConsumeBool()};
    const opcodetype conditional{provider.ConsumeBool() ? OP_IF : OP_NOTIF};
    const bool first_branch_executes{condition == (conditional == OP_IF)};
    const bool costed_first{provider.ConsumeBool()};
    const bool nested{provider.ConsumeBool()};

    CScript script;
    script << (condition ? OP_1 : OP_0) << conditional;
    // Condition push (OP_1 is a scalar, OP_0 an empty literal), then IF/NOTIF.
    uint64_t cost{InitialStackCost({element}) + (condition ? F() + ScalarCost() : CopyingCost({0})) + F()};
    const auto append_branch = [&](bool costed, bool executes) {
        if (!costed) {
            script << OP_NOP;
            if (executes) cost += F();
        } else if (nested) {
            script << OP_1 << OP_IF << OP_DUP << OP_ENDIF;
            // Inactive IF/ENDIF still pay F; the push and DUP are skipped.
            cost += executes ? F() + ScalarCost() + F() + CopyingCost({element.size()}) + F() : 2 * F();
        } else {
            script << OP_DUP;
            if (executes) cost += CopyingCost({element.size()});
        }
    };
    append_branch(costed_first, first_branch_executes);
    script << OP_ELSE;
    append_branch(!costed_first, !first_branch_executes);
    script << OP_ENDIF;
    cost += 2 * F();

    const bool duplicates{first_branch_executes == costed_first};
    const Stack expected{duplicates ? Stack{element, element} : Stack{element}};
    CheckExactEval(script, {element}, expected, cost);
}

void CheckPartialFailure(FuzzedDataProvider& provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 2)) {
    case 0: {
        Bytes element{ConsumeElement(provider)};
        if (element.empty()) element.push_back(1);
        CScript script;
        script << OP_DUP << OP_FROMALTSTACK;
        // F is spent before each opcode executes, so the failing FROMALTSTACK pays F.
        const uint64_t initial{InitialStackCost({element})};
        const uint64_t spent{initial + CopyingCost({element.size()}) + F()};
        const uint64_t extra{provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000)};
        CheckEvalErrorBudget(script, {element}, spent + extra, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, extra);
        // DUP's F is spent; its production charge then exceeds the rest.
        const uint64_t short_budget{initial + CopyingCost({element.size()}) - 1};
        CheckEvalErrorBudget(script, {element}, short_budget, SCRIPT_ERR_VAROP_COUNT, short_budget - initial - F());
        break;
    }
    case 1: {
        const Bytes a{ConsumeElement(provider)};
        Bytes b{ConsumeElement(provider)};
        if (b.empty()) b.push_back(1);
        CScript script;
        script << OP_DUP << OP_CAT;
        // CAT's F is spent; its production of the joined value is one varop short.
        const uint64_t before_cat{InitialStackCost({a, b}) + CopyingCost({b.size()}) + F()};
        const uint64_t cat_cost{ProduceCost(2 * b.size())};
        CheckEvalErrorBudget(script, {a, b}, before_cat + cat_cost - 1, SCRIPT_ERR_VAROP_COUNT, cat_cost - 1);
        break;
    }
    case 2: {
        const uint64_t budget{provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000)};
        const opcodetype opcode{provider.PickValueInArray<opcodetype>({OP_DUP, OP_CAT, OP_FROMALTSTACK})};
        // F is spent before the opcode discovers its missing operand.
        if (budget < F()) {
            CheckEvalErrorBudget(OneOp(opcode), {}, budget, SCRIPT_ERR_VAROP_COUNT, budget);
        } else {
            CheckEvalErrorBudget(
                OneOp(opcode),
                {},
                budget,
                opcode == OP_FROMALTSTACK ? SCRIPT_ERR_INVALID_ALTSTACK_OPERATION : SCRIPT_ERR_INVALID_STACK_OPERATION,
                budget - F());
        }
        break;
    }
    }
}

void CheckFinalSuccess(FuzzedDataProvider& provider)
{
    Stack stack;
    const size_t count{provider.ConsumeIntegralInRange<size_t>(0, 2)};
    for (size_t i{0}; i < count; ++i)
        stack.push_back(ConsumeElement(provider));

    const LeafSpend spend{BuildLeafSpend(CScript{}, stack)};
    const BaseSignatureChecker checker;
    if (stack.size() != 1) {
        const VerifyOutcome outcome{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, 1'000'000)};
        Assert(!outcome.ok);
        Assert(outcome.error == SCRIPT_ERR_CLEANSTACK);
        // Witness items are prepaid before the cleanstack check fails.
        Assert(outcome.remaining_budget == 1'000'000 - InitialStackCost(stack));
        return;
    }

    const uint64_t cost{InitialStackCost(stack) + FinalCheckCost(stack.back().size())};
    const VerifyOutcome exact{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, cost)};
    Assert(exact.ok == ContainsNonZero(stack.back()));
    Assert(exact.error == (exact.ok ? SCRIPT_ERR_OK : SCRIPT_ERR_EVAL_FALSE));
    Assert(exact.remaining_budget == 0);
    if (cost > 0) {
        const VerifyOutcome low{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, cost - 1)};
        Assert(!low.ok);
        Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
    }
}
} // namespace

FUZZ_TARGET(tapscript_v2_budget_accounting)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
    case 0: CheckSharedBudget(provider); break;
    case 1: CheckConditionalBudget(provider); break;
    case 2: CheckPartialFailure(provider); break;
    case 3: CheckFinalSuccess(provider); break;
    }
}
