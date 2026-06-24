// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Runs arbitrary Tapscript v2 scripts, as eval_script does for older script
// versions, with fuzzer-chosen flags, witness stack and checker results. There is
// no model of the opcodes: expected values come from the vectors and unit tests.
// This target checks what holds for every script: the budget only decides
// whether a run can pay for itself, flags are monotonic as in script_flags, the
// stack's accounting holds after success, and spending the script through
// VerifyScript gives the same result.

#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util/tapscript_v2.h>
#include <test/util/tapscript_v2.h>
#include <uint256.h>
#include <util/check.h>

#include <cstdint>
#include <vector>

using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

namespace {
//! Weight of other inputs that fund this script through the transaction's
//! budget. 20,000 weight units reach every stack limit and keep runs short.
constexpr uint32_t MAX_EXTRA_WEIGHT{20'000};
} // namespace

FUZZ_TARGET(tapscript_v2_eval)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto flags{script_verify_flags::from_int(provider.ConsumeIntegral<script_verify_flags::value_type>())};
    const auto other_flags{script_verify_flags::from_int(provider.ConsumeIntegral<script_verify_flags::value_type>())};
    const uint64_t checker_results{provider.ConsumeIntegral<uint64_t>()};
    const uint64_t budget_seed{provider.ConsumeIntegral<uint64_t>()};

    const uint32_t extra_weight{provider.ConsumeIntegralInRange<uint32_t>(0, MAX_EXTRA_WEIGHT)};
    const Stack witness{ConsumeStack(provider)};
    const std::vector<unsigned char> script_bytes{provider.remaining_bytes() ? provider.ConsumeRemainingBytes<unsigned char>()
                                                                               : std::vector<unsigned char>{}};
    const CScript script{script_bytes.begin(), script_bytes.end()};

    // Commit to the script in a single-leaf Taproot output, spent by the
    // smallest transaction.
    CScript script_pub_key;
    const CScriptWitness spend_witness{BuildTapscriptV2Witness(script, witness, script_pub_key)};
    CMutableTransaction mutable_spend;
    mutable_spend.vin.resize(1);
    mutable_spend.vin[0].scriptWitness = spend_witness;
    mutable_spend.vout.emplace_back(0, script_pub_key);
    const CTransaction spend{mutable_spend};
    const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT_V2, script)};
    // The transaction's budget caps the runs, so their time is bounded as it is
    // in validation.
    const uint64_t cap{varops::TxBudget(GetTransactionWeight(spend) + int64_t{extra_weight})};

    const auto run{[&](uint64_t budget, script_verify_flags run_flags) {
        // What script path validation knows about the leaf.
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash = leaf_hash;
        execdata.m_tapleaf_hash_init = true;
        const FuzzedChecker checker{checker_results};
        varops::Budget varops_budget{budget};
        ValtypeStack stack{witness};
        Outcome outcome;
        outcome.ok = EvalTapscriptV2(stack, script, run_flags, checker, execdata, varops_budget,
                                     &outcome.error, &outcome.immediate_success);
        if (outcome.ok) CheckStackAccounting(stack);
        if (outcome.ok && !outcome.immediate_success) {
            outcome.ok = CheckTapscriptV2ScriptResult(stack, varops_budget, &outcome.error);
        }
        outcome.consumed = budget - varops_budget.Remaining();
        outcome.stack = stack.GetStack();
        return outcome;
    }};

    const Outcome full{CheckBudget([&](uint64_t budget) { return run(budget, flags); }, cap, budget_seed % (cap + 1))};

    // As in script_flags: removing flags keeps a success, and adding flags keeps a failure.
    Assert(run(cap, full.ok ? flags & ~other_flags : flags | other_flags).ok == full.ok);

    // Spending the output adds only the commitment and witness checks, which pass.
    const FuzzedChecker checker{checker_results};
    varops::Budget budget{cap};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const script_verify_flags spend_flags{(flags & ~SCRIPT_VERIFY_DISCOURAGE_SCRIPT_RESTORATION) | TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS};
    Assert(VerifyScript(CScript{}, script_pub_key, &spend_witness, spend_flags, checker, &error, budget) == full.ok);
    Assert(error == full.error);
    Assert(cap - budget.Remaining() == full.consumed);
}
