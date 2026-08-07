// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_TAPLEAF_0XC2_H
#define BITCOIN_TEST_FUZZ_UTIL_TAPLEAF_0XC2_H

#include <script/interpreter.h>
#include <script/op_tx.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <test/util/tapleaf_0xc2.h>
#include <util/check.h>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace test::tapleaf_0xc2::fuzz {

using test::tapleaf_0xc2::Stack;

/** What a run exposes: its result, error, varops consumed and final stack. */
struct Outcome {
    bool ok{false};
    //! The run stopped early at an upgradable success, such as a reserved OP_TX selector.
    bool immediate_success{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t consumed{0};
    Stack stack;

    bool operator==(const Outcome&) const = default;
};

/**
 * Checker whose signature, locktime and sequence results the fuzzer chooses, as
 * in the signature_checker target. Results are read from fixed bits in call
 * order, so a rerun sees the same results. OP_TX reads tx_data.
 */
class FuzzedChecker final : public BaseSignatureChecker
{
    const uint64_t m_results;
    const std::optional<op_tx::TxView> m_tx_data;
    mutable unsigned m_calls{0};

    bool Next() const { return (m_results >> (m_calls++ % 64)) & 1; }

public:
    FuzzedChecker(uint64_t results, std::optional<op_tx::TxView> tx_data)
        : m_results{results}, m_tx_data{tx_data} {}

    bool CheckSchnorrSignature(std::span<const unsigned char>, std::span<const unsigned char>, SigVersion,
                               ScriptExecutionData&, ScriptError* serror) const override
    {
        if (Next()) return true;
        if (serror) *serror = SCRIPT_ERR_SCHNORR_SIG;
        return false;
    }
    bool CheckLockTime(const CScriptNum&) const override { return Next(); }
    bool CheckSequence(const CScriptNum&) const override { return Next(); }
    std::optional<op_tx::TxView> GetOpTxView() const override { return m_tx_data; }
};

inline Stack ConsumeStack(FuzzedDataProvider& provider, size_t max_items = 8, size_t max_size = 256)
{
    Stack stack(provider.ConsumeIntegralInRange<size_t>(0, max_items));
    for (auto& value : stack) value = ConsumeRandomLengthByteVector(provider, max_size);
    return stack;
}

/**
 * Check that the budget only decides whether a run can pay for itself. A
 * successful run is identical with any budget that covers its consumption and
 * fails with SCRIPT_ERR_VAROP_COUNT with any budget that does not. A failing run
 * need not deduct its charges; with a smaller budget it fails the same way, or
 * for lack of budget. run(budget) must be deterministic, and budget at most cap.
 * Returns the run at cap.
 */
template <typename Run>
Outcome CheckBudget(const Run& run, uint64_t cap, uint64_t budget)
{
    const Outcome full{run(cap)};
    Assert(full.ok == (full.error == SCRIPT_ERR_OK));
    if (!full.ok) {
        const ScriptError error{run(budget).error};
        Assert(error == full.error || error == SCRIPT_ERR_VAROP_COUNT);
        return full;
    }
    Assert(run(full.consumed) == full);
    if (full.consumed > 0) Assert(run(full.consumed - 1).error == SCRIPT_ERR_VAROP_COUNT);
    if (budget < full.consumed) Assert(run(budget).error == SCRIPT_ERR_VAROP_COUNT);
    return full;
}

/** Check a stack's size accounting and value storage after a successful run. */
inline void CheckStackAccounting(const ValtypeStack& stack)
{
    size_t total{0};
    for (const auto& value : stack.GetStack()) {
        // Values have capacity for their word padding, and at most twice that.
        const size_t padded{biguint::WordPaddedCapacity(value.size())};
        Assert(padded <= value.capacity() && value.capacity() <= 2 * padded);
        Assert(value.size() <= stack.GetMaxElementSize());
        total += value.size();
    }
    Assert(stack.GetTotalSize() == total);
    Assert(stack.size() <= size_t{MAX_TAPLEAF_0XC2_STACK_SIZE});
    Assert(total <= size_t{MAX_TAPLEAF_0XC2_TOTAL_STACK_SIZE});
    Assert(stack.GetMaxElementSize() <= size_t{MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE});
}

} // namespace test::tapleaf_0xc2::fuzz

#endif // BITCOIN_TEST_FUZZ_UTIL_TAPLEAF_0XC2_H
