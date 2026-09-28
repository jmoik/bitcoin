// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAROPS_H
#define BITCOIN_SCRIPT_VAROPS_H

#include <script/script.h>
#include <util/check.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

class ValtypeStack;

namespace varops {

/** Whole-varop prices of the BIP 440 work classes. Byte arguments are logical sizes. */
constexpr uint64_t WordSpan(size_t bytes) { return (static_cast<uint64_t>(bytes) + 7) / 8 * 8; }
// Four-machine coefficientwise maximum at 0.9x each machine's pre-v2 reference:
// flats rounded up to 50, variable rates to whole varops.
constexpr uint64_t FixedOpcodeCost() { return 350; }
constexpr uint64_t PrepCost(size_t bytes) { return 300 + WordSpan(bytes); }
constexpr uint64_t ProduceCost(size_t bytes) { return 1600 + 7 * static_cast<uint64_t>(bytes); }
constexpr uint64_t NormalizeCost(size_t bytes) { return 350 + 2 * WordSpan(bytes); }
constexpr uint64_t OutputCost(size_t bytes) { return ProduceCost(WordSpan(bytes)) + NormalizeCost(bytes); }
constexpr uint64_t CopyCost(size_t bytes) { return ProduceCost(bytes); }
constexpr uint64_t ReadCost(size_t bytes) { return 200 + 4 * WordSpan(bytes); }
// ARITH: word passes with a carry or borrow chain; BIT: word passes without one.
constexpr uint64_t ArithCost(size_t bytes) { return 300 + 5 * static_cast<uint64_t>(bytes); }
constexpr uint64_t BitCost(size_t bytes) { return 100 + 2 * static_cast<uint64_t>(bytes); }
constexpr uint64_t MoveCost(size_t entries) { return 300 + 25 * static_cast<uint64_t>(entries); }
/** Complete prepared OP_MUL: schoolbook rows over the longer operand's limbs, each
 *  multiplying the shorter operand's limbs, including internal scratch storage. */
constexpr uint64_t MulCost(uint64_t rows, uint64_t row_limbs)
{
    return 1450 + 41 * rows + 42 * rows * row_limbs;
}
constexpr uint64_t DivCoreCost(size_t steps, size_t divisor_limbs)
{
    return 11050 + 580 * static_cast<uint64_t>(steps) + 255 * static_cast<uint64_t>(steps) * divisor_limbs;
}
/** DIVCORE quotient rows for limb counts of the operands without trailing zero bytes. */
constexpr uint64_t DivSteps(uint64_t dividend_limbs, uint64_t divisor_limbs)
{
    // One row per quotient limb, plus one for a dividend limb added by divisor normalization.
    // A shorter dividend still takes one row to compare the operands.
    return dividend_limbs + 2 > divisor_limbs ? dividend_limbs + 2 - divisor_limbs : 1;
}
/** Bytes processed by a hash with 64-byte blocks (SHA1, SHA256, RIPEMD160): the
 *  message plus at least 9 bytes of padding and length, rounded up to whole blocks. */
constexpr uint64_t HashBlockSpan(size_t bytes) { return (static_cast<uint64_t>(bytes) + 72) / 64 * 64; }
constexpr uint64_t Sha256Cost(size_t bytes) { return 450 + 57 * HashBlockSpan(bytes); }
constexpr uint64_t Ripemd160Cost(size_t bytes) { return 200 + 44 * HashBlockSpan(bytes); }
constexpr uint64_t Sha1Cost(size_t bytes) { return 200 + 28 * HashBlockSpan(bytes); }
constexpr uint64_t SignatureCost() { return 500'000; }
constexpr uint64_t TweakCost() { return 168200; }
// Interim OP_BYTEREV price from the measured byte-wise reversal (covenant opcode BIP).
constexpr uint64_t ByteReverseCost(size_t bytes) { return 150 + 7 * static_cast<uint64_t>(bytes); }
// OP_TX draft: selector decoding plus locating and encoding k selected values
// or aggregate-scanned records. Provisional pending calibration.
constexpr uint64_t TxSelectCost(size_t items) { return 3250 + 645 * static_cast<uint64_t>(items); }
// Reusable macros draft: unrolling charge per substituted instruction and per
// visited reference. Provisional pending calibration.
constexpr uint64_t MacroUnrollCost() { return FixedOpcodeCost(); }
constexpr uint64_t ScalarOutputCost() { return OutputCost(8); }

// Charges are computed in uint64_t. Each opcode sums a bounded number of the
// terms below, so bounding the superlinear ones shows no charge can wrap.
// Both numeric operands are at most 4 MB, so DivSteps is at most MAX_V2_LIMBS + 2.
constexpr uint64_t MAX_V2_LIMBS{WordSpan(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) / 8};
static_assert(MAX_V2_LIMBS + 2 <=
              (std::numeric_limits<uint64_t>::max() - DivCoreCost(0, 0)) /
                  (DivCoreCost(1, MAX_V2_LIMBS) - DivCoreCost(0, 0)),
              "maximum OP_DIV and OP_MOD charge must fit in uint64_t");
// OP_MUL: MUL plus production of the full product span, both operands maximal.
constexpr uint64_t MAX_MUL_STORAGE_CHARGE{CopyCost(2 * MAX_V2_LIMBS * 8)};
static_assert(MAX_V2_LIMBS <= (std::numeric_limits<uint64_t>::max() - MulCost(0, 0) - MAX_MUL_STORAGE_CHARGE) /
                                  (MulCost(1, MAX_V2_LIMBS) - MulCost(0, 0)),
              "maximum OP_MUL charge must fit in uint64_t");

/** Hash work only; result construction is charged separately. */
constexpr uint64_t HashCost(opcodetype opcode, size_t input_bytes)
{
    switch (opcode) {
    case OP_SHA256: return Sha256Cost(input_bytes);
    case OP_HASH160: return Sha256Cost(input_bytes) + Ripemd160Cost(32);
    case OP_RIPEMD160: return Ripemd160Cost(input_bytes);
    case OP_SHA1: return Sha1Cost(input_bytes);
    case OP_HASH256: return Sha256Cost(input_bytes) + Sha256Cost(32);
    default: return 0;
    }
}

// Every logical opcode pays F before data-dependent work.
static constexpr uint64_t COST_PER_OPCODE = FixedOpcodeCost();

constexpr uint64_t ExecutionCost(opcodetype)
{
    return FixedOpcodeCost();
}

/** Thread-safe varops budget shared by script checks for one transaction. */
class Budget final
{
private:
    /** std::nullopt represents evaluation without varops metering. */
    std::optional<std::atomic<uint64_t>> m_remaining;

    Budget() = default;

public:
    explicit Budget(uint64_t remaining) : m_remaining{std::in_place, remaining} {}

    /** Use when standalone evaluation lacks transaction-wide budget context. */
    static Budget Unmetered() { return {}; }

    /** Return true if cost was charged; false if the bounded budget was exhausted. */
    [[nodiscard]] bool Spend(uint64_t cost)
    {
        if (!m_remaining || cost == 0) return true;
        // Only the counter value is synchronized; it does not publish other state.
        uint64_t remaining{m_remaining->load(std::memory_order_relaxed)};
        while (true) {
            if (cost > remaining) return false;
            if (m_remaining->compare_exchange_weak(remaining, remaining - cost,
                                                   std::memory_order_relaxed,
                                                   std::memory_order_relaxed)) {
                return true;
            }
        }
    }

    std::optional<uint64_t> Remaining() const
    {
        if (!m_remaining) return std::nullopt;
        return m_remaining->load(std::memory_order_relaxed);
    }
};

/**
 * Accumulate the whole-varop charges for one logical opcode. Spend() deducts
 * only the amount added since its previous call.
 */
class Meter final
{
private:
    uint64_t m_total{0};
    uint64_t m_deducted{0};

public:
    void Add(uint64_t added)
    {
        m_total += added;
    }

    [[nodiscard]] bool Spend(Budget& budget)
    {
        const uint64_t deduction{m_total - m_deducted};
        if (!budget.Spend(deduction)) return false;
        m_deducted = m_total;
        return true;
    }

    uint64_t Total() const { return m_total; }
};

/**
 * Benchmark-only observation hook. Runtime code reports completed logical
 * charges; the benchmark derives expected feature counts independently.
 */
class CostAudit
{
public:
    virtual ~CostAudit() = default;
    virtual void BeginOpcode(opcodetype opcode, const ValtypeStack& stack,
                             const ValtypeStack& altstack, opcodetype target) = 0;
    virtual void EndOpcode(opcodetype opcode, const ValtypeStack& stack,
                           const ValtypeStack& altstack, opcodetype target,
                           uint64_t actual_charge) = 0;
    virtual void StandaloneCharge(opcodetype opcode, uint64_t feature_units,
                                  uint64_t actual_charge) = 0;
    virtual void FinalCheck(size_t value_size, uint64_t actual_charge) = 0;
    virtual void InitialStack(const ValtypeStack&, uint64_t) {}
};

inline thread_local CostAudit* g_cost_audit{nullptr};

class ScopedCostAudit final
{
private:
    CostAudit* m_previous;

public:
    explicit ScopedCostAudit(CostAudit* audit)
        : m_previous{g_cost_audit}
    {
        g_cost_audit = audit;
    }

    ~ScopedCostAudit() { g_cost_audit = m_previous; }

    ScopedCostAudit(const ScopedCostAudit&) = delete;
    ScopedCostAudit& operator=(const ScopedCostAudit&) = delete;
};

// A per-transaction budget is determined by multiplying the
// total transaction weight by the fixed factor 10,000.
static constexpr uint64_t BUDGET_PER_WEIGHT_UNIT = 10'000;

inline constexpr uint64_t TxBudget(int64_t weight)
{
    Assume(weight >= 0);
    return static_cast<uint64_t>(weight) * BUDGET_PER_WEIGHT_UNIT;
}

// The signature charge is in addition to opcode dispatch and message hashing.
static constexpr uint64_t COST_PER_SIGOP = SignatureCost();
static_assert(COST_PER_SIGOP == BUDGET_PER_WEIGHT_UNIT * VALIDATION_WEIGHT_PER_SIGOP_PASSED);

constexpr uint64_t SigcheckCost(opcodetype)
{
    return COST_PER_SIGOP;
}

} // namespace varops

#endif // BITCOIN_SCRIPT_VAROPS_H
