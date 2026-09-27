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
constexpr uint64_t FixedOpcodeCost() { return 382; }
constexpr uint64_t PrepCost(size_t bytes) { return 233 + WordSpan(bytes); }
#ifdef GSR_PRODUCER_LIFETIME_EXPERIMENT
// Provisional measurement-derived schedule, isolated from ordinary builds.
inline constexpr bool PRODUCER_LIFETIME_EXPERIMENT{true};
constexpr uint64_t ProduceCost(size_t bytes) { return 639 + 6 * static_cast<uint64_t>(bytes); }
constexpr uint64_t NormalizeCost(size_t bytes) { return 766 + WordSpan(bytes); }
constexpr uint64_t OutputCost(size_t bytes) { return ProduceCost(WordSpan(bytes)) + NormalizeCost(bytes); }
constexpr uint64_t CopyCost(size_t bytes) { return ProduceCost(bytes); }
constexpr uint64_t ReleaseCost(size_t) { return 0; }
#else
inline constexpr bool PRODUCER_LIFETIME_EXPERIMENT{false};
constexpr uint64_t OutputCost(size_t bytes) { return 1209 + 4 * WordSpan(bytes); }
constexpr uint64_t CopyCost(size_t bytes) { return 668 + 2 * static_cast<uint64_t>(bytes); }
constexpr uint64_t ReleaseCost(size_t bytes) { return bytes == 0 ? 0 : 963 + 3 * WordSpan(bytes); }
#endif
constexpr uint64_t ReadCost(size_t bytes) { return 89 + 3 * WordSpan(bytes); }
constexpr uint64_t ArithCost(size_t bytes) { return 51 + 4 * static_cast<uint64_t>(bytes); }
constexpr uint64_t BitCost(size_t bytes) { return 74 + static_cast<uint64_t>(bytes); }
constexpr uint64_t MoveCost(size_t entries) { return 255 + 18 * static_cast<uint64_t>(entries); }
constexpr uint64_t MulRowCost(size_t limbs) { return 34 + 14 * static_cast<uint64_t>(limbs); }
constexpr uint64_t DivCoreCost(size_t steps, size_t divisor_limbs)
{
    return 1574 + 267 * static_cast<uint64_t>(steps) * divisor_limbs;
}
constexpr uint64_t Sha256Cost(size_t bytes) { return 2943 + 48 * static_cast<uint64_t>(bytes); }
constexpr uint64_t Ripemd160Cost(size_t bytes) { return 2555 + 40 * static_cast<uint64_t>(bytes); }
constexpr uint64_t Sha1Cost(size_t bytes) { return 1516 + 25 * static_cast<uint64_t>(bytes); }
constexpr uint64_t SignatureCost() { return 500'000; }
constexpr uint64_t TweakCost() { return 140839; }
constexpr uint64_t TxSelectCost(size_t items) { return 3234 + 645 * static_cast<uint64_t>(items); }
constexpr uint64_t MacroDecodeCost(size_t bytes) { return 2 + 55 * static_cast<uint64_t>(bytes); }
constexpr uint64_t ScalarOutputCost() { return OutputCost(8); }

// The quadratic charge dominates. Both numeric operands are at most 4 MB.
constexpr uint64_t MAX_V2_LIMBS{WordSpan(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) / 8};
static_assert(MAX_V2_LIMBS <=
              (std::numeric_limits<uint64_t>::max() - DivCoreCost(0, 0)) /
                  (DivCoreCost(1, 1) - DivCoreCost(0, 0)) / MAX_V2_LIMBS);

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

// Varops cost categories per byte:
// Fast operations: comparing bytes, comparing bytes against zero, and zeroing bytes
static constexpr uint64_t COST_FAST = 2;
// Copying bytes: slightly more expensive than fast operations due to memory allocation overhead
static constexpr uint64_t COST_COPYING = 3;
// Everything else
static constexpr uint64_t COST_OTHER = 4;
// Arithmetic operations (add/subtract inner loop)
static constexpr uint64_t COST_ARITH = 6;
// Multiplication quadratic term: inner loop cost with overhead multiplier
static constexpr uint64_t COST_MUL_QUAD = 27;
// OP_ROLL: per stack element moved (24 bytes per std::vector * COST_FAST)
static constexpr uint64_t COST_ROLL = 48;
// All hash operations
static constexpr uint64_t COST_HASH = 50;

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

namespace detail {

constexpr uint64_t ToCostSize(size_t size)
{
    return static_cast<uint64_t>(size);
}

constexpr uint64_t WordSize(size_t size)
{
    return WordSpan(size);
}

constexpr uint64_t MaxWordSize(size_t size1, size_t size2)
{
    return std::max(WordSize(size1), WordSize(size2));
}

constexpr uint64_t MinWordSize(size_t size1, size_t size2)
{
    return std::min(WordSize(size1), WordSize(size2));
}

// BIP 441 costs are maximal when every operand has the maximum permitted size.
constexpr uint64_t MAX_COST_SIZE{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE};
constexpr uint64_t MAX_U64{std::numeric_limits<uint64_t>::max()};
constexpr uint64_t MAX_COST_WORD_SIZE{WordSize(MAX_COST_SIZE)};
constexpr uint64_t MAX_MUL_COPY_COST{2 * MAX_COST_SIZE * COST_COPYING};
constexpr uint64_t MAX_DIV_SQUARE{MAX_COST_WORD_SIZE * MAX_COST_WORD_SIZE};
constexpr uint64_t MAX_DIV_QUADRATIC{MAX_DIV_SQUARE * 2 / 3};

// These bounds prove that every intermediate in the maximum-size BIP 441 cost
// expressions fits in uint64_t, not merely each final result.
static_assert(MAX_COST_SIZE <= MAX_U64 - 7);
static_assert(MAX_COST_SIZE <= MAX_U64 / (2 * COST_COPYING));
static_assert(MAX_COST_WORD_SIZE / 8 <=
                  (MAX_U64 - MAX_MUL_COPY_COST) / COST_MUL_QUAD / MAX_COST_WORD_SIZE,
              "maximum OP_MUL cost must fit in uint64_t");
static_assert(MAX_COST_WORD_SIZE <= MAX_U64 / MAX_COST_WORD_SIZE);
static_assert(MAX_DIV_SQUARE <= MAX_U64 / 2);
static_assert(MAX_COST_WORD_SIZE <=
                  (MAX_U64 - MAX_DIV_QUADRATIC) / (3 * COST_ARITH + COST_OTHER),
              "maximum OP_DIV and OP_MOD cost must fit in uint64_t");

} // namespace detail

/** Pure cost calculations taking operand sizes in bytes. */
constexpr uint64_t LengthConversionCost(size_t size)
{
    return detail::WordSize(size) * COST_FAST;
}

constexpr uint64_t CompareZeroCost(size_t size)
{
    return detail::WordSize(size) * COST_FAST;
}

constexpr uint64_t ComparisonCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * COST_FAST;
}

constexpr uint64_t AddCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * (COST_ARITH + COST_COPYING);
}

constexpr uint64_t SubCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * COST_ARITH;
}

constexpr uint64_t MulCost(size_t size1, size_t size2)
{
    const uint64_t copy_cost{(detail::ToCostSize(size1) + detail::ToCostSize(size2)) * COST_COPYING};
    const uint64_t quadratic_cost{detail::WordSize(size1) / 8 * detail::WordSize(size2) * COST_MUL_QUAD};
    return copy_cost + quadratic_cost;
}

constexpr uint64_t DivCost(size_t size1, size_t size2)
{
    const uint64_t s1{detail::WordSize(size1)};
    const uint64_t s2{detail::WordSize(size2)};
    const uint64_t linear_cost{s1 * (3 * COST_ARITH) + s2 * COST_OTHER};
    const uint64_t quadratic_cost{s1 * s1 * 2 / 3};
    return linear_cost + quadratic_cost;
}

constexpr uint64_t ModCost(size_t size1, size_t size2)
{
    // OP_MOD uses the same division algorithm and cost model as OP_DIV.
    return DivCost(size1, size2);
}

constexpr uint64_t BoolAndCost(size_t size1, size_t size2)
{
    return (detail::WordSize(size1) + detail::WordSize(size2)) * COST_FAST; // COMPARINGZERO both operands
}

constexpr uint64_t BoolOrCost(size_t size1, size_t size2)
{
    return (detail::WordSize(size1) + detail::WordSize(size2)) * COST_FAST; // COMPARINGZERO both operands
}

constexpr uint64_t WithinCost(size_t size1, size_t size2, size_t size3)
{
    // Two comparisons: v1 vs v2, v1 vs v3
    return detail::MaxWordSize(size1, size2) * COST_FAST + detail::MaxWordSize(size1, size3) * COST_FAST;
}

constexpr uint64_t InvertCost(size_t size)
{
    return detail::WordSize(size) * COST_OTHER;
}

constexpr uint64_t ByteReverseCost(size_t size)
{
    return detail::WordSize(size) * COST_OTHER;
}

constexpr uint64_t AndCost(size_t size1, size_t size2)
{
    // min * COST_OTHER + (max - min) * COST_FAST simplifies to this expression.
    return (detail::WordSize(size1) + detail::WordSize(size2)) * COST_FAST;
}

constexpr uint64_t OrCost(size_t size1, size_t size2)
{
    return detail::MinWordSize(size1, size2) * COST_OTHER;
}

constexpr uint64_t XorCost(size_t size1, size_t size2)
{
    return detail::MinWordSize(size1, size2) * COST_OTHER;
}

constexpr uint64_t MinMaxCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * COST_OTHER;
}

constexpr uint64_t TwoMulCost(size_t size)
{
    return detail::WordSize(size) * (COST_COPYING + COST_OTHER);
}

constexpr uint64_t TwoDivCost(size_t size)
{
    return detail::WordSize(size) * COST_OTHER;
}

constexpr uint64_t UnalignedUpShiftCost(size_t size, size_t prepended_bytes)
{
    return detail::WordSize(detail::ToCostSize(size) + detail::ToCostSize(prepended_bytes)) * COST_OTHER;
}

constexpr uint64_t ChecksigAddIncrementCost(size_t number_size)
{
    return std::max(detail::WordSize(1), detail::WordSize(number_size)) * (COST_ARITH + COST_COPYING);
}

} // namespace varops

#endif // BITCOIN_SCRIPT_VAROPS_H
