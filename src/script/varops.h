// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAROPS_H
#define BITCOIN_SCRIPT_VAROPS_H

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <script/script.h>
#include <util/check.h>

namespace varops {

static constexpr uint64_t UNLIMITED_BUDGET = std::numeric_limits<uint64_t>::max();

/** Thread-safe varops budget shared by script checks for one transaction. */
class Budget final
{
private:
    std::atomic<uint64_t> m_remaining;

public:
    explicit Budget(uint64_t remaining) : m_remaining{remaining} {}

    /** Return true if cost was charged; false if the bounded budget was exhausted. */
    [[nodiscard]] bool Spend(uint64_t cost)
    {
        if (cost == 0) return true;
        uint64_t remaining{m_remaining.load(std::memory_order_relaxed)};
        while (true) {
            if (remaining == UNLIMITED_BUDGET) return true;
            if (cost > remaining) return false;
            if (m_remaining.compare_exchange_weak(remaining, remaining - cost,
                                                  std::memory_order_relaxed,
                                                  std::memory_order_relaxed)) {
                return true;
            }
        }
    }

    uint64_t Remaining() const { return m_remaining.load(std::memory_order_relaxed); }
};

inline Budget UnlimitedBudget()
{
    return Budget{UNLIMITED_BUDGET};
}

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
// Hashing operations
static constexpr uint64_t COST_HASH = 50;

// A per-transaction budget is determined by multiplying the
// total transaction weight by the fixed factor 10,000.
static constexpr uint64_t BUDGET_PER_WEIGHT_UNIT = 10'000;

inline constexpr uint64_t TxBudget(int64_t weight)
{
    Assume(weight >= 0);
    return static_cast<uint64_t>(weight) * BUDGET_PER_WEIGHT_UNIT;
}

// BIP 440: Signature operations cost BUDGET_PER_WEIGHT_UNIT * VALIDATION_WEIGHT_PER_SIGOP_PASSED
// (10,000 * 50 = 500,000 varops units).
static constexpr uint64_t COST_PER_SIGOP = BUDGET_PER_WEIGHT_UNIT * VALIDATION_WEIGHT_PER_SIGOP_PASSED;

inline uint64_t cost_size(size_t size) {
    return static_cast<uint64_t>(size);
}

inline uint64_t word_size(size_t size) {
    const uint64_t s{cost_size(size)};
    return (s + 7) / 8 * 8;
}

inline uint64_t max_word_size(size_t size1, size_t size2) {
    return std::max(word_size(size1), word_size(size2));
}

inline uint64_t min_word_size(size_t size1, size_t size2) {
    return std::min(word_size(size1), word_size(size2));
}

// Pure cost-calculation functions taking operand byte-sizes, returning uint64_t.

inline uint64_t lengthconv_cost(size_t size) {
    return word_size(size) * COST_FAST;
}

inline uint64_t comparingzero_cost(size_t size) {
    return word_size(size) * COST_FAST;
}

inline uint64_t comparing_cost(size_t size1, size_t size2) {
    return max_word_size(size1, size2) * COST_FAST;
}

inline uint64_t add_cost(size_t size1, size_t size2) {
    return max_word_size(size1, size2) * (COST_ARITH + COST_COPYING);
}

inline uint64_t sub_cost(size_t size1, size_t size2) {
    return max_word_size(size1, size2) * COST_ARITH;
}

inline uint64_t mul_cost(size_t size1, size_t size2) {
    // (COPYING + quadratic MUL_QUAD)
    // Both operands are processed at 64-bit (8-byte) word granularity.
    return (cost_size(size1) + cost_size(size2)) * COST_COPYING
        + word_size(size1) / 8 * word_size(size2) * COST_MUL_QUAD;
}

inline uint64_t div_cost(size_t size1, size_t size2) {
    const uint64_t s1{word_size(size1)};
    const uint64_t s2{word_size(size2)};
    return s1 * (3 * COST_ARITH) + s2 * COST_OTHER
        + s1 * s1 * 2 / 3;
}

inline uint64_t mod_cost(size_t size1, size_t size2) {
    // OP_MOD uses the same division algorithm and cost model as OP_DIV.
    return div_cost(size1, size2);
}

namespace detail {

// BIP 441 costs are maximal when every operand has the maximum permitted size.
constexpr uint64_t MAX_COST_SIZE{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE};
constexpr uint64_t MAX_U64{std::numeric_limits<uint64_t>::max()};
constexpr uint64_t MAX_COST_WORD_SIZE{(MAX_COST_SIZE + 7) / 8 * 8};
constexpr uint64_t MAX_MUL_COPY_COST{2 * MAX_COST_SIZE * COST_COPYING};
constexpr uint64_t MAX_DIV_SQUARE{MAX_COST_WORD_SIZE * MAX_COST_WORD_SIZE};
constexpr uint64_t MAX_DIV_QUADRATIC{MAX_DIV_SQUARE * 2 / 3};

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

inline uint64_t booland_cost(size_t size1, size_t size2) {
    return (word_size(size1) + word_size(size2)) * COST_FAST; // COMPARINGZERO both operands
}

inline uint64_t boolor_cost(size_t size1, size_t size2) {
    return (word_size(size1) + word_size(size2)) * COST_FAST; // COMPARINGZERO both operands
}

inline uint64_t within_cost(size_t size1, size_t size2, size_t size3) {
    // Two comparisons: v1 vs v2, v1 vs v3
    return max_word_size(size1, size2) * COST_FAST + max_word_size(size1, size3) * COST_FAST;
}

inline uint64_t invert_cost(size_t size) {
    return word_size(size) * COST_OTHER;
}

inline uint64_t and_cost(size_t size1, size_t size2) {
    return (word_size(size1) + word_size(size2)) * COST_FAST;
}

inline uint64_t or_cost(size_t size1, size_t size2) {
    return min_word_size(size1, size2) * COST_OTHER;
}

inline uint64_t xor_cost(size_t size1, size_t size2) {
    return min_word_size(size1, size2) * COST_OTHER;
}

inline uint64_t minmax_cost(size_t size1, size_t size2) {
    return max_word_size(size1, size2) * COST_OTHER;
}

inline uint64_t twomul_cost(size_t size) {
    return word_size(size) * (COST_COPYING + COST_OTHER);
}

inline uint64_t twodiv_cost(size_t size) {
    return word_size(size) * COST_OTHER;
}

inline uint64_t upshift_bitshift_cost(size_t size, size_t prebytes) {
    return word_size(cost_size(size) + cost_size(prebytes)) * COST_OTHER;
}

inline uint64_t checksigadd_incr_cost(size_t num_size) {
    return std::max(word_size(1), word_size(num_size)) * (COST_ARITH + COST_COPYING);
}

} // namespace varops

#endif // BITCOIN_SCRIPT_VAROPS_H
