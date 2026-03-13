// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAROPS_H
#define BITCOIN_SCRIPT_VAROPS_H

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace varops {

// Varops cost categories per byte:
// Fast operations: comparing bytes, comparing bytes against zero, and zeroing bytes
static constexpr int COST_FAST = 2;
// Copying bytes: slightly more expensive than fast operations due to memory allocation overhead
static constexpr int COST_COPYING = 3;
// Everything else
static constexpr int COST_OTHER = 4;
// Arithmetic operations (add/subtract inner loop)
static constexpr int COST_ARITH = 6;
// Multiplication quadratic term: inner loop cost with overhead multiplier
static constexpr int COST_MUL_QUAD = 27;
// OP_ROLL: per stack element moved (24 bytes per std::vector * COST_FAST)
static constexpr int COST_ROLL = 48;
// Hashing operations
static constexpr int COST_HASH = 50;

// A per-transaction budget is determined by multiplying the
// total transaction weight by the fixed factor 10,000.
static constexpr int BUDGET_PER_BYTE = 10'000;

// BIP#ops: Signature operations cost BUDGET_PER_BYTE * VALIDATION_WEIGHT_PER_SIGOP_PASSED
// (10,000 * 50 = 500,000 varops units). VALIDATION_WEIGHT_PER_SIGOP_PASSED is defined
// in script.h; we use the literal here to avoid a heavyweight include dependency.
static constexpr int COST_PER_SIGOP = BUDGET_PER_BYTE * 50;

// Pure cost-calculation functions taking operand byte-sizes, returning size_t.

inline size_t mul_cost(size_t size1, size_t size2) {
    // (COPYING + quadratic MUL_QUAD)
    return (size1 + size2) * COST_COPYING
        + (size1 + 7) / 8 * uint64_t(size2) * COST_MUL_QUAD;
}

inline size_t div_cost(size_t size1, size_t size2) {
    return size1 * (3 * COST_ARITH) + size2 * COST_OTHER
        + uint64_t(size1) * uint64_t(size1) * 2 / 3;
}

inline size_t mod_cost(size_t size1, size_t size2) {
    return size1 * (3 * COST_ARITH) + size2 * COST_OTHER
        + uint64_t(size1) * uint64_t(size1) * 2 / 3;
}

inline size_t booland_cost(size_t size1, size_t size2) {
    return (size1 + size2) * COST_FAST; // COMPARINGZERO both operands
}

inline size_t boolor_cost(size_t size1, size_t size2) {
    return (size1 + size2) * COST_FAST; // COMPARINGZERO both operands
}

inline size_t within_cost(size_t size1, size_t size2, size_t size3) {
    // Two comparisons: v1 vs v2, v1 vs v3
    return std::max(size1, size2) * COST_FAST + std::max(size1, size3) * COST_FAST;
}

inline size_t or_cost(size_t size1, size_t size2) {
    return std::min(size1, size2) * COST_OTHER;
}

inline size_t xor_cost(size_t size1, size_t size2) {
    return std::min(size1, size2) * COST_OTHER;
}

inline size_t checksigadd_incr_cost(size_t num_size) {
    return std::max(size_t(1), num_size) * (COST_ARITH + COST_COPYING);
}

} // namespace varops

#endif // BITCOIN_SCRIPT_VAROPS_H
