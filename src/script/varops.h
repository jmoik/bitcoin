// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAROPS_H
#define BITCOIN_SCRIPT_VAROPS_H

#include <script/script.h>
#include <util/check.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace varops {

/** Bytes in the 64-bit words that hold a value of the given size. */
constexpr uint64_t WordSpan(size_t bytes) { return (static_cast<uint64_t>(bytes) + 7) / 8 * 8; }

// Prices of the BIP 440 cost primitives. Byte arguments are logical sizes; size
// rates apply to the padded span the work processes: W(n) bytes, or H(n) for hashes.

// Every logical opcode pays BASE, which includes checking its charges against the budget.
constexpr uint64_t BaseCost() { return 300; }
// READ: converting or inspecting an operand.
constexpr uint64_t ReadCost(size_t bytes) { return 350 + 2 * WordSpan(bytes); }
// WRITE: producing a stack value, numeric or not. Values are allocated with
// capacity for their word padding.
constexpr uint64_t WriteCost(size_t bytes) { return 800 + 7 * WordSpan(bytes); }
// ARITH: a pass over 64-bit words, with or without a carry chain.
constexpr uint64_t ArithCost(size_t bytes) { return 200 + 3 * WordSpan(bytes); }
// MOVE: taking the top k entries off a stack and putting back some or all of
// them, in any order and on either stack.
constexpr uint64_t MoveCost(size_t entries) { return 200 + 23 * static_cast<uint64_t>(entries); }
/** MUL: schoolbook multiplication of an n-byte by an m-byte operand (n >= m),
 *  including internal scratch storage: setup, a pass over the longer operand, one
 *  row per word of the shorter operand and one product per pair of words. */
constexpr uint64_t MulCost(size_t longer_bytes, size_t shorter_bytes)
{
    const uint64_t n{WordSpan(longer_bytes)}, m{WordSpan(shorter_bytes)};
    return 700 + n + 18 * m + n * m;
}
/** Q(n, m): bytes by which the word span of an n-byte dividend exceeds that of an
 *  m-byte divisor; zero for a shorter dividend. */
constexpr uint64_t DivExcess(size_t dividend_bytes, size_t divisor_bytes)
{
    const uint64_t n{WordSpan(dividend_bytes)}, m{WordSpan(divisor_bytes)};
    return n > m ? n - m : 0;
}
/** DIV: long division or remainder of an n-byte dividend by an m-byte divisor, both
 *  without trailing zero bytes: one row per word of Q(n, m) and a fixed few, each
 *  estimating a quotient word and subtracting that multiple of the divisor. */
constexpr uint64_t DivCost(size_t dividend_bytes, size_t divisor_bytes)
{
    const uint64_t q{DivExcess(dividend_bytes, divisor_bytes)}, m{WordSpan(divisor_bytes)};
    return 1150 + 60 * q + 11 * m + q * m;
}
/** Bytes processed by a hash with 64-byte blocks (SHA1, SHA256, RIPEMD160): the
 *  message plus at least 9 bytes of padding and length, rounded up to whole blocks. */
constexpr uint64_t HashBlockSpan(size_t bytes) { return (static_cast<uint64_t>(bytes) + 72) / 64 * 64; }
// HASH: one SHA256, RIPEMD160 or SHA1 pass over a message's 64-byte blocks.
constexpr uint64_t HashCost(size_t bytes) { return 50 + 40 * HashBlockSpan(bytes); }
// An elliptic-curve operation: a signature check, charged in addition to BASE and
// message hashing, or a public key tweak.
constexpr uint64_t SignatureCost() { return 500'000; }
// BIP 340 verification of a msg_bytes message: the challenge hash over R || P ||
// msg after the tag midstate, plus the signature check.
constexpr uint64_t SchnorrVerifyCost(size_t msg_bytes) { return HashCost(64 + msg_bytes) + SignatureCost(); }

/** Hash work of a hash opcode; result construction is charged separately.
 *  OP_HASH160 and OP_HASH256 hash the 32-byte SHA256 digest a second time. */
constexpr uint64_t HashCost(opcodetype opcode, size_t input_bytes)
{
    switch (opcode) {
    case OP_SHA256: case OP_RIPEMD160: case OP_SHA1: return HashCost(input_bytes);
    case OP_HASH160: case OP_HASH256: return HashCost(input_bytes) + HashCost(32);
    default: return 0;
    }
}

/**
 * Counter shared by parallel script checks. Only its value is synchronized; it
 * does not publish other state. Where 64-bit atomics are not lock-free, such as
 * on 32-bit bare-metal targets without libatomic, a spin lock on an always
 * lock-free std::atomic_flag guards a plain value instead.
 */
template <bool LOCK_FREE = std::atomic<uint64_t>::is_always_lock_free>
class SharedCounter final
{
private:
    std::conditional_t<LOCK_FREE, std::atomic<uint64_t>, uint64_t> m_value;
    mutable std::atomic_flag m_lock;

    template <typename Fn>
    auto Locked(Fn fn) const
    {
        while (m_lock.test_and_set(std::memory_order_acquire)) {}
        const auto result{fn()};
        m_lock.clear(std::memory_order_release);
        return result;
    }

public:
    explicit SharedCounter(uint64_t value) : m_value{value} {}

    uint64_t Load() const
    {
        if constexpr (LOCK_FREE) {
            return m_value.load(std::memory_order_relaxed);
        } else {
            return Locked([&] { return m_value; });
        }
    }

    /** Subtract amount unless it exceeds the value; return whether it was subtracted. */
    [[nodiscard]] bool TrySubtract(uint64_t amount)
    {
        if constexpr (LOCK_FREE) {
            uint64_t value{Load()};
            do {
                if (amount > value) return false;
            } while (!m_value.compare_exchange_weak(value, value - amount, std::memory_order_relaxed));
            return true;
        } else {
            return Locked([&] {
                if (amount > m_value) return false;
                m_value -= amount;
                return true;
            });
        }
    }
};

/** Thread-safe varops budget shared by script checks for one transaction. */
class Budget final
{
private:
    SharedCounter<> m_remaining;

public:
    explicit Budget(uint64_t remaining) : m_remaining{remaining} {}

    /** Return true if cost was charged; false if the budget was exhausted. */
    [[nodiscard]] bool Spend(uint64_t cost)
    {
        return cost == 0 || m_remaining.TrySubtract(cost);
    }

    uint64_t Remaining() const { return m_remaining.Load(); }
};

/**
 * Accumulate a script's whole-varop charges and deduct them from the shared
 * budget once. The inputs of a transaction may be checked on different threads,
 * which would contend for the budget if every opcode deducted from it. A script
 * instead checks its running total against the budget that remained when it
 * started (Fits()), and deducts the total when it ends (Spend()). A transaction
 * still fails exactly when its charges exceed its budget: a script whose total
 * exceeds what remained at its start exceeds the budget with the other inputs'
 * charges, and otherwise the deduction that overruns the budget fails. Scripts
 * checked in parallel may each run on budget that another then spends, but only
 * in a transaction that fails.
 */
class Meter final
{
private:
    uint64_t m_limit;
    uint64_t m_total{0};

public:
    explicit Meter(const Budget& budget) : m_limit{budget.Remaining()} {}

    void Add(uint64_t added)
    {
        m_total += added;
    }

    /** Whether the charges so far fit the budget that remained when the script started. */
    [[nodiscard]] bool Fits() const { return m_total <= m_limit; }

    /** Deduct the script's charges; called once, when the script ends. */
    [[nodiscard]] bool Spend(Budget& budget) const { return budget.Spend(m_total); }
};

// A transaction's varops budget is its weight, excluding the weight of inputs
// that do not use the budget, times the fixed factor 10,000 (BIP 440).
inline constexpr uint64_t BUDGET_PER_WEIGHT_UNIT = 10'000;

constexpr uint64_t TxBudget(int64_t weight)
{
    Assume(weight >= 0);
    return static_cast<uint64_t>(weight) * BUDGET_PER_WEIGHT_UNIT;
}

// A signature check costs the budget of the weight BIP 342 requires per signature check.
static_assert(SignatureCost() == BUDGET_PER_WEIGHT_UNIT * VALIDATION_WEIGHT_PER_SIGOP_PASSED);

} // namespace varops

#endif // BITCOIN_SCRIPT_VAROPS_H
