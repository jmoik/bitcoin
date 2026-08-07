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
#include <limits>
#include <type_traits>
#include <utility>

namespace varops {

/** Bytes in the 64-bit words that hold a value of the given size. */
constexpr uint64_t WordSpan(size_t bytes) { return (static_cast<uint64_t>(bytes) + 7) / 8 * 8; }
/** 64-bit words that hold a value of the given size. */
constexpr uint64_t WordCount(size_t bytes) { return WordSpan(bytes) / 8; }

// Whole-varop prices of the BIP 440 work classes. Byte arguments are logical sizes;
// size rates apply to the padded span the work processes: W(n) bytes, or H(n) for hashes.
// Six-machine envelope at 0.9x each machine's pre-v2 reference. Flats are rounded up
// to a multiple of 10 below 100 and of 50 from 100, rates to two significant figures
// and at least to a whole varop.

// Every logical opcode pays BASE, which includes deducting its charges from the budget.
constexpr uint64_t BaseCost() { return 350; }
constexpr uint64_t PrepareCost(size_t bytes) { return 200 + WordSpan(bytes); }
// Stack values are allocated with capacity for their word padding.
constexpr uint64_t WriteCost(size_t bytes) { return 800 + 8 * WordSpan(bytes); }
// NORMALIZE is flat: converting a number to bytes hands its buffer over in place.
constexpr uint64_t NormalizeCost() { return 200; }
constexpr uint64_t OutputCost(size_t bytes) { return WriteCost(bytes) + NormalizeCost(); }
constexpr uint64_t ReadCost(size_t bytes) { return 90 + 2 * WordSpan(bytes); }
// ARITH: word passes with a carry or borrow chain; BIT: word passes without one.
constexpr uint64_t ArithCost(size_t bytes) { return 150 + 3 * WordSpan(bytes); }
constexpr uint64_t BitCost(size_t bytes) { return 200 + 2 * WordSpan(bytes); }
constexpr uint64_t MoveCost(size_t entries) { return 200 + 37 * static_cast<uint64_t>(entries); }
/** Complete prepared OP_MUL, including internal scratch storage: fixed setup, a pass
 *  over the longer operand's limbs, one row per limb of the shorter operand (as
 *  Val64::OpMul computes it) and one product per pair of limbs. */
constexpr uint64_t MulCost(uint64_t longer_limbs, uint64_t shorter_limbs)
{
    return 400 + 6 * longer_limbs + 120 * shorter_limbs + 29 * longer_limbs * shorter_limbs;
}
constexpr uint64_t DivCost(uint64_t steps, uint64_t divisor_limbs)
{
    return 510 * steps + 33 * steps * divisor_limbs;
}
/** DIV quotient rows for limb counts of the operands without trailing zero bytes. */
constexpr uint64_t DivSteps(uint64_t dividend_limbs, uint64_t divisor_limbs)
{
    // One row per quotient limb, plus one for a dividend limb added by divisor normalization.
    // A shorter dividend still takes one row to compare the operands.
    return dividend_limbs + 2 > divisor_limbs ? dividend_limbs + 2 - divisor_limbs : 1;
}
/** Bytes processed by a hash with 64-byte blocks (SHA1, SHA256, RIPEMD160): the
 *  message plus at least 9 bytes of padding and length, rounded up to whole blocks. */
constexpr uint64_t HashBlockSpan(size_t bytes) { return (static_cast<uint64_t>(bytes) + 72) / 64 * 64; }
constexpr uint64_t Sha256Cost(size_t bytes) { return 300 + 38 * HashBlockSpan(bytes); }
constexpr uint64_t Ripemd160Cost(size_t bytes) { return 60 + 40 * HashBlockSpan(bytes); }
constexpr uint64_t Sha1Cost(size_t bytes) { return 200 + 24 * HashBlockSpan(bytes); }
// Signature verification, charged in addition to BASE and message hashing.
constexpr uint64_t SignatureCost() { return 500'000; }
// BIP 340 verification of a msg_bytes message: the challenge hash over R || P ||
// msg after the tag midstate, plus the signature check.
constexpr uint64_t SchnorrVerifyCost(size_t msg_bytes) { return Sha256Cost(64 + msg_bytes) + SignatureCost(); }
// OP_TX draft: selector decoding plus locating and encoding k selected values
// or aggregate-scanned records.
constexpr uint64_t TxSelectCost(size_t items) { return 2400 + 270 * static_cast<uint64_t>(items); }
// Scalar results pay for one word, whatever their length: a number converted to
// bytes (counts, numeric comparisons) pays WRITE(8) + NORMALIZE; a constant or
// boolean written directly as bytes (OP_1..16, EQUAL, CHECKSIG, ...) pays WRITE(8)
// alone.
constexpr uint64_t ScalarOutputCost() { return OutputCost(8); }

// Charges are computed in uint64_t. Each opcode sums a bounded number of the
// terms below, so bounding the superlinear ones shows no charge can wrap.
// Both numeric operands are at most 4 MB, so DivSteps is at most MAX_V2_LIMBS + 2.
inline constexpr uint64_t MAX_V2_LIMBS{WordCount(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)};
static_assert(MAX_V2_LIMBS + 2 <=
              (std::numeric_limits<uint64_t>::max() - DivCost(0, 0)) /
                  (DivCost(1, MAX_V2_LIMBS) - DivCost(0, 0)),
              "maximum OP_DIV and OP_MOD charge must fit in uint64_t");
// OP_MUL: MUL plus production of the full product span, both operands maximal.
// The shorter operand has at most as many limbs as the longer one, so each longer
// limb adds at most MulCost(1, MAX_V2_LIMBS) - MulCost(0, 0).
inline constexpr uint64_t MAX_MUL_STORAGE_CHARGE{WriteCost(2 * MAX_V2_LIMBS * 8)};
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
 * Accumulate a script's whole-varop charges. Deducting from the shared budget
 * is an atomic update that costs as much as a cheap opcode, so each opcode
 * deducts once: before its work if it must be paid in advance (Prepay()),
 * otherwise when it ends (EndOpcode()). Charges it adds after prepaying are
 * deducted with the next deduction.
 */
class Meter final
{
private:
    uint64_t m_total{0};
    uint64_t m_deducted{0};
    bool m_prepaid{false};

public:
    void Add(uint64_t added)
    {
        m_total += added;
    }

    /** Deduct the charges added since the previous deduction. */
    [[nodiscard]] bool Spend(Budget& budget)
    {
        const uint64_t deduction{m_total - m_deducted};
        if (!budget.Spend(deduction)) return false;
        m_deducted = m_total;
        return true;
    }

    /** Deduct before an opcode's work; the opcode then does not deduct when it ends. */
    [[nodiscard]] bool Prepay(Budget& budget)
    {
        m_prepaid = true;
        return Spend(budget);
    }

    /** Deduct an opcode's charges when it ends, unless it prepaid. */
    [[nodiscard]] bool EndOpcode(Budget& budget)
    {
        return std::exchange(m_prepaid, false) || Spend(budget);
    }
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
