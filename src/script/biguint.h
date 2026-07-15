// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_BIGUINT_H
#define BITCOIN_SCRIPT_BIGUINT_H

#include <crypto/common.h>
#include <script/varops.h>
#include <util/check.h>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

/** Arithmetic behind BigUint, and the stack values it works on. Exposed for
 *  tests and benchmarks. */
namespace biguint {

/** varops::WordSpan as a storage size. Stack values carry it as capacity, so
 *  pushing them, or later preparing them as numbers, never reallocates. */
constexpr size_t WordPaddedCapacity(size_t size) { return static_cast<size_t>(varops::WordSpan(size)); }

/** Size of the minimal encoding of value: its little-endian bytes without trailing zeros. */
constexpr size_t MinimalEncodingSize(uint64_t value) { return static_cast<size_t>(std::bit_width(value) + 7) / 8; }

/**
 * View of 64-bit limbs stored in bytes, least significant limb first, each
 * limb little-endian. Limbs are copied in and out on access, so the bytes need
 * no alignment and results do not depend on the host's byte order.
 */
template <typename Byte>
class LimbSpan
{
    std::span<Byte> m_bytes;

public:
    LimbSpan() = default;
    explicit LimbSpan(std::span<Byte> bytes) : m_bytes{bytes} { Assume(bytes.size() % 8 == 0); }
    template <typename Other>
        requires std::is_convertible_v<Other (*)[], Byte (*)[]>
    LimbSpan(LimbSpan<Other> other) : m_bytes{other.Bytes()}
    {
    }

    std::span<Byte> Bytes() const { return m_bytes; }
    size_t size() const { return m_bytes.size() / 8; }
    bool empty() const { return m_bytes.empty(); }

    uint64_t operator[](size_t i) const
    {
        Assume(i < size());
        return ReadLE64(m_bytes.data() + 8 * i);
    }
    void Set(size_t i, uint64_t limb) const
    {
        Assume(i < size());
        WriteLE64(m_bytes.data() + 8 * i, limb);
    }

    LimbSpan first(size_t count) const { return LimbSpan{m_bytes.first(8 * count)}; }
    LimbSpan subspan(size_t offset) const { return LimbSpan{m_bytes.subspan(8 * offset)}; }
    LimbSpan subspan(size_t offset, size_t count) const { return LimbSpan{m_bytes.subspan(8 * offset, 8 * count)}; }
};

using Limbs = LimbSpan<unsigned char>;
using ConstLimbs = LimbSpan<const unsigned char>;

struct Wide {
    uint64_t hi;
    uint64_t lo;
};

struct DivResult {
    uint64_t quotient;
    uint64_t remainder;
};

// Return a * b.
Wide MulWide(uint64_t a, uint64_t b);
// Return (hi:lo) / d and (hi:lo) % d. d must have its top bit set and exceed hi.
DivResult DivWide(uint64_t hi, uint64_t lo, uint64_t d);
// MulWide and DivWide from 32-bit halves, for platforms without 128-bit
// arithmetic. Always compiled, so tests can compare them with the native ones.
Wide MulWidePortable(uint64_t a, uint64_t b);
DivResult DivWidePortable(uint64_t hi, uint64_t lo, uint64_t d);

bool IsZero(ConstLimbs a);
// Return -1, 0 or 1 as a is less than, equal to or greater than b.
int Compare(ConstLimbs a, ConstLimbs b);
// a += b, where a has at least as many limbs as b. Return the carry out of a.
// If `top` is given and there is no carry, set it to one past a's most
// significant nonzero limb.
bool Add(Limbs a, ConstLimbs b, size_t* top = nullptr);
// a -= b. Return true, leaving a unspecified, if b > a. Otherwise set `top`, if
// given, to one past a's most significant nonzero limb.
bool Subtract(Limbs a, ConstLimbs b, size_t* top = nullptr);
// a += b * m, where a and b have the same length. Return the carry limb.
uint64_t AddMul(Limbs a, ConstLimbs b, uint64_t m);
// a -= b * m, where a and b have the same length. Return the borrow limb.
uint64_t SubMul(Limbs a, ConstLimbs b, uint64_t m);
// Shift a up (toward more significant bits) by 0 to 63 bits. Return the bits
// shifted out of the top limb.
uint64_t ShiftUp(Limbs a, unsigned bits);
// Shift a down (toward less significant bits) by any number of bits, filling
// the vacated top with zeros.
void ShiftDown(Limbs a, uint64_t bits);

} // namespace biguint

/**
 * Arbitrary-length unsigned Script value for BIP 441 arithmetic and bit
 * operations.
 *
 * A BigUint owns a stack element's bytes, least significant first, zero-padded
 * to whole 64-bit limbs so operations can work a limb at a time. Stack
 * elements have capacity for that padding (see biguint::WordPaddedCapacity), so taking
 * and returning them does not reallocate.
 *
 * Operations are unmetered: the evaluator charges BIP 440 varops for them.
 * Binary operations leave their result in v1. They may swap the operands, and
 * leave a non-const v2 with an unspecified value.
 */
class BigUint
{
public:
    BigUint() = default;
    // Take ownership of a stack element.
    explicit BigUint(std::vector<unsigned char>&& bytes) { MoveFromValtype(std::move(bytes)); }
    // The minimal encoding of `value`.
    explicit BigUint(uint64_t value) { Assign(value); }

    BigUint(BigUint&& other) noexcept;
    BigUint& operator=(BigUint&& other) noexcept;
    BigUint(const BigUint&) = delete;
    BigUint& operator=(const BigUint&) = delete;

    // Take ownership of a stack element.
    void MoveFromValtype(std::vector<unsigned char>&& bytes);
    // Return the encoding as a stack element, leaving this value empty.
    std::vector<unsigned char> MoveToValtype();

    // Encoded length in bytes, including trailing zero bytes.
    size_t size() const { return m_size; }

    bool IsZero() const { return biguint::IsZero(Limbs()); }
    // Return -1, 0 or 1 as this value is less than, equal to or greater than `other`.
    int Compare(const BigUint& other) const { return biguint::Compare(Limbs(), other.Limbs()); }
    // Return the value, or `max` if the value is greater.
    uint64_t ToU64Clamped(uint64_t max) const;
    void TrimTrailingZeros() { TrimTrailingZeros(Limbs().size()); }

    // Arithmetic operations. Their results have no trailing zero bytes.
    static void OpAdd(BigUint& v1, BigUint& v2);
    static void Op1Add(BigUint& v1);
    // Return false, leaving v1 unspecified, if v2 > v1.
    static bool OpSub(BigUint& v1, const BigUint& v2);
    // Return false if v1 is zero.
    static bool Op1Sub(BigUint& v1);
    static void Op2Mul(BigUint& v1);
    static void Op2Div(BigUint& v1);
    static void OpMin(BigUint& v1, BigUint& v2);
    static void OpMax(BigUint& v1, BigUint& v2);
    // Return v1 * v2, which needs new storage of ProductSize() bytes.
    static BigUint OpMul(const BigUint& v1, const BigUint& v2);
    // As above, building the product in `product`: ProductSize() zero bytes.
    static BigUint OpMul(const BigUint& v1, const BigUint& v2, std::vector<unsigned char>&& product);
    static size_t ProductSize(const BigUint& v1, const BigUint& v2);
    // Return false if v2 is zero.
    static bool OpDiv(BigUint& v1, BigUint& v2);
    static bool OpMod(BigUint& v1, BigUint& v2);

    // Bit operations. Their results are not normalized: trailing zero bytes are kept.
    static void OpInvert(BigUint& v1);
    static void OpAnd(BigUint& v1, BigUint& v2);
    static void OpOr(BigUint& v1, BigUint& v2);
    static void OpXor(BigUint& v1, BigUint& v2);
    // Return false if the result would be longer than max_size bytes.
    static bool OpUpShift(BigUint& v1, const BigUint& v2, size_t max_size);
    static void OpDownShift(BigUint& v1, const BigUint& v2);

private:
    // The encoding, zero-padded to whole limbs.
    std::vector<unsigned char> m_bytes;
    // Encoded length. The padding from here to the end of m_bytes is zero.
    size_t m_size{0};

    biguint::Limbs Limbs() { return biguint::Limbs{m_bytes}; }
    biguint::ConstLimbs Limbs() const { return biguint::ConstLimbs{m_bytes}; }

    // Set to the minimal encoding of `value`.
    void Assign(uint64_t value);
    // Recompute the length from the limbs, which must be zero from
    // `nonzero_limbs` on. The padding may have been written.
    void TrimTrailingZeros(size_t nonzero_limbs);
    // Truncate or zero-extend the encoding to `size` bytes.
    void Resize(size_t size);
    // Insert `count` zero bytes below the least significant byte.
    void PrependZeros(size_t count);
    // Extend the value with a limb holding a carry of 1 out of its top limb.
    void AppendCarry();
    void CheckInvariants() const;

    enum class DivModOp { DIV, MOD };
    static bool DivMod(BigUint& v1, BigUint& v2, DivModOp op);
};

#endif // BITCOIN_SCRIPT_BIGUINT_H
