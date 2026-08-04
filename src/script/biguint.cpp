// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/biguint.h>

#include <compat/byteswap.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <utility>

#if defined(_MSC_VER) && !defined(__SIZEOF_INT128__)
#include <intrin.h>
#endif

namespace {

// These wrap modulo 2^64 and return the carry or borrow. The builtins keep the
// intended wraparound out of -fsanitize=unsigned-integer-overflow reports.
bool AddOverflow(uint64_t lhs, uint64_t rhs, uint64_t& result)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_add_overflow(lhs, rhs, &result);
#else
    result = lhs + rhs;
    return result < lhs;
#endif
}

bool SubUnderflow(uint64_t lhs, uint64_t rhs, uint64_t& result)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_sub_overflow(lhs, rhs, &result);
#else
    result = lhs - rhs;
    return lhs < rhs;
#endif
}

// Return value << shift modulo 2^64, for shift < 64. Clearing the bits that
// would be shifted out keeps them out of -fsanitize=unsigned-shift-base reports.
uint64_t ShiftLeftLow64(uint64_t value, unsigned shift)
{
    return (value & (UINT64_MAX >> shift)) << shift;
}

} // namespace

namespace biguint {

Wide MulWidePortable(uint64_t a, uint64_t b)
{
    // Schoolbook multiplication of 32-bit halves. The middle column sums three
    // 32-bit values, so it cannot overflow.
    const uint64_t a_lo{a & 0xffffffff}, a_hi{a >> 32};
    const uint64_t b_lo{b & 0xffffffff}, b_hi{b >> 32};
    const uint64_t low{a_lo * b_lo}, cross1{a_lo * b_hi}, cross2{a_hi * b_lo}, high{a_hi * b_hi};
    const uint64_t middle{(low >> 32) + (cross1 & 0xffffffff) + (cross2 & 0xffffffff)};
    return {high + (cross1 >> 32) + (cross2 >> 32) + (middle >> 32),
            ShiftLeftLow64(middle, 32) | (low & 0xffffffff)};
}

DivResult DivWidePortable(uint64_t hi, uint64_t lo, uint64_t d)
{
    // Hacker's Delight divlu for a normalized divisor: Knuth's Algorithm D
    // with 32-bit digits, dividing (hi:lo) one quotient digit at a time.
    Assume(d >> 63 && hi < d);
    constexpr uint64_t BASE{uint64_t{1} << 32};
    const uint64_t d1{d >> 32}, d0{d & 0xffffffff};
    const uint64_t u1{lo >> 32}, u0{lo & 0xffffffff};

    // Estimate the upper quotient digit from hi / d1, then correct it using d0.
    uint64_t q1{hi / d1}, r1{hi % d1};
    while (q1 >= BASE || q1 * d0 > (r1 << 32) + u1) {
        --q1;
        r1 += d1;
        if (r1 >= BASE) break;
    }
    // The upper three digits less q1 * d, which is less than d. Terms wrap.
    uint64_t u21;
    SubUnderflow(ShiftLeftLow64(r1, 32) | u1, q1 * d0, u21);

    uint64_t q0{u21 / d1}, r0{u21 % d1};
    while (q0 >= BASE || q0 * d0 > (r0 << 32) + u0) {
        --q0;
        r0 += d1;
        if (r0 >= BASE) break;
    }
    uint64_t remainder;
    SubUnderflow(ShiftLeftLow64(r0, 32) | u0, q0 * d0, remainder);

    assert(q1 < BASE && q0 < BASE);
    return {(q1 << 32) | q0, remainder};
}

Wide MulWide(uint64_t a, uint64_t b)
{
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 product{static_cast<unsigned __int128>(a) * b};
    return {static_cast<uint64_t>(product >> 64), static_cast<uint64_t>(product)};
#elif defined(_MSC_VER) && defined(_M_X64)
    uint64_t hi;
    const uint64_t lo{_umul128(a, b, &hi)};
    return {hi, lo};
#elif defined(_MSC_VER) && defined(_M_ARM64)
    return {__umulh(a, b), a * b};
#else
    return MulWidePortable(a, b);
#endif
}

DivResult DivWide(uint64_t hi, uint64_t lo, uint64_t d)
{
    Assume(d >> 63 && hi < d);
#if defined(__SIZEOF_INT128__)
    const unsigned __int128 dividend{(static_cast<unsigned __int128>(hi) << 64) | lo};
    const uint64_t quotient{static_cast<uint64_t>(dividend / d)};
    return {quotient, static_cast<uint64_t>(dividend - static_cast<unsigned __int128>(quotient) * d)};
#elif defined(_MSC_VER) && defined(_M_X64)
    uint64_t remainder;
    const uint64_t quotient{_udiv128(hi, lo, d, &remainder)};
    return {quotient, remainder};
#else
    return DivWidePortable(hi, lo, d);
#endif
}

bool IsZero(ConstLimbs a)
{
    if (a.empty()) return true;
    // Compare the limbs with themselves, offset by one limb:
    // https://rusty.ozlabs.org/2015/10/20/ccanmems-memeqzero-iteration.html
    const auto bytes{a.Bytes()};
    return a[0] == 0 && std::memcmp(bytes.data(), bytes.data() + 8, bytes.size() - 8) == 0;
}

int Compare(ConstLimbs a, ConstLimbs b)
{
    // Compare with a as the longer operand, negating the result if swapped.
    const int sign{a.size() < b.size() ? -1 : 1};
    if (sign < 0) std::swap(a, b);
    // A nonzero limb beyond b decides; otherwise the most significant limb
    // where the operands differ does.
    if (!IsZero(a.subspan(b.size()))) return sign;
    size_t i{b.size()};
    while (i > 0 && a[i - 1] == b[i - 1]) --i;
    if (i == 0) return 0;
    return a[i - 1] < b[i - 1] ? -sign : sign;
}

namespace {
// Return one past the most significant nonzero limb of a, given that a's limbs
// below `bottom` end at `nonzero`.
size_t FindTop(ConstLimbs a, size_t bottom, size_t nonzero)
{
    for (size_t i{a.size()}; i > bottom; --i) {
        if (a[i - 1] != 0) return i;
    }
    return nonzero;
}
} // namespace

bool Add(Limbs a, ConstLimbs b, size_t* top)
{
    Assume(a.size() >= b.size());
    // Adding a[i] and b[i] before the carry keeps only one addition on the
    // carry chain. At most one of the two additions carries.
    uint64_t carry{0};
    size_t nonzero{0};
    size_t i{0};
    for (; i < b.size(); ++i) {
        uint64_t sum;
        const uint64_t carry1{AddOverflow(a[i], b[i], sum)};
        carry = carry1 + AddOverflow(sum, carry, sum);
        a.Set(i, sum);
        if (sum != 0) nonzero = i + 1;
    }
    for (; carry && i < a.size(); ++i) {
        uint64_t sum;
        carry = AddOverflow(a[i], 1, sum);
        a.Set(i, sum);
        if (sum != 0) nonzero = i + 1;
    }
    if (top && !carry) *top = FindTop(a, i, nonzero);
    return carry != 0;
}

bool Subtract(Limbs a, ConstLimbs b, size_t* top)
{
    const size_t common{std::min(a.size(), b.size())};
    if (!IsZero(b.subspan(common))) return true;
    // As in Add, only one subtraction is on the borrow chain.
    uint64_t borrow{0};
    size_t nonzero{0};
    size_t i{0};
    for (; i < common; ++i) {
        uint64_t difference;
        const uint64_t borrow1{SubUnderflow(a[i], b[i], difference)};
        borrow = borrow1 + SubUnderflow(difference, borrow, difference);
        a.Set(i, difference);
        if (difference != 0) nonzero = i + 1;
    }
    for (; borrow && i < a.size(); ++i) {
        uint64_t difference;
        borrow = SubUnderflow(a[i], 1, difference);
        a.Set(i, difference);
        if (difference != 0) nonzero = i + 1;
    }
    if (borrow) return true;
    if (top) *top = FindTop(a, i, nonzero);
    return false;
}

uint64_t AddMul(Limbs a, ConstLimbs b, uint64_t m)
{
    Assume(a.size() == b.size());
    // Each step's sum is at most (2^64 - 1) + (2^64 - 1)^2 + (2^64 - 1), so its
    // high limb absorbs both carries. Adding a[i] first leaves only the carry's
    // addition on the carry chain.
    uint64_t carry{0};
    for (size_t i{0}; i < b.size(); ++i) {
        auto [hi, lo]{MulWide(b[i], m)};
        hi += AddOverflow(lo, a[i], lo);
        hi += AddOverflow(lo, carry, lo);
        a.Set(i, lo);
        carry = hi;
    }
    return carry;
}

uint64_t SubMul(Limbs a, ConstLimbs b, uint64_t m)
{
    Assume(a.size() == b.size());
    // As in AddMul, the high limb absorbs both borrows, and subtracting the
    // product's low limb first leaves only the borrow on the chain.
    uint64_t borrow{0};
    for (size_t i{0}; i < b.size(); ++i) {
        auto [hi, lo]{MulWide(b[i], m)};
        uint64_t difference;
        hi += SubUnderflow(a[i], lo, difference);
        hi += SubUnderflow(difference, borrow, difference);
        a.Set(i, difference);
        borrow = hi;
    }
    return borrow;
}

uint64_t ShiftUp(Limbs a, unsigned bits)
{
    assert(bits < 64);
    if (bits == 0) return 0;
    uint64_t carry{0};
    for (size_t i{0}; i < a.size(); ++i) {
        const uint64_t limb{a[i]};
        a.Set(i, ShiftLeftLow64(limb, bits) | carry);
        carry = limb >> (64 - bits);
    }
    return carry;
}

void ShiftDown(Limbs a, uint64_t bits)
{
    const auto bytes{a.Bytes()};
    if (bits % 8 == 0) {
        // The limbs form one little-endian byte string: whole bytes just move.
        const size_t count{static_cast<size_t>(std::min<uint64_t>(bits / 8, bytes.size()))};
        if (count == 0) return;
        std::memmove(bytes.data(), bytes.data() + count, bytes.size() - count);
        std::fill(bytes.end() - count, bytes.end(), 0);
        return;
    }
    const size_t words{static_cast<size_t>(std::min<uint64_t>(bits / 64, a.size()))};
    const unsigned shift{static_cast<unsigned>(bits % 64)};
    const size_t kept{a.size() - words};
    if (kept > 0) {
        uint64_t low{a[words] >> shift};
        for (size_t i{0}; i + 1 < kept; ++i) {
            const uint64_t next{a[words + i + 1]};
            a.Set(i, low | ShiftLeftLow64(next, 64 - shift));
            low = next >> shift;
        }
        a.Set(kept - 1, low);
    }
    std::fill(bytes.begin() + 8 * kept, bytes.end(), 0);
}

void ReverseBytes(std::span<unsigned char> bytes)
{
    // Swap byte-swapped words from both ends, then reverse the fewer than 16
    // bytes left in the middle.
    size_t lo{0};
    size_t hi{bytes.size()};
    while (hi - lo >= 16) {
        const uint64_t front{ReadLE64(bytes.data() + lo)};
        const uint64_t back{ReadLE64(bytes.data() + hi - 8)};
        WriteLE64(bytes.data() + lo, internal_bswap_64(back));
        WriteLE64(bytes.data() + hi - 8, internal_bswap_64(front));
        lo += 8;
        hi -= 8;
    }
    std::reverse(bytes.begin() + lo, bytes.begin() + hi);
}

} // namespace biguint

BigUint::BigUint(BigUint&& other) noexcept
    : m_bytes{std::exchange(other.m_bytes, {})}, m_size{std::exchange(other.m_size, 0)}
{
}

BigUint& BigUint::operator=(BigUint&& other) noexcept
{
    m_bytes = std::exchange(other.m_bytes, {});
    m_size = std::exchange(other.m_size, 0);
    return *this;
}

void BigUint::MoveFromValtype(std::vector<unsigned char>&& bytes)
{
    m_bytes = std::move(bytes);
    m_size = m_bytes.size();
    m_bytes.resize(biguint::WordPaddedCapacity(m_size));
}

std::vector<unsigned char> BigUint::MoveToValtype()
{
    CheckInvariants();
    m_bytes.resize(m_size);
    m_size = 0;
    return std::exchange(m_bytes, {});
}

uint64_t BigUint::ToU64Clamped(uint64_t max) const
{
    const auto limbs{Limbs()};
    if (limbs.empty()) return 0;
    if (limbs[0] > max || !biguint::IsZero(limbs.subspan(1))) return max;
    return limbs[0];
}

void BigUint::Assign(uint64_t value)
{
    m_size = biguint::MinimalEncodingSize(value);
    m_bytes.resize(biguint::WordPaddedCapacity(m_size));
    if (m_size != 0) Limbs().Set(0, value);
}

void BigUint::TrimTrailingZeros(size_t nonzero_limbs)
{
    const auto limbs{Limbs()};
    if constexpr (G_ABORT_ON_FAILED_ASSUME) Assume(biguint::IsZero(limbs.subspan(nonzero_limbs)));
    size_t top{nonzero_limbs};
    while (top > 0 && limbs[top - 1] == 0) --top;
    m_size = top == 0 ? 0 : 8 * (top - 1) + biguint::MinimalEncodingSize(limbs[top - 1]);
    m_bytes.resize(8 * top);
    CheckInvariants();
}

void BigUint::Resize(size_t size)
{
    const size_t padded{biguint::WordPaddedCapacity(size)};
    if (size < m_size) {
        // Clear the value bytes that become padding.
        std::fill(m_bytes.begin() + size, m_bytes.begin() + std::min(m_size, padded), 0);
    }
    m_bytes.resize(padded);
    m_size = size;
}

void BigUint::PrependZeros(size_t count)
{
    if (count == 0) return; // std::copy_backward below needs a nonempty shift
    const size_t padded{biguint::WordPaddedCapacity(m_size + count)};
    if (padded > m_bytes.capacity()) {
        // Build the result in exactly sized new storage, writing each byte once.
        std::vector<unsigned char> bytes;
        bytes.reserve(padded);
        bytes.resize(count);
        bytes.insert(bytes.end(), m_bytes.begin(), m_bytes.begin() + m_size);
        bytes.resize(padded);
        m_bytes = std::move(bytes);
    } else {
        m_bytes.resize(padded);
        std::copy_backward(m_bytes.begin(), m_bytes.begin() + m_size, m_bytes.begin() + count + m_size);
        std::fill_n(m_bytes.begin(), count, 0);
    }
    m_size += count;
}

void BigUint::AppendCarry()
{
    const size_t carry_byte{m_bytes.size()};
    m_bytes.resize(carry_byte + 8);
    m_bytes[carry_byte] = 1;
    m_size = carry_byte + 1;
}

void BigUint::CheckInvariants() const
{
    if constexpr (G_ABORT_ON_FAILED_ASSUME) {
        Assume(m_bytes.size() == biguint::WordPaddedCapacity(m_size));
        Assume(std::all_of(m_bytes.begin() + m_size, m_bytes.end(), [](unsigned char b) { return b == 0; }));
    }
}

void BigUint::OpAdd(BigUint& v1, BigUint& v2)
{
    // Add into the longer operand, which then only grows for a carry.
    if (v1.m_size < v2.m_size) std::swap(v1, v2);
    size_t top;
    if (biguint::Add(v1.Limbs(), v2.Limbs(), &top)) {
        v1.AppendCarry();
    } else {
        v1.TrimTrailingZeros(top);
    }
}

namespace {
constexpr std::array<unsigned char, 8> ONE{1};
} // namespace

void BigUint::Op1Add(BigUint& v1)
{
    if (v1.m_size == 0) {
        v1.Assign(1);
        return;
    }
    size_t top;
    if (biguint::Add(v1.Limbs(), biguint::ConstLimbs{ONE}, &top)) {
        v1.AppendCarry();
    } else {
        v1.TrimTrailingZeros(top);
    }
}

bool BigUint::OpSub(BigUint& v1, const BigUint& v2)
{
    size_t top;
    if (biguint::Subtract(v1.Limbs(), v2.Limbs(), &top)) {
        // Leave v1 valid: the subtraction may have written its padding.
        v1.Resize(0);
        return false;
    }
    v1.TrimTrailingZeros(top);
    return true;
}

bool BigUint::Op1Sub(BigUint& v1)
{
    size_t top;
    if (biguint::Subtract(v1.Limbs(), biguint::ConstLimbs{ONE}, &top)) {
        v1.Resize(0);
        return false;
    }
    v1.TrimTrailingZeros(top);
    return true;
}

void BigUint::Op2Mul(BigUint& v1)
{
    // Trim first so that trailing zero limbs are not shifted.
    v1.TrimTrailingZeros();
    if (biguint::ShiftUp(v1.Limbs(), 1) != 0) {
        v1.AppendCarry();
    } else {
        // The shift may have moved a bit into the padding.
        v1.TrimTrailingZeros();
    }
}

void BigUint::Op2Div(BigUint& v1)
{
    // Trim first so that trailing zero limbs are not shifted.
    v1.TrimTrailingZeros();
    biguint::ShiftDown(v1.Limbs(), 1);
    v1.TrimTrailingZeros();
}

void BigUint::OpMin(BigUint& v1, BigUint& v2)
{
    if (v1.Compare(v2) > 0) std::swap(v1, v2);
    v1.TrimTrailingZeros();
}

void BigUint::OpMax(BigUint& v1, BigUint& v2)
{
    if (v1.Compare(v2) < 0) std::swap(v1, v2);
    v1.TrimTrailingZeros();
}

size_t BigUint::ProductSize(const BigUint& v1, const BigUint& v2)
{
    return v1.m_bytes.size() + v2.m_bytes.size();
}

BigUint BigUint::OpMul(const BigUint& v1, const BigUint& v2)
{
    return OpMul(v1, v2, std::vector<unsigned char>(ProductSize(v1, v2)));
}

BigUint BigUint::OpMul(const BigUint& v1, const BigUint& v2, std::vector<unsigned char>&& product)
{
    assert(product.size() == ProductSize(v1, v2));
    // Schoolbook multiplication with one row per limb of the shorter operand, as
    // BIP 441 charges it.
    const bool v1_shorter{v1.m_size <= v2.m_size};
    const auto multipliers{(v1_shorter ? v1 : v2).Limbs()};
    const auto multiplicand{(v1_shorter ? v2 : v1).Limbs()};
    BigUint result{std::move(product)};
    const auto rows{result.Limbs()};
    if constexpr (G_ABORT_ON_FAILED_ASSUME) Assume(biguint::IsZero(rows));
    for (size_t i{0}; i < multipliers.size(); ++i) {
        // Row i adds into limbs i onward; limb i + multiplicand.size() is still zero.
        const uint64_t carry{biguint::AddMul(rows.subspan(i, multiplicand.size()), multiplicand, multipliers[i])};
        rows.Set(i + multiplicand.size(), carry);
    }
    result.TrimTrailingZeros();
    return result;
}

bool BigUint::OpDiv(BigUint& v1, BigUint& v2)
{
    return DivMod(v1, v2, DivModOp::DIV);
}

bool BigUint::OpMod(BigUint& v1, BigUint& v2)
{
    return DivMod(v1, v2, DivModOp::MOD);
}

bool BigUint::DivMod(BigUint& v1, BigUint& v2, DivModOp op)
{
    // Knuth, TAOCP vol. 2, section 4.3.1, Algorithm D, in place: v1's limbs
    // hold the running remainder, and each dividend limb a step retires stores
    // that step's quotient limb. v2 is left normalized.
    assert(&v1 != &v2);
    v1.TrimTrailingZeros();
    v2.TrimTrailingZeros();
    if (v2.m_size == 0) return false;
    if (v1.m_size < v2.m_size) {
        // The divisor is greater: the quotient is zero and the remainder is v1.
        if (op == DivModOp::DIV) v1.Resize(0);
        return true;
    }

    const auto u{v1.Limbs()};
    const auto v{v2.Limbs()};
    const size_t n{v.size()};
    const size_t m{u.size() - n};
    if (u.size() == 1) {
        u.Set(0, op == DivModOp::DIV ? u[0] / v[0] : u[0] % v[0]);
        v1.TrimTrailingZeros();
        return true;
    }

    // D1: normalize, shifting both operands until the divisor's top bit is
    // set. The shifts can fill the padding, so both encodings are widened over
    // it first; that keeps the storage, and u and v, in place. Bits shifted out
    // of the dividend form an extra limb above it.
    const unsigned shift{static_cast<unsigned>(std::countl_zero(v[n - 1]))};
    v1.Resize(8 * u.size());
    v2.Resize(8 * n);
    biguint::ShiftUp(v, shift);
    uint64_t top{biguint::ShiftUp(u, shift)};

    if (n == 1) {
        // Short division, from the most significant limb down.
        uint64_t remainder{top};
        for (size_t i{u.size()}; i > 0; --i) {
            const auto [quotient, next_remainder]{biguint::DivWide(remainder, u[i - 1], v[0])};
            if (op == DivModOp::DIV) u.Set(i - 1, quotient);
            remainder = next_remainder;
        }
        if (op == DivModOp::MOD) {
            v1.Assign(remainder >> shift);
        } else {
            v1.TrimTrailingZeros();
        }
        return true;
    }

    // D2-D7: step j divides the window top:u[j + n - 1..j] by v, leaving the
    // remainder in u[j + n - 1..j]. Each window is less than v * 2^64, so its
    // quotient is a single limb and `top` is at most v's top limb.
    const uint64_t v_top{v[n - 1]}, v_next{v[n - 2]};
    uint64_t quotient_top{0};
    for (size_t step{0}; step <= m; ++step) {
        const size_t j{m - step};
        assert(top <= v_top);
        const uint64_t u_top{u[j + n - 1]}, u_next{u[j + n - 2]};

        // D3: estimate the quotient limb as (top:u_top) / v_top, capped at
        // 2^64 - 1. Correcting it with v_next leaves it at most one too large.
        uint64_t qhat{UINT64_MAX}, rhat;
        bool rhat_overflow;
        if (top == v_top) {
            rhat_overflow = AddOverflow(u_top, v_top, rhat);
        } else {
            const biguint::DivResult estimate{biguint::DivWide(top, u_top, v_top)};
            qhat = estimate.quotient;
            rhat = estimate.remainder;
            rhat_overflow = false;
        }
        while (!rhat_overflow) {
            const auto [hi, lo]{biguint::MulWide(qhat, v_next)};
            if (hi < rhat || (hi == rhat && lo <= u_next)) break;
            --qhat;
            rhat_overflow = AddOverflow(rhat, v_top, rhat);
        }

        // D4: subtract qhat * v from the window. A zero estimate leaves it
        // unchanged, as happens often without normalization.
        const auto window{u.subspan(j, n)};
        const uint64_t borrow{qhat == 0 ? 0 : biguint::SubMul(window, v, qhat)};
        if (borrow > top) {
            // D6: qhat was one too large. Adding v back carries into `top`.
            --qhat;
            const bool carry{biguint::Add(window, v)};
            assert(carry && borrow - top == 1);
        } else {
            assert(borrow == top);
        }

        // The window's top limb is now zero, and stores the quotient limb.
        if (j == m) {
            quotient_top = qhat;
        } else {
            u.Set(j + n, qhat);
        }
        top = u[j + n - 1];
    }

    const auto bytes{u.Bytes()};
    if (op == DivModOp::DIV) {
        // The quotient's limbs are quotient_top and u[m + n - 1..n].
        std::memmove(bytes.data(), bytes.data() + 8 * n, 8 * m);
        u.Set(m, quotient_top);
        std::fill(bytes.begin() + 8 * (m + 1), bytes.end(), 0);
        v1.TrimTrailingZeros(m + 1);
    } else {
        // The remainder is u[n - 1..0], still normalized.
        std::fill(bytes.begin() + 8 * n, bytes.end(), 0);
        biguint::ShiftDown(u.first(n), shift);
        v1.TrimTrailingZeros(n);
    }
    return true;
}

void BigUint::OpInvert(BigUint& v1)
{
    const auto limbs{v1.Limbs()};
    for (size_t i{0}; i < limbs.size(); ++i) limbs.Set(i, ~limbs[i]);
    std::fill(v1.m_bytes.begin() + v1.m_size, v1.m_bytes.end(), 0);
}

void BigUint::OpAnd(BigUint& v1, BigUint& v2)
{
    // The result has the longer operand's width.
    if (v1.m_size < v2.m_size) std::swap(v1, v2);
    const auto a{v1.Limbs()};
    const auto b{v2.Limbs()};
    for (size_t i{0}; i < b.size(); ++i) a.Set(i, a[i] & b[i]);
    std::fill(a.Bytes().begin() + 8 * b.size(), a.Bytes().end(), 0);
}

void BigUint::OpOr(BigUint& v1, BigUint& v2)
{
    if (v1.m_size < v2.m_size) std::swap(v1, v2);
    const auto a{v1.Limbs()};
    const auto b{v2.Limbs()};
    for (size_t i{0}; i < b.size(); ++i) a.Set(i, a[i] | b[i]);
}

void BigUint::OpXor(BigUint& v1, BigUint& v2)
{
    if (v1.m_size < v2.m_size) std::swap(v1, v2);
    const auto a{v1.Limbs()};
    const auto b{v2.Limbs()};
    for (size_t i{0}; i < b.size(); ++i) a.Set(i, a[i] ^ b[i]);
}

bool BigUint::OpUpShift(BigUint& v1, const BigUint& v2, size_t max_size)
{
    const uint64_t bits{v2.ToU64Clamped(8 * uint64_t{max_size} + 1)};
    if (bits + 8 * uint64_t{v1.m_size} > 8 * uint64_t{max_size}) return false;

    // As BIP 441 defines it: prepend the shift's bytes, rounded up, then shift
    // down the excess bits. Prepended limbs below the one receiving the lowest
    // bits stay zero, so only the limbs holding the value are shifted.
    const size_t zeros{static_cast<size_t>((bits + 7) / 8)};
    v1.PrependZeros(zeros);
    if (const uint64_t excess{8 * zeros - bits}; excess != 0) {
        biguint::ShiftDown(v1.Limbs().subspan((zeros - 1) / 8), excess);
    }
    return true;
}

void BigUint::OpDownShift(BigUint& v1, const BigUint& v2)
{
    const uint64_t bits{v2.ToU64Clamped(8 * uint64_t{v1.m_size})};
    // Shift, then drop only the whole bytes shifted out.
    biguint::ShiftDown(v1.Limbs(), bits);
    v1.Resize(v1.m_size - static_cast<size_t>(bits / 8));
}
