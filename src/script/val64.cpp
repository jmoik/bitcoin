// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/val64.h>
#include <script/varops.h>
#include <util/check.h>
#include <algorithm>
#include <bit>
#include <cassert>
#include <cstring>
#include <memory>
#include <compat/endian.h>
#include <utility>

// MSVC compatibility: use compiler intrinsics where __int128 is not available.
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
#include <intrin.h>
#if defined(_M_X64)
#include <immintrin.h>
#define VAL64_HAVE_MSVC_UMUL128 1
#if _MSC_VER >= 1920
#define VAL64_HAVE_MSVC_UDIV128 1
#endif
#elif defined(_M_ARM64)
#define VAL64_HAVE_MSVC_UMULH 1
#endif
#endif


// For testing.
bool Val64::force_offset_span = false;
bool Val64::force_portable_math = false;

namespace {

#ifdef __has_builtin
#if __has_builtin(__builtin_add_overflow) && __has_builtin(__builtin_sub_overflow)
#define VAL64_HAVE_BUILTIN_OVERFLOW 1
#endif
#endif

bool AddOverflow(uint64_t lhs, uint64_t rhs, uint64_t& result)
{
#ifdef VAL64_HAVE_BUILTIN_OVERFLOW
    return __builtin_add_overflow(lhs, rhs, &result);
#else
    const bool overflow{rhs > UINT64_MAX - lhs};
    result = overflow ? rhs - (UINT64_MAX - lhs) - 1 : lhs + rhs;
    return overflow;
#endif
}

bool SubUnderflow(uint64_t lhs, uint64_t rhs, uint64_t& result)
{
#ifdef VAL64_HAVE_BUILTIN_OVERFLOW
    return __builtin_sub_overflow(lhs, rhs, &result);
#else
    const bool underflow{lhs < rhs};
    result = underflow ? UINT64_MAX - (rhs - lhs) + 1 : lhs - rhs;
    return underflow;
#endif
}

uint64_t ShiftLeftLow64(uint64_t value, size_t shift)
{
    assert(shift < 64);
    if (shift == 0) return value;
    return (value & (UINT64_MAX >> shift)) << shift;
}

struct Div64Result {
    uint64_t quotient;
    uint64_t remainder;
    bool quotient_is_beta;
};

struct Uint128 {
    uint64_t hi;
    uint64_t lo;

    static Uint128 FromParts(uint64_t hi, uint64_t lo)
    {
        return {hi, lo};
    }

    static Uint128 Mul(uint64_t a, uint64_t b, bool force_portable_math)
    {
#if defined(__SIZEOF_INT128__)
        if (!force_portable_math) {
            const unsigned __int128 product{static_cast<unsigned __int128>(a) * b};
            return {static_cast<uint64_t>(product >> 64), static_cast<uint64_t>(product)};
        }
#elif defined(VAL64_HAVE_MSVC_UMUL128)
        if (!force_portable_math) {
            uint64_t hi;
            const uint64_t lo{_umul128(a, b, &hi)};
            return {hi, lo};
        }
#elif defined(VAL64_HAVE_MSVC_UMULH)
        if (!force_portable_math) {
            return {__umulh(a, b), a * b};
        }
#endif

        const uint64_t a_lo{a & 0xFFFFFFFFULL};
        const uint64_t a_hi{a >> 32};
        const uint64_t b_lo{b & 0xFFFFFFFFULL};
        const uint64_t b_hi{b >> 32};

        const uint64_t p0{a_lo * b_lo};
        const uint64_t p1{a_lo * b_hi};
        const uint64_t p2{a_hi * b_lo};
        const uint64_t p3{a_hi * b_hi};

        const uint64_t carry{((p0 >> 32) + (p1 & 0xFFFFFFFFULL) + (p2 & 0xFFFFFFFFULL)) >> 32};
        uint64_t lo;
        AddOverflow(p0, ShiftLeftLow64(p1, 32), lo);
        AddOverflow(lo, ShiftLeftLow64(p2, 32), lo);
        const uint64_t hi{p3 + (p1 >> 32) + (p2 >> 32) + carry};
        return {hi, lo};
    }

    Div64Result DivMod64(uint64_t divisor, bool force_portable_math) const
    {
        assert(divisor != 0);

        if (hi >= divisor) {
            // The trial quotient is beta. D3 represents the corrected beta - 1.
            assert(hi == divisor);
            return {UINT64_MAX, lo, true};
        }

#if defined(__SIZEOF_INT128__)
        if (!force_portable_math) {
            const unsigned __int128 dividend{(static_cast<unsigned __int128>(hi) << 64) | lo};
            const unsigned __int128 quotient{dividend / divisor};
            const unsigned __int128 remainder{dividend % divisor};

            assert((quotient >> 64) == 0);
            return {static_cast<uint64_t>(quotient), static_cast<uint64_t>(remainder), false};
        }
#elif defined(VAL64_HAVE_MSVC_UDIV128)
        if (!force_portable_math) {
            uint64_t remainder;
            const uint64_t quotient{_udiv128(hi, lo, divisor, &remainder)};
            return {quotient, remainder, false};
        }
#endif

        // Portable 128-bit by 64-bit division using 32-bit digits.
        // Based on Hacker's Delight divlu() and Knuth's Algorithm D.
        // Computes (hi:lo) / divisor. When hi == divisor, Knuth's trial
        // quotient is beta and gets corrected by D3 in the caller.
        if (hi == 0) {
            return {lo / divisor, lo % divisor, false};
        }

        // The divisor has its top bit set (normalized), so we can safely use
        // 32-bit chunks without overflow in intermediate calculations.
        constexpr uint64_t B = 1ULL << 32; // Base (2^32)

        // Split divisor into two 32-bit digits.
        const uint64_t d1{divisor >> 32};
        const uint64_t d0{divisor & 0xFFFFFFFF};

        // The dividend is (hi : lo), treated as four 32-bit digits:
        // hi = (u3 : u2), lo = (u1 : u0). Compute one quotient digit at a time.
        const uint64_t u32{hi};
        const uint64_t u1{lo >> 32};
        const uint64_t u0{lo & 0xFFFFFFFF};

        // Estimate q1 = floor(u32 / d1). Since divisor is normalized and
        // hi < divisor, the result fits in 32 bits.
        uint64_t q1{u32 / d1};
        uint64_t r1{u32 % d1};

        // Refine: while q1 >= B or q1 * d0 > B * r1 + u1.
        while (q1 >= B || q1 * d0 > ShiftLeftLow64(r1, 32) + u1) {
            q1--;
            r1 += d1;
            if (r1 >= B) break;
        }

        // Update partial remainder for next digit:
        // u21 = (u32 * B + u1) - q1 * divisor
        //     = (r1 * B + u1) - q1 * d0.
        uint64_t u21;
        SubUnderflow(ShiftLeftLow64(r1, 32) + u1, q1 * d0, u21);

        uint64_t q0{u21 / d1};
        uint64_t r0{u21 % d1};

        while (q0 >= B || q0 * d0 > ShiftLeftLow64(r0, 32) + u0) {
            q0--;
            r0 += d1;
            if (r0 >= B) break;
        }

        assert(q1 < B);
        assert(q0 < B);
        const uint64_t quotient{(q1 << 32) + q0};
        uint64_t remainder;
        SubUnderflow(ShiftLeftLow64(r0, 32) + u0, q0 * d0, remainder);
        return {quotient, remainder, false};
    }
};

// Make the byte-backed words accessible as uint64_t objects before exposing
// them through m_u64span.
uint64_t* StartLimbLifetimes(void* aligned_ptr, size_t limb_count)
{
    uint64_t* limbs = static_cast<uint64_t*>(aligned_ptr);
    unsigned char* bytes = static_cast<unsigned char*>(aligned_ptr);

    for (size_t i = 0; i < limb_count; ++i) {
        uint64_t value;
        std::memcpy(&value, bytes + i * sizeof(uint64_t), sizeof(value));
        std::construct_at(limbs + i, value);
    }

    return limbs;
}

#undef VAL64_HAVE_BUILTIN_OVERFLOW

} // namespace

Val64::Val64(std::vector<unsigned char>&& v) : m_charvec(std::move(v))
{
    set_span();
}

size_t Val64::u64ptr_off() const
{
    if (m_realsize == 0) return 0;

    const unsigned char *p = reinterpret_cast<const unsigned char *>(m_u64span.data());

    /* Sanity check it's in bounds */
    assert(p >= m_charvec.data());
    assert(p + m_realsize <= m_charvec.data() + m_charvec.size());

    return p - m_charvec.data();
}

#ifdef DEBUG
void Val64::check_invariants() const
{
    assert(m_realsize <= m_charvec.size());

    if (m_u64span.empty()) {
        assert(m_realsize == 0);
        return;
    }

    const unsigned char* const data{m_charvec.data()};
    const unsigned char* const span_bytes{reinterpret_cast<const unsigned char*>(m_u64span.data())};
    const size_t span_bytes_size{m_u64span.size_bytes()};

    assert(span_bytes >= data);
    assert(span_bytes + span_bytes_size <= data + m_charvec.size());

    const size_t span_offset{static_cast<size_t>(span_bytes - data)};
    assert(span_offset + m_realsize <= m_charvec.size());
    assert(std::all_of(m_charvec.begin(), m_charvec.begin() + span_offset, [](unsigned char c) { return c == 0; }));
    assert(std::all_of(m_charvec.begin() + span_offset + m_realsize, m_charvec.end(), [](unsigned char c) { return c == 0; }));
}
#endif

// Only m_charvec is set: initialize other fields.
void Val64::set_span()
{
    m_realsize = m_charvec.size();

    // Round up to get number of u64s
    size_t limb_count = (m_realsize + sizeof(uint64_t) - 1) / sizeof(uint64_t);
    if (limb_count == 0) {
        m_u64span = {};
#ifdef DEBUG
        check_invariants();
#endif
        return;
    }

    // Enlarge if necessary (trailing zeroes are harmless in little-endian)
    if (m_charvec.size() < limb_count * sizeof(uint64_t))
        m_charvec.insert(m_charvec.end(), limb_count * sizeof(uint64_t) - m_charvec.size(), 0);

    // Val64 stores script values as bytes and creates live 64-bit limb objects
    // in aligned byte storage so arithmetic can use word-sized spans.
    size_t available_space = m_charvec.size();
    void *aligned_ptr = m_charvec.data();
    if (std::align(alignof(uint64_t), limb_count * sizeof(uint64_t), aligned_ptr, available_space) == m_charvec.data()
        && aligned_ptr == m_charvec.data()
        && !force_offset_span) {
        m_u64span = std::span<le64_t>(StartLimbLifetimes(m_charvec.data(), limb_count), limb_count);
#ifdef DEBUG
        check_invariants();
#endif
        return;
    }

    // Append zeroes so we can move values.  This might change alignment.
    m_charvec.insert(m_charvec.end(), sizeof(uint64_t), 0);
    available_space = m_charvec.size();
    aligned_ptr = m_charvec.data();
    std::align(alignof(uint64_t), limb_count * sizeof(uint64_t), aligned_ptr, available_space);

    // Force an offset span in tests even when the vector is already aligned.
    if (force_offset_span && aligned_ptr == m_charvec.data())
        aligned_ptr = m_charvec.data() + sizeof(uint64_t);

    // Figure out how much the offset now is, so we can move data.
    size_t span_offset = static_cast<unsigned char*>(aligned_ptr) - m_charvec.data();
    memmove(m_charvec.data() + span_offset, m_charvec.data(), limb_count * sizeof(uint64_t));
    std::fill(m_charvec.begin(), m_charvec.begin() + span_offset, 0);
    m_u64span = std::span<le64_t>(StartLimbLifetimes(aligned_ptr, limb_count), limb_count);
#ifdef DEBUG
    check_invariants();
#endif
}

// Remove offset because we're changing m_charvec.
void Val64::charvec_change_start()
{
#ifdef DEBUG
    check_invariants();
#endif
    size_t span_offset = u64ptr_off();
    if (span_offset)
        m_charvec.erase(m_charvec.begin(), m_charvec.begin() + span_offset);

    // Trim any added bytes.
    assert(m_realsize <= m_charvec.size());
    m_charvec.resize(m_realsize);
}

void Val64::charvec_change_end()
{
    set_span();
}

void Val64::remove_front(size_t bytes)
{
    assert(bytes <= m_realsize);

    charvec_change_start();
    m_charvec.erase(m_charvec.begin(), m_charvec.begin() + bytes);
    charvec_change_end();
}

void Val64::prepend_zeros(size_t prebytes)
{
    charvec_change_start();
    m_charvec.insert(m_charvec.begin(), prebytes, 0);
    charvec_change_end();
}

void Val64::truncate(size_t new_realsize)
{
    assert(new_realsize <= m_charvec.size());

    charvec_change_start();
    m_charvec.resize(new_realsize);
    charvec_change_end();
}

void Val64::move_from_valtype(std::vector<unsigned char>&& bytes)
{
    m_charvec = std::move(bytes);
    set_span();
}

std::vector<unsigned char> Val64::move_to_valtype()
{
    std::vector<unsigned char> ret;

    charvec_change_start();
    ret = std::move(m_charvec);
    charvec_change_end();

    return ret;
}

void Val64::trim_trailing_zeros()
{
    trim_tail();
}

Val64::Val64()
{
    set_span();
}

Val64::Val64(const Val64 &v)
{
    const size_t span_offset{v.u64ptr_off()};
    m_charvec.assign(v.m_charvec.begin() + span_offset, v.m_charvec.begin() + span_offset + v.m_realsize);
    set_span();
}

// Faster "trim zeroes from end" function
void Val64::trim_tail(size_t nonzero_len)
{
#ifdef DEBUG
    // Check that the words after nonzero len are indeed all zero.
    for (size_t i = nonzero_len; i < m_u64span.size(); i++) {
        assert(m_u64span[i] == 0);
    }
#endif

    if (nonzero_len < m_u64span.size())
        m_u64span = m_u64span.first(nonzero_len);

    trim_tail();
}

void Val64::trim_tail()
{
    // Discard complete zero limbs before examining the remaining bytes.
    size_t nonzero_words{m_u64span.size()};
    while (nonzero_words > 0 && m_u64span[nonzero_words - 1] == 0) {
        --nonzero_words;
    }
    if (nonzero_words < m_u64span.size()) {
        m_u64span = m_u64span.first(nonzero_words);
    }

    m_realsize = m_u64span.size_bytes();

    charvec_change_start();
    // At most the seven high zero bytes in the final non-zero limb remain.
    while (m_charvec.size() > 0 && m_charvec.back() == 0)
        m_charvec.pop_back();
    charvec_change_end();
}

Val64::Val64(uint64_t v) : m_charvec(sizeof(uint64_t))
{
    set_span();
    set(0, v);
    trim_tail();
}

// Move constructor
Val64::Val64(Val64&& other) noexcept:
    m_charvec()
{
    other.charvec_change_start();
    m_charvec = std::move(other.m_charvec);
    other.charvec_change_end();
    set_span();
}

// Move assignment operator
Val64& Val64::operator=(Val64&& other) noexcept {
    if (this != &other) {
        other.charvec_change_start();
        m_charvec = std::move(other.m_charvec);
        other.charvec_change_end();
        set_span();
    }
    return *this;
}

void Val64::swap(Val64 &other) noexcept
{
    std::swap(m_charvec, other.m_charvec);
    std::swap(m_realsize, other.m_realsize);
    std::swap(m_u64span, other.m_u64span);
}

uint64_t Val64::get_or_zero(size_t index) const
{
    if (index >= m_u64span.size())
        return 0;
    return get(index);
}

// Append a 1 byte to the u64ptr array.
void Val64::append_one()
{
    charvec_change_start();

    // Make sure we have room to append.
    m_charvec.resize(m_u64span.size() * sizeof(uint64_t) + 1);
    m_charvec[m_u64span.size() * sizeof(uint64_t)] = 1;

    // Re-evaluate with new m_charvec.
    charvec_change_end();
}

uint64_t Val64::to_u64_ceil(uint64_t max, uint64_t& varcost) const
{
    uint64_t v;

    // Worst case, we have to examine the padded word span (LENGTHCONV).
    varcost += varops::lengthconv_cost(m_realsize);

    // Little endian: get first word (zero-fills)
    v = get_or_zero(0);
    if (v > max)
        return max;

    // If any other bytes are non-zero, it's > UINT64_MAX.
    if (m_u64span.size() > 1 && !span_is_allzero(m_u64span.last(m_u64span.size()-1))) {
        return max;
    }

    return v;
}

bool Val64::is_zero() const
{
    return span_is_allzero(m_u64span);
}

bool Val64::is_zero(uint64_t& varcost) const
{
    varcost += varops::comparingzero_cost(m_realsize);
    return span_is_allzero(m_u64span);
}

bool Val64::span_is_allzero(std::span<le64_t> span)
{
    if (span.size() == 0)
        return true;
    if (span[0] != 0)
        return false;
    // memcmp-with-self trick: see https://rusty.ozlabs.org/2015/10/20/ccanmems-memeqzero-iteration.html
    return memcmp(span.data(), span.data() + 1, (span.size() - 1) * sizeof(le64_t)) == 0;
}

// If v1 > v2: 1.  If v1 < v2: -1.  Else 0
int Val64::cmp_span(std::span<le64_t> v1, std::span<le64_t> v2)
{
    size_t maxlen = std::max(v1.size(), v2.size());
    if (maxlen == 0) return 0;

    for (size_t i = maxlen; i > 0;) {
        --i;
        uint64_t iv1, iv2;

        iv1 = i < v1.size() ? le64toh_internal(v1[i]) : 0;
        iv2 = i < v2.size() ? le64toh_internal(v2[i]) : 0;
        if (iv1 < iv2)
            return -1;
        if (iv1 > iv2)
            return 1;
    }
    return 0;
}

int Val64::cmp(const Val64 &v2) const
{
    return cmp_span(m_u64span, v2.m_u64span);
}

int Val64::cmp(const Val64& v2, uint64_t& varcost) const
{
    varcost += varops::comparing_cost(m_realsize, v2.m_realsize);

    return cmp_span(m_u64span, v2.m_u64span);
}

// v1 += v2 (size v2 <= v1).  Return true if carry overflowed.
bool Val64::add_span(std::span<le64_t> v1, std::span<le64_t> v2,
                     size_t &nonzero_len)
{
    assert(v1.size() >= v2.size());

    // Little endian, overflow forward.
    bool carry = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < v2.size(); ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh_internal(v1[i]);
        u2 = le64toh_internal(v2[i]);

        const bool add_carry{AddOverflow(u1, u2, res)};
        const bool carry_carry{AddOverflow(res, uint64_t{carry}, res)};
        carry = add_carry || carry_carry;
        if (res)
            nonzero_len = i + 1;
        v1[i] = htole64_internal(res);
    }

    /* Carry forwards if required (continue even if not overflowing,
     * to set nonzero_len) */
    while (i < v1.size()) {
        uint64_t u1;
        carry = AddOverflow(le64toh_internal(v1[i]), uint64_t{carry}, u1);
        v1[i] = htole64_internal(u1);
        if (u1)
            nonzero_len = i + 1;
        i++;
    }

    return carry;
}

void Val64::op_add(Val64& v1, Val64& v2, uint64_t& varcost)
{
    binop_v1_longest(v1, v2);

    // BIP 441:
    // |OP_ADD
    // |MAX(W(length(A)), W(length(B))) * (ARITH + COPYING)
    varcost += varops::add_cost(v1.m_realsize, v2.m_realsize);

    size_t nonzero_len;
    bool carry = add_span(v1.m_u64span, v2.m_u64span, nonzero_len);

    if (carry) {
        v1.append_one();
        return;
    }

    v1.trim_tail(nonzero_len);
}

void Val64::op_1add(Val64& v1, uint64_t& varcost)
{
    // BIP 441:
    // |OP_1ADD
    // |MAX(1, operand length) * 9

    // BIP 441:
    // OP_1ADD and OP_1SUB are the same cost as ADD/SUB with a minimal 1 operand.
    varcost += varops::add_cost(v1.m_realsize, 1);
    if (v1.m_u64span.empty()) {
        v1.append_one();
        return;
    }

    le64_t one{htole64_internal(1)};
    size_t nonzero_len;
    if (add_span(v1.m_u64span, std::span<le64_t>{&one, 1}, nonzero_len)) {
        v1.append_one();
    } else {
        v1.trim_tail(nonzero_len);
    }
}

// v1 -= v2
bool Val64::sub_span(std::span<le64_t> v1, std::span<le64_t> v2, size_t &nonzero_len)
{
    size_t common_len = std::min(v1.size(), v2.size());

    // Little endian, underflow forward.
    bool underflow = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < common_len; ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh_internal(v1[i]);
        u2 = le64toh_internal(v2[i]);

        const bool sub_underflow{SubUnderflow(u1, u2, res)};
        const bool borrow_underflow{SubUnderflow(res, uint64_t{underflow}, res)};
        underflow = sub_underflow || borrow_underflow;
        v1[i] = htole64_internal(res);
        if (res)
            nonzero_len = i + 1;
    }

    /* We have exhausted v1? */
    if (i < v2.size()) {
        if (underflow)
            return underflow;
        while (i < v2.size()) {
            if (v2[i] != 0)
                return true;
            i++;
        }
        return false;
    }

    /* We have exhausted v2.  Underflow forwards if required: we keep
     * going even if we don't need to, to update nonzero_len. */
    while (i < v1.size()) {
        const uint64_t u1{le64toh_internal(v1[i])};
        uint64_t res;
        underflow = SubUnderflow(u1, uint64_t{underflow}, res);
        v1[i] = htole64_internal(res);
        if (res)
            nonzero_len = i + 1;
        i++;
    }

    return underflow;
}


bool Val64::op_sub(Val64& v1, const Val64& v2, uint64_t& varcost)
{
    // BIP 441:
    // |OP_SUB
    // |MAX(W(length(A)), W(length(B))) * ARITH
    varcost += varops::sub_cost(v1.m_realsize, v2.m_realsize);
    size_t nonzero_len;

    bool underflow = sub_span(v1.m_u64span, v2.m_u64span, nonzero_len);
    if (underflow) {
        // sub_span writes whole words, but padding bytes outside the logical value
        // must remain zero even when the result is discarded for underflow.
        if (v1.m_realsize < v1.m_u64span.size_bytes()) {
            unsigned char* bytes{reinterpret_cast<unsigned char*>(v1.m_u64span.data())};
            std::fill(bytes + v1.m_realsize, bytes + v1.m_u64span.size_bytes(), 0);
        }
        return false;
    }

    v1.trim_tail(nonzero_len);
    return true;
}

bool Val64::op_1sub(Val64& v1, uint64_t& varcost)
{
    varcost += varops::sub_cost(v1.m_realsize, 1);
    if (v1.m_u64span.empty()) return false;

    le64_t one{htole64_internal(1)};
    size_t nonzero_len;
    if (sub_span(v1.m_u64span, std::span<le64_t>{&one, 1}, nonzero_len)) return false;

    v1.trim_tail(nonzero_len);
    return true;
}

void Val64::bitshift_down(size_t words, size_t bits)
{
    // Not empty
    assert(m_u64span.size() != 0);
    assert(bits > 0);
    assert(bits < 64);

    // [B, A] rshift 1 => [B>>1 | A>>63, A << 1]
    uint64_t prevbits = get(words) >> bits;
    for (size_t i = words; i < m_u64span.size() - 1; ++i) {
        uint64_t next = get(i + 1);
        uint64_t v = prevbits | ShiftLeftLow64(next, 64 - bits);
        set(i - words, v);
        prevbits = next >> bits;
    }
    // Shift the last word
    set(m_u64span.size() - 1 - words, prevbits);
}

void Val64::op_downshift(Val64& v1, const Val64& v2, uint64_t& varcost)
{
    uint64_t bits = v2.to_u64_ceil(v1.m_realsize * 8, varcost);
    size_t bytes = bits / 8;

    // BIP 441:
    // |OP_DOWNSHIFT
    // |Length of BITS * 2 + MAX((Length of A - (Value of BITS) / 8), 0) * 3
    // (LENGTHCONV@2 + COPYING@3)

    // We already added length of BITS in to_u64_ceil above (LENGTHCONV@2).

    // Shift past end?  Empty.  Also covers empty array.
    if (bytes >= v1.m_realsize) {
        v1 = Val64(0);
        return;
    }

    // (Length of A - (Value of BITS) / 8) > 0 (COPYING).
    varcost += (v1.m_realsize - bytes) * varops::COST_COPYING;

    // Bitwise shifts can't do 0 anyway, as << 64 undefined.
    if (bits % 8 == 0) {
        // Remove least-significant words.
        v1.remove_front(bytes);
        return;
    }

    // Size after this is at least 1!
    assert(v1.m_u64span.size() > 0);

    // We shift and move at the same time.
    v1.bitshift_down(bits / 64, bits % 64);

    // Truncate.
    v1.truncate(v1.m_realsize - bytes);
}

// This means "shift bits higher": number go up!
bool Val64::op_upshift(Val64& v1, const Val64& v2, size_t max_size, uint64_t& varcost)
{
    uint64_t bits = v2.to_u64_ceil(max_size * 8 + 1, varcost);

    // BIP 441:
    // |OP_UPSHIFT
    // ...

    // Cannot overflow: m_realsize is (far) less than 32 bits, so is max_size.
    if (bits + v1.m_realsize * 8 > max_size * 8)
        return false;

    // How many whole bytes should we prepend?
    size_t prebytes = bits / 8;

    // BIP 441:
    // |OP_UPSHIFT
    // |W(length(BITS)) * FAST + (Value of BITS) / 8 * FAST + Length of A * COPYING (LENGTHCONV + ZEROING + COPYING).
    // If BITS % 8 != 0, add W(length(A) + (Value of BITS) / 8) * OTHER.
    varcost += prebytes * varops::COST_FAST + v1.m_realsize * varops::COST_COPYING;

    if (bits % 8 == 0) {
        // Simply insert bytes at the beginning.
        v1.prepend_zeros(prebytes);
    } else {
        varcost += varops::upshift_bitshift_cost(v1.m_realsize, prebytes);
        // There's no nice C++ "add this many bytes at the beginning,
        // and one at the end" so it is better to prepend too many bytes
        // (fast!) and shift backwards.
        v1.prepend_zeros(prebytes + 1);
        v1.bitshift_down(0, 8 - (bits % 8));
    }

    return true;
}

bool Val64::bitshift_up_small(size_t bits)
{
    assert(bits > 0);
    assert(bits < 64);

    uint64_t prevbits = 0;

    // [B, A] lshift 1 => [B<<1, A<<1 | B >> 63]
    for (size_t i = 0; i < m_u64span.size(); ++i) {
        uint64_t old_v = get(i);
        uint64_t new_v = ShiftLeftLow64(old_v, bits) | prevbits;

        set(i, new_v);
        prevbits = old_v >> (64 - bits);
    }
    return (prevbits != 0);
}

void Val64::op_2mul(Val64& v1, uint64_t& varcost)
{
    bool carry;

    // BIP 441:
    // |OP_2MUL
    // |W(length(A)) * (COPYING + OTHER)
    varcost += varops::twomul_cost(v1.m_realsize);

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.trim_tail();

    carry = v1.bitshift_up_small(1);

    if (carry)
        v1.append_one();
    else
        v1.trim_tail();
}

void Val64::op_2div(Val64& v1, uint64_t& varcost)
{
    // BIP 441:
    // |OP_2DIV
    // |W(length(A)) * OTHER
    varcost += varops::twodiv_cost(v1.m_realsize);

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.trim_tail();

    // bitshift_down assumes non-zero size.
    if (v1.m_realsize == 0)
        return;

    v1.bitshift_down(0, 1);
    v1.trim_tail();
}

void Val64::op_invert(Val64& v1, uint64_t& varcost)
{
    // BIP 441:
    // |OP_INVERT
    // |W(length(A)) * OTHER
    varcost += varops::invert_cost(v1.m_realsize);

    // Endian doesn't matter, so access raw.
    for (le64_t& v : v1.m_u64span) {
        v ^= UINT64_MAX;
    }

    // Zero out padding bytes beyond m_realsize in the last u64 word,
    // so subsequent Val64 operations don't see contaminated padding.
    size_t padding = v1.m_u64span.size() * sizeof(uint64_t) - v1.m_realsize;
    if (padding > 0) {
        unsigned char* bytes = reinterpret_cast<unsigned char*>(v1.m_u64span.data());
        std::memset(bytes + v1.m_realsize, 0, padding);
    }
}

// Makes sure v1 is at least as long as v2.
void Val64::binop_v1_longest(Val64 &v1, Val64 &v2)
{
    // Make sure v1 is the longer one.
    if (v1.m_realsize < v2.m_realsize)
        v1.swap(v2);
}

void Val64::op_and(Val64& v1, Val64& v2, uint64_t& varcost)
{
    binop_v1_longest(v1, v2);

    // BIP 441:
    // |OP_AND
    // |(W(length(A)) + W(length(B))) * FAST (OTHER on shorter + ZEROING on rest)
    varcost += varops::and_cost(v1.m_realsize, v2.m_realsize);

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i) {
        v1.m_u64span[i] &= v2.m_u64span[i];
    }

    // Rest is 0.
    std::fill(v1.m_u64span.begin() + v2.m_u64span.size(), v1.m_u64span.end(), 0);
}

void Val64::op_or(Val64& v1, Val64& v2, uint64_t& varcost)
{
    binop_v1_longest(v1, v2);

    // BIP 441:
    // |OP_OR
    // |(Lesser of the two operand lengths) * OTHER
    varcost += varops::or_cost(v1.m_realsize, v2.m_realsize);

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i)
        v1.m_u64span[i] |= v2.m_u64span[i];
}

void Val64::op_xor(Val64& v1, Val64& v2, uint64_t& varcost)
{
    binop_v1_longest(v1, v2);

    // BIP 441:
    // |OP_XOR
    // |(Lesser of the two operand lengths) * OTHER
    varcost += varops::xor_cost(v1.m_realsize, v2.m_realsize);

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i)
        v1.m_u64span[i] ^= v2.m_u64span[i];
}

void Val64::op_min(Val64& v1, Val64& v2, uint64_t& varcost)
{
    binop_v1_longest(v1, v2);

    // BIP 441:
    // |OP_MIN
    // |MAX(W(length(A)), W(length(B))) * OTHER
    varcost += varops::minmax_cost(v1.m_realsize, v2.m_realsize);

    if (cmp_span(v1.m_u64span, v2.m_u64span) > 0) {
        v1 = std::move(v2);
    }
    v1.trim_tail();
}

void Val64::op_max(Val64& v1, Val64& v2, uint64_t& varcost)
{
    binop_v1_longest(v1, v2);

    // BIP 441:
    // |OP_MAX
    // |MAX(W(length(A)), W(length(B))) * OTHER
    varcost += varops::minmax_cost(v1.m_realsize, v2.m_realsize);

    if (cmp_span(v1.m_u64span, v2.m_u64span) < 0) {
        v1 = std::move(v2);
    }
    v1.trim_tail();
}

void Val64::mul_span(std::span<le64_t> res,
                     std::span<le64_t> src,
                     uint64_t mul)
{
    // Result must be (at least) 1 word larger, for carry.
    assert(res.size() >= src.size() + 1);

    // Calculate this * mul, into res.
    res[0] = htole64_internal(0);
    for (size_t i = 0; i < src.size(); ++i) {
        const Uint128 product{Uint128::Mul(le64toh_internal(src[i]), mul, force_portable_math)};
        uint64_t hi{product.hi};
        uint64_t lo{product.lo};
        const uint64_t oldhi{le64toh_internal(res[i])};
        /* Note: hi cannot overflow since UINT64MAX * UINT64MAX
         * gives an upper u64 which is < UINT64MAX. */
        if (AddOverflow(lo, oldhi, lo)) hi++;
        res[i] = htole64_internal(lo);
        res[i+1] = htole64_internal(hi);
    }
}

Val64 Val64::op_mul(Val64 &v1, Val64 &v2)
{
    // Slightly more optimal if v1 is the larger operand.
    binop_v1_longest(v1, v2);

    // Result (worst case is sum of operand lengths)
    std::vector<unsigned char> retvec((v1.m_u64span.size() + v2.m_u64span.size()) * sizeof(uint64_t));
    Val64 ret(std::move(retvec));

    // Result of each v1[] * v2.
    std::vector<le64_t> scratch(v2.m_u64span.size() + 1);

    size_t ret_nonzero_len = 0;

    for (size_t i = 0; i < v1.m_u64span.size(); i++) {
        size_t nonzero_len;
        // Multiply v2 by v1[i] into scratch.
        mul_span(scratch, v2.m_u64span, v1.get(i));

        // Now add into result at offset i.
        // Cannot overflow.  Worst case ret effectively adds 1 to v1[i],
        // which *still* doesn't quite overflow.
        bool carry = add_span(ret.m_u64span.subspan(i, v2.m_u64span.size() + 1),
                              scratch, nonzero_len);
        assert(!carry);
        if (nonzero_len)
            ret_nonzero_len = i + nonzero_len;
    }

    ret.trim_tail(ret_nonzero_len);
    return ret;
}

// False iff v2 is 0.
bool Val64::div_mod(Val64 &v1, Val64 &v2, divmod_op op)
{
    // This is BasecaseDivRem from "Modern Computer Arithmetic" by Richard
    // Brent and Paul Zimmerman.  I discovered later that this is the same as
    // Knuth's TAOCP v2 (of course!) page 272, Algorithm D "Division of
    // non-negative integers".

    // For efficiency, the divisor (v2) needs to be *normalized*, i.e.
    // the top bit is set.  We trim and shift both to ensure this is true.

    // Note: this doesn't cost cost anything!  This is because any
    // bytes trimmed here (cost == number of bytes trimmed + 1) saves
    // costs below.
    v1.trim_tail();
    v2.trim_tail();

    // BIP 441:
    // |OP_DIV
    //...
    // If B is empty or all zeroes, fail.
    //...
    // |OP_MOD
    //...
    // If B is empty or all zeroes, fail.

    // Now there's only one canonical zero.
    if (v2.m_realsize == 0)
        return false;

    // How many bits do we have to shift to get top bit set?
    size_t k = std::countl_zero(v2.get(v2.m_u64span.size()-1));

    if (v1.m_realsize < v2.m_realsize) {
        // v2 > v1: v1 is remainder, quotient is 0.
        if (op == divmod_op::VAL64_DIV)
            v1 = Val64(0);
        return true;
    }

    // These might have to reallocate, but by no more than 8 bytes.
    // In theory, we could save this cost by doing shifting as we go.
    // But this shift isn't really the main overhead, so keep it simple.
    if (k != 0) {
        uint64_t varcost{0};
        // Val64(k) makes a one-limb temporary and varcost is discarded; both
        // are fine: this runs once per division and OP_DIV/OP_MOD pre-charge
        // their full cost.
        // k is at most 63, and max_size reserves one extra limb for normalization.
        const bool shifted{op_upshift(v1, Val64(k), v1.m_realsize + sizeof(uint64_t), varcost)};
        assert(shifted);
        bool overflow = v2.bitshift_up_small(k);
        assert(!overflow);
    }

    // Shift can add a few zero bytes, re-normalize.
    v1.trim_tail();
    v2.trim_tail();

    // v1 has n+m words, v2 has n words.  β is the base (2^64 here).
    assert(v1.m_u64span.size() >= v2.m_u64span.size());
    size_t n = v2.m_u64span.size();
    size_t m = v1.m_u64span.size() - n;

    // If we need quotient, create empty q vec, worst-case len.
    Val64 q;
    if (op == divmod_op::VAL64_DIV) {
        std::vector<unsigned char> qvec((m + 1) * sizeof(uint64_t));
        q.move_from_valtype(std::move(qvec));
    }

    // 1: if v1 >= β^m x v2, then q_m = 1, v1 = v1 - β^m x v2 else q_m = 0
    if (cmp_span(v1.m_u64span.subspan(m), v2.m_u64span) > -1) {
        size_t last_nonzero;
        if (op == divmod_op::VAL64_DIV)
            q.set(m, 1);
        bool carry = sub_span(v1.m_u64span.subspan(m), v2.m_u64span, last_nonzero);
        assert(!carry);
    } else {
        if (op == divmod_op::VAL64_DIV)
            q.set(m, 0);
    }

    // We need a temporary, but we overwrite it all, so create outside loop.
    std::vector<le64_t> scratch(v2.m_u64span.size() + 1);

    // 2: for j from m-1 downto 0 do:
    for (size_t j = m; j > 0;) {
        --j;

        // 3: q* = floor((v1_n+j_ x β + v1_n+j-1_) / v2_n-1_)
        const uint64_t v_hi{v1.get(n+j)};
        const uint64_t v_lo{v1.get(n+j-1)};
        const uint64_t divisor{v2.get(n-1)};
        const Div64Result div64{Uint128::FromParts(v_hi, v_lo).DivMod64(divisor, force_portable_math)};
        uint64_t qstar{div64.quotient};
        uint64_t rstar{div64.remainder};
        bool qstar_is_beta{div64.quotient_is_beta};
        bool rstar_overflow{false};
        if (qstar_is_beta) assert(n > 1);

        // Knuth suggests: test if q* == β, or
        // q* x v2_n-2_ > βr* + v1_n+j-2_.  If so, decrease q* by 1,
        // increase r* by v2_n-1_, and repeat if r* did not overflow β.
        if (n > 1) {
            const uint64_t v2_n2{v2.get(n - 2)};
            const uint64_t v1_nj2{v1.get(n + j - 2)};
            const uint64_t divisor{v2.get(n - 1)};

            auto product_greater_than_remainder = [&]() {
                const Uint128 product{Uint128::Mul(qstar, v2_n2, force_portable_math)};
                return product.hi > rstar || (product.hi == rstar && product.lo > v1_nj2);
            };

            while (qstar_is_beta || (!rstar_overflow && product_greater_than_remainder())) {
                if (qstar_is_beta) {
                    qstar_is_beta = false;
                } else {
                    qstar--;
                }

                rstar_overflow = AddOverflow(rstar, divisor, rstar);
            }
        }

        // This is our (64-bit) guess.
        uint64_t qj = qstar;

        // D4: v1 = v1 - q_j_ x β^j x v2

        // Assign scratch = q_j_ x v2
        // Note: v2 doesn't change in this loop, so scratch gets fully
        // overwritten each time, meaning we don't need to zero it.
        mul_span(scratch, v2.m_u64span, qj);

        bool underflow;
        size_t last_nonzero;
        underflow = sub_span(v1.m_u64span.subspan(j), scratch, last_nonzero);
        // D5: Set q_j_ = q*.  If the result of D4 was negative, go to D6.
        if (underflow) {
            // D6: Decrease q_j_ by 1, and add β^j x v2 to v1

            // Intuitively: we've got an estimate on v1/v2, using division on
            // the high words, plus a compensation from the next-highest.  It
            // could be an overestimate by one, however!  This path is covered
            // by the val64_div_mod_knuth_d6_add_back regression test.
            qj--;
            bool carry;
            size_t nonzero_len;
            carry = add_span(v1.m_u64span.subspan(j), v2.m_u64span, nonzero_len);
            assert(carry);
        }

        // Keep shrinking v1.  Note: we could use the sub/add_with_offset
        // return to trim a bit faster if we wanted.
        if (v1.m_u64span.size() > 0) {
            assert(v1.get(v1.m_u64span.size()-1) == 0);
            v1.truncate((v1.m_u64span.size()-1) * sizeof(uint64_t));
        }

        if (op == divmod_op::VAL64_DIV)
            q.set(j, qj);
    }

    switch (op) {
    case divmod_op::VAL64_MOD:
        // Remainder needs shifting back (quotient is unaffected, since
        // (A * N) / (B * N) == A / B).
        if (k != 0 && v1.m_realsize != 0)
            v1.bitshift_down(0, k);
        v1.trim_tail();
        return true;
    case divmod_op::VAL64_DIV:
        v1 = std::move(q);
        v1.trim_tail();
        return true;
    }
    assert(!"Invalid op");
}

bool Val64::op_div(Val64 &v1, Val64 &v2)
{
    return div_mod(v1, v2, divmod_op::VAL64_DIV);
}

bool Val64::op_mod(Val64 &v1, Val64 &v2)
{
    return div_mod(v1, v2, divmod_op::VAL64_MOD);
}
