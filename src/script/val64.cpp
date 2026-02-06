// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/val64.h>
#include <bit>
#include <cassert>
#include <cstring>
#include <memory>
#include <compat/endian.h>
#include <iostream>

// MSVC compatibility: __int128 and __builtin_add_overflow are not available
#if !defined(__SIZEOF_INT128__) && defined(_MSC_VER)
#define PORTABLE_64BIT_MATH 1
#endif


// For testing.
bool Val64::force_unaligned = false;
bool Val64::force_portable_math = false;
bool Val64::suppress_alignment_warnings = false;

void Val64::warn_alignment_once(const void *p, size_t len)
{
    static bool warned = false;

    if (warned || suppress_alignment_warnings)
        return;

    std::cerr
        << "WARNING: Vector pointer " << p
        << " size " << len
        << " is misaligned: performance may suffer"
        << std::endl;
    warned = true;
}

Val64::Val64(std::vector<unsigned char> &v)
{
    move_from_valtype(v);
}

size_t Val64::u64ptr_off() const
{
    const unsigned char *p = reinterpret_cast<const unsigned char *>(m_u64span.data());

    /* Sanity check it's in bounds */
    assert(p >= m_charvec.data());
    assert(p + m_realsize <= m_charvec.data() + m_charvec.size());

    return p - m_charvec.data();
}

// Only m_charvec is set: initialize other fields.
void Val64::set_span()
{
    m_realsize = m_charvec.size();

    // Round up to get number of u64s
    size_t u64size = (m_realsize + sizeof(uint64_t) - 1) / sizeof(uint64_t);

    // Enlarge if necessary (trailing zeroes are harmless in little-endian)
    if (m_charvec.size() < u64size * sizeof(uint64_t))
        m_charvec.insert(m_charvec.end(), u64size * sizeof(uint64_t) - m_charvec.size(), 0);

    // We are always 64-bit aligned, but we handle it if we're not.
    size_t space = m_charvec.size();
    void *ptr = m_charvec.data();
    if (std::align(alignof(uint64_t), u64size * sizeof(uint64_t), ptr, space) == m_charvec.data()
        && ptr == m_charvec.data()
        && !force_unaligned) {
        m_u64span = std::span<le64_t>(reinterpret_cast<uint64_t *>(m_charvec.data()), u64size);
        return;
    }

    Val64::warn_alignment_once(m_charvec.data(), m_charvec.size());

    // Append zeroes so we can move values.  This might change alignment.
    m_charvec.insert(m_charvec.end(), sizeof(uint64_t), 0);
    space = m_charvec.size();
    ptr = m_charvec.data();
    std::align(alignof(uint64_t), u64size * sizeof(uint64_t), ptr, space);

    // For testing, it will actually be aligned, so move a whole u64.
    if (force_unaligned && ptr == m_charvec.data())
        ptr = m_charvec.data() + sizeof(uint64_t);

    m_u64span = std::span<le64_t>(reinterpret_cast<uint64_t *>(ptr), u64size);

    // Figure out how much the offset now is, so we can move data.
    size_t off = u64ptr_off();
    memmove(m_charvec.data() + off, m_charvec.data(), u64size * sizeof(uint64_t));
}

// Remove offset because we're changing m_charvec.
void Val64::charvec_change_start()
{
    size_t off = u64ptr_off();
    if (off)
        m_charvec.erase(m_charvec.begin(), m_charvec.begin() + off);

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

void Val64::move_from_valtype(std::vector<unsigned char> &vch)
{
    m_charvec = std::move(vch);
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

Val64::Val64()
{
    set_span();
}

Val64::Val64(const Val64 &v)
{
    m_charvec = v.m_charvec;
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
    // We don't care how long it started, just what it could be now.
    m_realsize = m_u64span.size_bytes();

    charvec_change_start();
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
    m_charvec(std::move(other.m_charvec))
{
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

uint64_t Val64::to_u64_ceil(uint64_t max, size_t &varcost) const
{
    uint64_t v;

    // Worst case, we have to examine all bytes.
    varcost += m_realsize;

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

bool Val64::is_zero(size_t &varcost) const
{
    varcost += m_realsize;
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

    for (ptrdiff_t i = maxlen-1; i >= 0; --i) {
        uint64_t iv1, iv2;

        iv1 = size_t(i) < v1.size() ? le64toh_internal(v1[i]) : 0;
        iv2 = size_t(i) < v2.size() ? le64toh_internal(v2[i]) : 0;
        if (iv1 < iv2)
            return -1;
        if (iv1 > iv2)
            return 1;
    }
    return 0;
}

int Val64::cmp(const Val64 &v2, size_t &varcost) const
{
    varcost += std::max(m_realsize, v2.m_realsize);

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

        res = u1 + u2 + carry;
        if (res)
            nonzero_len = i + 1;
        v1[i] = htole64_internal(res);
        if (res > u1)
            carry = false;
        else {
            carry = (res < u1) || (res == u1 && u2 != 0);
        }
    }

    /* Carry forwards if required (continue even if not overflowing,
     * to set nonzero_len) */
    while (i < v1.size()) {
        uint64_t u1 = le64toh_internal(v1[i] + carry);
        v1[i] = htole64_internal(u1);
        if (u1)
            nonzero_len = i + 1;
        carry = carry && (u1 == 0);
        i++;
    }

    return carry;
}

void Val64::op_add(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_ADD
    // |Greater of two operand lengths * 4
    varcost += v1.m_realsize * 4;

    size_t nonzero_len;
    bool carry = add_span(v1.m_u64span, v2.m_u64span, nonzero_len);

    if (carry) {
        v1.append_one();
        return;
    }

    v1.trim_tail(nonzero_len);
}

void Val64::op_1add(Val64 &v1, size_t &varcost)
{
    Val64 v2(1);

    // BIP#ops:
    // |OP_1ADD
    // |MAX(1, operand length) * 3

    // BIP#ops:
    // OP_1ADD and OP_1SUB are the same cost as ADD/SUB with a minimal 1 operand.
    op_add(v1, v2, varcost);
}

// v1 -= v2
bool Val64::sub_span(std::span<le64_t> v1, std::span<le64_t> v2, size_t &nonzero_len)
{
    auto common_len = std::min(v1.size(), v2.size());

    // Little endian, underflow forward.
    bool underflow = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < common_len; ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh_internal(v1[i]);
        u2 = le64toh_internal(v2[i]);

        res = u1 - u2 - underflow;
        v1[i] = htole64_internal(res);
        if (res)
            nonzero_len = i + 1;
        if (res < u1)
            underflow = false;
        else {
            underflow = (res > u1) || (res == u1 && u2 != 0);
        }
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
        uint64_t u1 = le64toh_internal(v1[i]);
        v1[i] = htole64_internal(u1 - underflow);
        if (v1[i] != 0)
            nonzero_len = i + 1;
        underflow = (underflow && u1 == 0);
        i++;
    }

    return underflow;
}


bool Val64::op_sub(Val64 &v1, const Val64 &v2, size_t &varcost)
{
    // BIP#ops:
    // |OP_SUB
    // |Greater of two operand lengths * 3
    varcost += std::max(v1.m_realsize, v2.m_realsize) * 3;
    size_t nonzero_len;

    bool underflow = sub_span(v1.m_u64span, v2.m_u64span, nonzero_len);
    if (underflow)
        return false;

    v1.trim_tail(nonzero_len);
    return true;
}

bool Val64::op_1sub(Val64 &v1, size_t &varcost)
{
    const Val64 v2(1);

    return op_sub(v1, v2, varcost);
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
        uint64_t v = prevbits | (next << (64 - bits));
        set(i - words, v);
        prevbits = next >> bits;
    }
    // Shift the last word
    set(m_u64span.size() - 1 - words, prevbits);
}

void Val64::op_downshift(Val64 &v1, const Val64 &v2, size_t &varcost)
{
    uint64_t bits = v2.to_u64_ceil(v1.m_realsize * 8, varcost);
    size_t bytes = bits / 8;

    // BIP#ops:
    // |OP_DOWNSHIFT
    // |Length of BITS + MAX((Length of A - (Value of BITS) / 8), 0) * 2

    // We already added length of BITS in to_u64_ceil above.

    // Shift past end?  Empty.  Also covers empty array.
    if (bytes >= v1.m_realsize) {
        v1 = Val64(0);
        return;
    }

    // (Length of A - (Value of BITS) / 8) > 0.
    varcost += (v1.m_realsize - bytes) * 2;

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
bool Val64::op_upshift(Val64 &v1, const Val64 &v2, size_t max_size, size_t &varcost)
{
    uint64_t bits = v2.to_u64_ceil(max_size * 8 + 1, varcost);

    // BIP#ops:
    // |OP_UPSHIFT
    // ...

    // Cannot overflow: m_realsize is (far) less than 32 bits, so is max_size.
    if (bits + v1.m_realsize * 8 > max_size * 8)
        return false;

    // How many whole bytes should we prepend?
    size_t prebytes = bits / 8;

    // BIP#ops:
    // |OP_UPSHIFT
    // |Length of BITS + (Value of BITS) / 8 + Length of A (LENGTHCONV + ZEROING + COPYING).
    // If BITS % 8 != 0, add (Length of A) * 2.
    varcost += prebytes + v1.m_realsize;

    if (bits % 8 == 0) {
        // Simply insert bytes at the beginning.
        v1.prepend_zeros(prebytes);
    } else {
        varcost += v1.m_realsize * 2;
        // There's no nice C++ "add this many bytes at the beginning,
        // and one at the end" so we are actually best off prepending too
        // many bytes (fast!) and shifting backwards.
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
        uint64_t new_v = (old_v << bits) | prevbits;

        set(i, new_v);
        prevbits = old_v >> (64 - bits);
    }
    return (prevbits != 0);
}

void Val64::op_2mul(Val64 &v1, size_t &varcost)
{
    bool carry;

    // BIP#ops:
    // |OP_2MUL
    // |Operand length * 3
    varcost += v1.m_realsize * 3;

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.trim_tail();

    carry = v1.bitshift_up_small(1);

    if (carry)
        v1.append_one();
    else
        v1.trim_tail();
}

void Val64::op_2div(Val64 &v1, size_t &varcost)
{
    // BIP#ops:
    // |OP_2DIV
    // |Operand length
    varcost += v1.m_realsize * 2;

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.trim_tail();

    // bitshift_down assumes non-zero size.
    if (v1.m_realsize == 0)
        return;

    v1.bitshift_down(0, 1);
    v1.trim_tail();
}

void Val64::op_invert(Val64 &v1, size_t &varcost)
{
    // BIP#ops:
    // |OP_INVERT
    // |(Length of operand) * 2
    varcost += v1.m_realsize * 2;

    // Endian doesn't matter, so access raw.
    for (auto &v: v1.m_u64span) {
        v ^= UINT64_MAX;
    }
}

// Makes sure v1 is at least as long as v2.
void Val64::binop_v1_longest(Val64 &v1, Val64 &v2)
{
    // Make sure v1 is the longer one.
    if (v1.m_realsize < v2.m_realsize)
        v1.swap(v2);
}

void Val64::op_and(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_AND
    // |Sum of two operand lengths
    varcost += v1.m_realsize + v2.m_realsize;

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i) {
        v1.m_u64span[i] &= v2.m_u64span[i];
    }

    // Rest is 0.
    std::fill(v1.m_u64span.begin() + v2.m_u64span.size(), v1.m_u64span.end(), 0);
}

void Val64::op_or(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_OR
    // |(Lesser of the two operand lengths) * 2
    varcost += v2.m_realsize * 2;

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i)
        v1.m_u64span[i] |= v2.m_u64span[i];
}

void Val64::op_xor(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_XOR
    // |(Lesser of the two operand lengths) * 2
    varcost += v2.m_realsize * 2;

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i)
        v1.m_u64span[i] ^= v2.m_u64span[i];
}

void Val64::op_min(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_MIN
    // |(Greater of two operand lengths) * 2
    varcost += v1.m_realsize * 2;

    if (cmp_span(v1.m_u64span, v2.m_u64span) > 0) {
        v1 = std::move(v2);
    }
    v1.trim_tail();
}

void Val64::op_max(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_MAX
    // |(Greater of two operand lengths) * 2
    varcost += v1.m_realsize * 2;

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
        uint64_t hi, lo, oldhi;

        // Take advantage of 64 bit multiplier if platform has it
#if defined(__SIZEOF_INT128__)
        if (!force_portable_math) {
            unsigned __int128 product;
            product = ((unsigned __int128)(le64toh_internal(src[i]))) * mul;
            hi = static_cast<uint64_t>(product >> 64);
            lo = static_cast<uint64_t>(product & (unsigned __int128)UINT64_MAX);

            oldhi = le64toh_internal(res[i]);
            /* Note: hi cannot overflow since UINT64MAX * UINT64MAX
             * gives an upper u64 which is < UINT64MAX. */
#ifdef __has_builtin
#if __has_builtin(__builtin_add_overflow)
            if (__builtin_add_overflow(lo, oldhi, &lo))
                hi++;
#else
            // Fallback without __builtin_add_overflow
            uint64_t new_lo = lo + oldhi;
            if (new_lo < lo)  // overflow in addition
                hi++;
            lo = new_lo;
#endif
#else
            // Fallback for compilers without __has_builtin
            uint64_t new_lo = lo + oldhi;
            if (new_lo < lo)  // overflow in addition
                hi++;
            lo = new_lo;
#endif
        } else
#endif
        {
            // Portable fallback: 64x64->128 bit multiplication
            uint64_t a = le64toh_internal(src[i]);
            uint64_t a_lo = a & 0xFFFFFFFFULL;
            uint64_t a_hi = a >> 32;
            uint64_t b_lo = mul & 0xFFFFFFFFULL;
            uint64_t b_hi = mul >> 32;

            uint64_t p0 = a_lo * b_lo;
            uint64_t p1 = a_lo * b_hi;
            uint64_t p2 = a_hi * b_lo;
            uint64_t p3 = a_hi * b_hi;

            uint64_t carry = ((p0 >> 32) + (p1 & 0xFFFFFFFFULL) + (p2 & 0xFFFFFFFFULL)) >> 32;
            lo = p0 + (p1 << 32) + (p2 << 32);
            hi = p3 + (p1 >> 32) + (p2 >> 32) + carry;

            oldhi = le64toh_internal(res[i]);
            uint64_t new_lo = lo + oldhi;
            if (new_lo < lo)  // overflow in addition
                hi++;
            lo = new_lo;
        }
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
    Val64 ret(retvec);

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

    // BIP#ops:
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
        size_t varcost;
        // FIXME: create upshift which takes size_t to avoid Val64(k) here!
        op_upshift(v1, Val64(k), v1.m_realsize + sizeof(uint64_t), varcost);
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
        q.move_from_valtype(qvec);
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
    std::vector<le64_t> scratch((v2.m_u64span.size() + 1) * sizeof(uint64_t));

    // 2: for j from m-1 downto 0 do:
    for (ptrdiff_t j = m - 1; j >= 0; j--) {
        // 3: q* = floor((v1_n+j_ x β + v1_n+j-1_) / v2_n-1_)
        uint64_t qstar;
        uint64_t rstar;

#if defined(__SIZEOF_INT128__)
        if (!force_portable_math) {
            unsigned __int128 v;
            unsigned __int128 qstar128;
            unsigned __int128 rstar128;

            v = ((unsigned __int128)v1.get(n+j)) << 64 | v1.get(n+j-1);
            qstar128 = v / v2.get(n-1);

            // Knuth suggests: (notation reworked to match us, the rest is a
            // direct quote):

            // ... let r* be the remainder.
            // Now test if q* == β, or q* x v2_n-2_ > βr* + v1_n+j-2_:
            // if so, decrease q* by 1, increase r* by v2_n-1_, and
            // repeat this test if r* < β. (The test on v2_n-2_ determines at
            // high speed most of the cases in which the trial value q* is
            // one too large, and it eliminates /all/ cases where q* is
            // two too large
            rstar128 = v % v2.get(n-1);

            if ((qstar128 >> 64) != 0
                || (n > 1 && qstar128 * v2.get(n-2)
                    > (rstar128 << 64) + v1.get(n+j-2))) {
                qstar128--;
                rstar128 += v2.get(n-1);
                if ((rstar128 >> 64) == 0
                    && (n > 1 && qstar128 * v2.get(n-2)
                        > (rstar128 << 64) + v1.get(n+j-2))) {
                    qstar128--;
                }
            }
            qstar = static_cast<uint64_t>(qstar128);
            rstar = static_cast<uint64_t>(rstar128);
        } else
#endif
        {
            // Portable 128-bit by 64-bit division using 32-bit digits.
            // Based on Hacker's Delight divlu() and Knuth's Algorithm D.
            // Computes (v_hi:v_lo) / divisor where v_hi < divisor (guaranteed
            // since divisor is normalized with top bit set).
            uint64_t v_hi = v1.get(n+j);
            uint64_t v_lo = v1.get(n+j-1);
            uint64_t divisor = v2.get(n-1);

            if (v_hi >= divisor) {
                // Quotient would overflow 64 bits
                qstar = UINT64_MAX;
                rstar = v_hi - divisor; // Not accurate but will be corrected
            } else if (v_hi == 0) {
                // Simple case: dividend fits in 64 bits
                qstar = v_lo / divisor;
                rstar = v_lo % divisor;
            } else {
                // 128-bit by 64-bit division using 32-bit digit long division.
                // The divisor has its top bit set (normalized), so we can safely
                // use 32-bit chunks without overflow in intermediate calculations.
                constexpr uint64_t B = 1ULL << 32; // Base (2^32)

                // Split divisor into two 32-bit digits
                uint64_t d1 = divisor >> 32;      // High 32 bits of divisor
                uint64_t d0 = divisor & 0xFFFFFFFF; // Low 32 bits of divisor

                // The dividend is (v_hi : v_lo), treat as 4 32-bit digits:
                // v_hi = (u3 : u2), v_lo = (u1 : u0)
                // We compute quotient one 32-bit digit at a time.

                // First quotient digit q1: divide (v_hi : high32(v_lo)) by divisor
                // Since divisor is normalized and v_hi < divisor, we know the result fits in 32 bits.
                uint64_t u32 = v_hi; // This is the top 64 bits of the 96-bit partial dividend
                uint64_t u1 = v_lo >> 32;
                uint64_t u0 = v_lo & 0xFFFFFFFF;

                // Estimate q1 = floor(u32 / d1)
                uint64_t q1 = u32 / d1;
                uint64_t r1 = u32 % d1;

                // Refine: while q1 >= B or q1 * d0 > B * r1 + u1
                while (q1 >= B || q1 * d0 > (r1 << 32) + u1) {
                    q1--;
                    r1 += d1;
                    if (r1 >= B) break;
                }

                // Update partial remainder for next digit
                // u21 = (u32 * B + u1) - q1 * divisor
                // Note: u32 * B would overflow, but we can compute:
                // (r1 * B + u1) - q1 * d0 since u32 = q1 * d1 + r1
                // Actually: u21 = (r1 << 32) + u1 - q1 * d0
                // But we need to be careful about underflow.
                // Safer: u21 = u32 * B + u1 - q1 * divisor
                //           = (q1 * d1 + r1) * B + u1 - q1 * (d1 * B + d0)
                //           = q1 * d1 * B + r1 * B + u1 - q1 * d1 * B - q1 * d0
                //           = r1 * B + u1 - q1 * d0
                uint64_t u21 = (r1 << 32) + u1 - q1 * d0;

                // Second quotient digit q0: divide (u21 : u0) by divisor
                uint64_t q0 = u21 / d1;
                uint64_t r0 = u21 % d1;

                // Refine q0
                while (q0 >= B || q0 * d0 > (r0 << 32) + u0) {
                    q0--;
                    r0 += d1;
                    if (r0 >= B) break;
                }

                qstar = (q1 << 32) + q0;
                // Remainder = (r0 << 32) + u0 - q0 * d0
                rstar = (r0 << 32) + u0 - q0 * d0;
            }

            // Apply Knuth's test on v2[n-2] if available
            if (n > 1) {
                uint64_t v2_n2 = v2.get(n-2);
                uint64_t v1_nj2 = v1.get(n+j-2);
                uint64_t divisor = v2.get(n-1);
                // Test: if qstar * v2[n-2] > (rstar << 64) + v1[n+j-2]
                // Since rstar < divisor and divisor has top bit set, rstar < 2^63,
                // so if (rstar >> 63) != 0, the condition is false.
                while ((rstar >> 63) == 0) {
                    // Compute qstar * v2_n2 as 128-bit (prod_hi:prod_lo)
                    uint64_t prod_lo = qstar * v2_n2;
                    // For high part, use: a*b = (a_hi*B + a_lo)*(b_hi*B + b_lo)
                    // High 64 bits of 64x64->128 multiply:
                    uint64_t a_hi = qstar >> 32;
                    uint64_t a_lo = qstar & 0xFFFFFFFF;
                    uint64_t b_hi = v2_n2 >> 32;
                    uint64_t b_lo = v2_n2 & 0xFFFFFFFF;
                    // Note: a_hi * b_lo + a_lo * b_hi can overflow uint64_t,
                    // so we must track the carry separately.
                    uint64_t p1 = a_hi * b_lo;
                    uint64_t p2 = a_lo * b_hi;
                    uint64_t cross = p1 + p2;
                    uint64_t cross_carry = (cross < p1) ? (1ULL << 32) : 0;
                    uint64_t prod_hi = a_hi * b_hi + (cross >> 32) + cross_carry;
                    // Add carry from cross + (a_lo * b_lo >> 32)
                    uint64_t lo_cross = (a_lo * b_lo >> 32) + (cross & 0xFFFFFFFF);
                    prod_hi += (lo_cross >> 32);

                    // Compare (prod_hi:prod_lo) > (rstar:v1_nj2)
                    if (prod_hi > rstar || (prod_hi == rstar && prod_lo > v1_nj2)) {
                        qstar--;
                        rstar += divisor;
                        // If rstar overflowed (>= 2^64), stop
                        if (rstar < divisor) break;
                    } else {
                        break;
                    }
                }
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

            // FIXME: As Knuth points out, this is a hard to hit case:
            // solve Exercise 21 so we can test the damn thing!

            // Intuitively: we've got an estimate on v1/v2, using division on
            // the high words, plus a compensation from the next-highest.  It
            // could be an overestimate by one, however!
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

size_t Val64::op_mul_varcost(const Val64 &v1, const Val64 &v2)
{
    // BIP#ops:
    // |OP_MUL
    // |Length of A + length of B + (length of A + 7) / 8 * (length of B) * 6
    //  (BEWARE OVERFLOW)
    return v1.m_realsize + v2.m_realsize + (v1.m_realsize + 7) / 8 * uint64_t(v2.m_realsize) * 6;
}

size_t Val64::op_div_varcost(const Val64 &v1, const Val64 &v2)
{
    // BIP#ops:
    // |OP_DIV
    // |Length of A * 9 + length of B * 2 + (length of A)^2 / 3  (BEWARE OVERFLOW)
    return v1.m_realsize * 9 + v2.m_realsize * 2
        + uint64_t(v1.m_realsize) * uint64_t(v1.m_realsize) / 3;
}

size_t Val64::op_mod_varcost(const Val64 &v1, const Val64 &v2)
{
    // BIP#ops:
    // |OP_MOD
    // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4  (BEWARE OVERFLOW)
    return v1.m_realsize * 9 + v2.m_realsize * 2
        + uint64_t(v1.m_realsize) * uint64_t(v1.m_realsize) / 4;
}
