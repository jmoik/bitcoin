// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAL64_H
#define BITCOIN_SCRIPT_VAL64_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <span.h>
#include <compat/endian.h>

/**
 * This class is used for all modern taproot ops: this is
 * much more efficient for bit and arithmetic ops on large values.
 * Logical bytes start at u64ptr_off() inside m_charvec. Any bytes before or
 * after the logical range are representation padding and must remain zero.
 */
class Val64 {
protected:
    // Convenience typedef for clarity, where dealing with little-endian.
    typedef uint64_t le64_t;

    // Byte storage for the value plus possible alignment padding.
    std::vector<unsigned char> m_charvec;

    // Number of logical value bytes starting at u64ptr_off().
    size_t m_realsize;

    // Little-endian uint64_t span over the logical bytes and zero padding.
    std::span<le64_t> m_u64span;

    // Helper to set other fields after m_charvec is set, preserving the
    // invariant that logical bytes begin at u64ptr_off().
    void set_span();

    // Helpers to alter m_charvec.
    void charvec_change_start();
    void charvec_change_end();

    // Are we actually offset within m_charvec?
    size_t u64ptr_off() const;

#ifdef DEBUG
    void check_invariants() const;
#endif

    // Append a 1 byte to the value (for carry)
    void append_one();

    // Remove this many bytes from the front.
    void remove_front(size_t bytes);

    // Prepend this many zero bytes to the front.
    void prepend_zeros(size_t prebytes);

    // Trim to this length.
    void truncate(size_t new_realsize);

public:
    Val64();
    Val64(std::vector<unsigned char>&& v);

    // Make a (minimal) val64 from a uint64_t
    explicit Val64(uint64_t v);

    // Move constructor
    Val64(Val64&& other) noexcept;
    // Move assignment operator
    Val64& operator=(Val64&& other) noexcept;

    void move_from_valtype(std::vector<unsigned char>&& bytes);

    // Convert to a valtype: CLEARS THE VAL64!
    std::vector<unsigned char> move_to_valtype();

    // Trim trailing zero bytes so serialization is minimal.
    void normalize();

    // Byte size of the value.
    size_t size() const { return m_realsize; }

    // Costless overloads (caller charges via varops:: cost functions).
    bool is_zero() const;
    int cmp(const Val64 &v2) const;

    // &varcost here is always increased by the operation.

    // Convert to a 64 bit, or max if it's too large.
    uint64_t to_u64_ceil(uint64_t max, uint64_t& varcost) const;

    // Invert this to convert to boolean.
    bool is_zero(uint64_t& varcost) const;

    // Returns -1 if this < v2, 0 if equal, 1 if this > v2.
    int cmp(const Val64& v2, uint64_t& varcost) const;

    // We use explicit names here, to show that these are *not* generic operations, but consensus constrained.
    static void op_add(Val64& v1, Val64& v2, uint64_t& varcost);
    static void op_1add(Val64& v1, uint64_t& varcost);

    // if v1 < v2: returns false, mangles v1.
    // otherwise: returns true, sets v1 to v1 - v2.
    static bool op_sub(Val64& v1, const Val64& v2, uint64_t& varcost);
    static bool op_1sub(Val64& v1, uint64_t& varcost);

    // Returns false if v1 would exceed max_size.
    static bool op_upshift(Val64& v1, const Val64& v2, size_t max_size, uint64_t& varcost);
    static void op_downshift(Val64& v1, const Val64& v2, uint64_t& varcost);

    // Like shift 1, but normalize.
    static void op_2mul(Val64& v1, uint64_t& varcost);
    static void op_2div(Val64& v1, uint64_t& varcost);

    static void op_invert(Val64& v1, uint64_t& varcost);

    static void op_and(Val64& v1, Val64& v2, uint64_t& varcost);
    static void op_or(Val64& v1, Val64& v2, uint64_t& varcost);
    static void op_xor(Val64& v1, Val64& v2, uint64_t& varcost);

    static void op_min(Val64& v1, Val64& v2, uint64_t& varcost);
    static void op_max(Val64& v1, Val64& v2, uint64_t& varcost);

    // Non-const, since might switch variables.
    static Val64 op_mul(Val64 &v1, Val64 &v2);

    // Returns false if v2 is 0.
    static bool op_div(Val64 &v1, Val64 &v2);
    static bool op_mod(Val64 &v1, Val64 &v2);

protected:
    // Copy constructor, useful for tests.
    Val64(const Val64 &);

    // Swap with the other value
    void swap(Val64& other) noexcept;

    // Endian fixers - inline for performance
    inline void set(size_t index, uint64_t v)
    {
        m_u64span[index] = htole64_internal(v);
    }

    inline uint64_t get(size_t index) const
    {
        return le64toh_internal(m_u64span[index]);
    }

    // If it's past the end, return 0.
    uint64_t get_or_zero(size_t index) const;

    // We've treated this as a u64 array, now trim trailing zero bytes.
    void trim_tail();

    // Fast version, if we know some zeros already.
    void trim_tail(size_t nonzero_len);

    // Swap v1 and v2 so v1 is always longer or same size than v2.
    static void binop_v1_longest(Val64 &v1, Val64 &v2);

    // Right shift by this many words, and this many bits (1-63 incl).
    void bitshift_down(size_t words, size_t bits);

    // Left shift in place by this many bits (1-64 incl)
    // Return true iff we had overflow.
    bool bitshift_up_small(size_t bits);

    // False if any non-zero bytes in span.
    static bool span_is_allzero(std::span<le64_t> span);

    // (*this) cmp (v2 << shift_words*64)
    static int cmp_span(std::span<le64_t> v1, std::span<le64_t> v2);

    // v1 += v2, return carry.  v1.size() >= v2.size().
    // If returns false, nonzero_len is one past the last non-zero u64 in v1
    // (which helps optimize trim_tail)
    static bool add_span(std::span<uint64_t> v1, std::span<uint64_t> v2, size_t &nonzero_len);

    // v1 -= v2, returns underflow.
    // If returns false, nonzero_len is one past the last non-zero u64 in v1
    // (which helps optimize trim_tail)
    static bool sub_span(std::span<le64_t> v1, std::span<le64_t> v2, size_t &nonzero_len);

    // res = src * mul
    static void mul_span(std::span<le64_t> res,
                         std::span<le64_t> src,
                         uint64_t mul);

    enum class divmod_op {
        VAL64_DIV,
        VAL64_MOD,
    };

    // Div: v1 = v1 / v2.  Mod: v1 = v1 % v2.  False if v2 is zero.
    static bool div_mod(Val64 &v1, Val64 &v2, divmod_op op);

    // Test helpers
    static bool force_offset_span;
    static bool force_portable_math;
};

#endif // BITCOIN_SCRIPT_VAL64_H
