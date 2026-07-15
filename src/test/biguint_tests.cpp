// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/common.h>
#include <script/biguint.h>
#include <test/util/biguint.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(biguint_tests, BasicTestingSetup)

using Bytes = std::vector<unsigned char>;

// Resize/create vector so this bit will fit
static Bytes SizedForBit(size_t bit, Bytes v = {})
{
    if (v.size() < (bit + 8) / 8) v.resize((bit + 8) / 8);
    return v;
}

// Set bit or create vector with this bit set.
static Bytes WithBit(size_t bit, Bytes v = {})
{
    v = SizedForBit(bit, std::move(v));
    v[bit / 8] |= (1 << (bit % 8));
    return v;
}

// A BigUint holding a copy of `bytes`.
static BigUint Num(const Bytes& bytes)
{
    return BigUint{Bytes{bytes}};
}

// A BigUint holding `value` as one full limb, with trailing zero bytes.
static BigUint FullLimb(uint64_t value)
{
    Bytes bytes(8);
    WriteLE64(bytes.data(), value);
    return BigUint{std::move(bytes)};
}

// `bytes` with `value` appended as one more limb.
static Bytes WithLimb(Bytes bytes, uint64_t value)
{
    unsigned char limb[8];
    WriteLE64(limb, value);
    bytes.insert(bytes.end(), limb, limb + 8);
    return bytes;
}

// `bytes`, zero-padded to whole limbs.
static Bytes Padded(Bytes bytes)
{
    bytes.resize((bytes.size() + 7) / 8 * 8);
    return bytes;
}

BOOST_AUTO_TEST_CASE(valtype_conversion)
{
    // Stack element bytes and the limbs they read as once zero-padded.
    const std::vector<std::pair<Bytes, std::vector<uint64_t>>> cases{
        {{}, {}},
        {{0}, {0}},
        {{1}, {1}},
        {{1, 2}, {0x0201}},
        {{1, 2, 0}, {0x0201}},
        {{1, 0, 0, 0, 0, 0, 0, 2}, {0x0200000000000001}},
        {{1, 0, 0, 0, 0, 0, 0, 2, 7}, {0x0200000000000001, 7}},
        // Zero limbs are kept.
        {{1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0}, {0x0200000000000001, 0}},
        {{1, 0, 0, 0, 0, 0, 0, 2, 3, 0, 0, 0, 0, 0, 0, 2}, {0x0200000000000001, 0x0200000000000003}},
    };
    for (const auto& [bytes, expected_limbs] : cases) {
        const Bytes padded{Padded(bytes)};
        const biguint::ConstLimbs limbs{padded};
        std::vector<uint64_t> actual_limbs;
        for (size_t i{0}; i < limbs.size(); ++i) actual_limbs.push_back(limbs[i]);
        BOOST_CHECK(actual_limbs == expected_limbs);

        // A BigUint returns the stack element it took.
        BOOST_CHECK(Num(bytes).MoveToValtype() == bytes);
    }
}

BOOST_AUTO_TEST_CASE(limbs_need_no_alignment)
{
    for (size_t offset{0}; offset < 8; ++offset) {
        Bytes storage(offset + 16, 0xee);
        const biguint::Limbs limbs{std::span{storage}.subspan(offset, 16)};
        limbs.Set(0, 0x0807060504030201);
        limbs.Set(1, 0x100f0e0d0c0b0a09);
        for (size_t i{0}; i < 16; ++i) BOOST_CHECK_EQUAL(storage[offset + i], i + 1);
        BOOST_CHECK_EQUAL(limbs[0], 0x0807060504030201U);
        BOOST_CHECK_EQUAL(limbs[1], 0x100f0e0d0c0b0a09U);
        BOOST_CHECK_EQUAL(limbs.subspan(1)[0], 0x100f0e0d0c0b0a09U);
    }
}

BOOST_AUTO_TEST_CASE(and_or_xor)
{
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 128; j++) {
            Bytes expected_and, expected_or, expected_xor;

            expected_or = WithBit(j, WithBit(i, expected_or));
            if (i != j) {
                expected_and = SizedForBit(i, SizedForBit(j));
                expected_xor = expected_or;
            } else {
                expected_and = WithBit(i);
                expected_xor = SizedForBit(i);
            }

            // AND test
            {
                BigUint v64a{WithBit(i)};
                BigUint v64b{WithBit(j)};
                BigUint::OpAnd(v64a, v64b);
                BOOST_CHECK(v64a.MoveToValtype() == expected_and);
            }

            // OR test
            {
                BigUint v64a{WithBit(i)};
                BigUint v64b{WithBit(j)};
                BigUint::OpOr(v64a, v64b);
                BOOST_CHECK(v64a.MoveToValtype() == expected_or);
            }

            // XOR test
            {
                BigUint v64a{WithBit(i)};
                BigUint v64b{WithBit(j)};
                BigUint::OpXor(v64a, v64b);
                BOOST_CHECK(v64a.MoveToValtype() == expected_xor);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(invert_clears_word_padding)
{
    for (size_t width{1}; width < sizeof(uint64_t); ++width) {
        Bytes input(width);
        Bytes expected(width);
        for (size_t i{0}; i < width; ++i) {
            input[i] = static_cast<unsigned char>(width * 17 + i);
            expected[i] = static_cast<unsigned char>(~input[i]);
        }

        BigUint value{std::move(input)};
        BigUint::OpInvert(value);

        BOOST_CHECK_EQUAL(value.size(), width);
        // Inverted padding would make the value compare greater.
        BOOST_CHECK_EQUAL(value.Compare(Num(expected)), 0);
        BOOST_CHECK(value.MoveToValtype() == expected);
    }
}

BOOST_AUTO_TEST_CASE(add)
{
    // Add two bits, check result.
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 128; j++) {
            BigUint v64a{WithBit(i)};
            BigUint v64b{WithBit(j)};
            BigUint::OpAdd(v64a, v64b);

            // Check against expected vector.
            Bytes expected;
            if (i != j) {
                expected = WithBit(i);
                expected = WithBit(j, expected);
            } else {
                expected = WithBit(i + 1);
            }
            BOOST_CHECK(v64a.MoveToValtype() == expected);
        }
    }

    // Overflow tests.
    for (size_t i = 1; i < 24; i++) {
        BigUint v64a{Bytes(i, 0xff)};
        BigUint v64b{Bytes{1}};
        BigUint::OpAdd(v64a, v64b);

        Bytes expect(i, 0);
        expect.push_back(1);
        BOOST_CHECK(v64a.MoveToValtype() == expect);
    }
}

BOOST_AUTO_TEST_CASE(sub)
{
    // A failed subtraction leaves a value that can be returned.
    {
        BigUint smaller{Bytes{0xb2, 0x89}};
        const BigUint larger{Bytes{0x16, 0xaa, 0x73, 0x3d}};
        BOOST_CHECK(!BigUint::OpSub(smaller, larger));
        smaller.MoveToValtype();
    }

    // Sub zero (unchanged).
    for (size_t i = 0; i < 128; i++) {
        // Subtract 0, should not change.
        BigUint v64a{WithBit(i)};
        const BigUint v64zero{Bytes{}};

        BOOST_CHECK(BigUint::OpSub(v64a, v64zero));
        BOOST_CHECK(v64a.MoveToValtype() == WithBit(i));
    }

    // Sub one.
    for (size_t i = 63; i < 128; i++) {
        BigUint v64a{WithBit(i)};
        const BigUint v64one{Bytes{1}};

        BOOST_CHECK(BigUint::OpSub(v64a, v64one));

        Bytes expected;
        for (size_t j = 0; j < i; j++) expected = WithBit(j, expected);

        BOOST_CHECK(v64a.MoveToValtype() == expected);
    }
}

BOOST_AUTO_TEST_CASE(add_sub_one_min_max)
{
    // 1ADD and 1SUB return minimal results, whatever the operand's encoding.
    for (const auto& [operand, expected] : std::vector<std::pair<Bytes, Bytes>>{
             {{}, {1}},
             {{0, 0}, {1}},
             {{0xff}, {0, 1}},
             {{0xff, 0}, {0, 1}},
             {Bytes(8, 0xff), {0, 0, 0, 0, 0, 0, 0, 0, 1}},
             {{1, 0, 0, 0, 0, 0, 0, 0, 0}, {2}},
         }) {
        BigUint sum{Num(operand)};
        BigUint::Op1Add(sum);
        BOOST_CHECK(sum.MoveToValtype() == expected);

        BigUint difference{Num(expected)};
        BOOST_CHECK(BigUint::Op1Sub(difference));
        BOOST_CHECK(difference.MoveToValtype() == TrimTrailingZeros(operand));
    }

    // 1SUB fails on zero, including non-minimal zero, and leaves a value that
    // can be returned.
    for (const Bytes& zero : {Bytes{}, Bytes{0}, Bytes(9, 0)}) {
        BigUint value{Num(zero)};
        BOOST_CHECK(!BigUint::Op1Sub(value));
        value.MoveToValtype();
    }

    // MIN and MAX return the minimal encoding of the selected operand, in either
    // operand order and when the operands are equal.
    for (const auto& [smaller, larger] : std::vector<std::pair<Bytes, Bytes>>{
             {{5, 0, 0}, {7}},
             {{}, {0, 0}},
             {{0xff, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 1}},
             {{2, 0, 0, 0, 0, 0, 0, 0, 1}, {3, 0, 0, 0, 0, 0, 0, 0, 1, 0}},
             {{4, 0}, {4}},
         }) {
        for (const bool swapped : {false, true}) {
            const Bytes& first{swapped ? larger : smaller};
            const Bytes& second{swapped ? smaller : larger};
            BigUint min_first{Num(first)}, min_second{Num(second)};
            BigUint::OpMin(min_first, min_second);
            BOOST_CHECK(min_first.MoveToValtype() == TrimTrailingZeros(smaller));
            BigUint max_first{Num(first)}, max_second{Num(second)};
            BigUint::OpMax(max_first, max_second);
            BOOST_CHECK(max_first.MoveToValtype() == TrimTrailingZeros(larger));
        }
    }
}

BOOST_AUTO_TEST_CASE(cmp)
{
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 128; j++) {
            const BigUint v64a{WithBit(i)};
            const BigUint v64b{WithBit(j)};
            int res = v64a.Compare(v64b);

            const int expected{i == j ? 0 : i > j ? 1 : -1};
            BOOST_CHECK(res == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(upshift)
{
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 128; j++) {
            BigUint v64a{WithBit(i)};
            BOOST_CHECK(BigUint::OpUpShift(v64a, FullLimb(j), 1000));

            Bytes expected = WithBit(i + j);
            // Definitionally, upshift inserts an extra (j + 7) / 8 bytes.
            expected.resize(1 + i / 8 + (j + 7) / 8);

            BOOST_CHECK(v64a.MoveToValtype() == expected);
        }
    }

    for (size_t i = 0; i < 1000; i++) {
        size_t len1 = m_rng.randrange(500);
        size_t sbits = m_rng.randrange(500 * 8);

        Bytes v1 = m_rng.randbytes(len1);

        // The result keeps every prepended byte, even a zero top byte.
        const size_t expected_len = len1 + sbits / 8 + (sbits % 8 ? 1 : 0);
        const Bytes expect = ShiftLeftFixed(v1, sbits, expected_len);

        // BigUint version
        BigUint v64(std::move(v1));
        BOOST_CHECK(BigUint::OpUpShift(v64, FullLimb(sbits), 5000));
        BOOST_CHECK(v64.MoveToValtype() == expect);
    }

    // The result may not exceed the size limit.
    BigUint at_limit{Bytes(10, 0xff)};
    BOOST_CHECK(BigUint::OpUpShift(at_limit, FullLimb(8 * 6), 16));
    BigUint over_limit{Bytes(10, 0xff)};
    BOOST_CHECK(!BigUint::OpUpShift(over_limit, FullLimb(8 * 6 + 1), 16));
}

BOOST_AUTO_TEST_CASE(downshift)
{
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 128; j++) {
            Bytes va = WithBit(i);
            BOOST_CHECK(va.size() == (i + 8) / 8);
            BigUint v64a(std::move(va));
            BigUint::OpDownShift(v64a, FullLimb(j));

            Bytes expected;
            if (j <= i) expected = WithBit(i - j);

            // Definitionally, downshift only removes one byte for every 8 bits shifted.
            if (j / 8 <= (i + 8) / 8) expected.resize((i + 8) / 8 - j / 8);

            BOOST_CHECK(v64a.MoveToValtype() == expected);
        }
    }

    for (size_t i = 0; i < 1000; i++) {
        size_t len1 = m_rng.randrange(500);
        size_t sbits = m_rng.randrange(500 * 8);

        Bytes v1 = m_rng.randbytes(len1);

        // We subtract only whole bytes from length.
        const size_t expected_len = v1.size() > sbits / 8 ? v1.size() - sbits / 8 : 0;
        const Bytes expect = ShiftRightFixed(v1, sbits, expected_len);

        // BigUint version
        BigUint v64(std::move(v1));
        BigUint::OpDownShift(v64, FullLimb(sbits));
        BOOST_CHECK(v64.MoveToValtype() == expect);
    }
}

BOOST_AUTO_TEST_CASE(add_limbs)
{
    Bytes result(16);
    const biguint::Limbs res{result};

    const Bytes u64_max(8, 0xff), u64_zero(8, 0), one{Padded({1})};
    size_t top;

    // Add zero at offset 0.
    BOOST_CHECK(!biguint::Add(res, biguint::ConstLimbs{u64_zero}, &top));
    BOOST_CHECK(res[0] == 0);
    BOOST_CHECK(res[1] == 0);
    BOOST_CHECK(top == 0);

    // Add at offset 0.
    BOOST_CHECK(!biguint::Add(res, biguint::ConstLimbs{u64_max}, &top));
    BOOST_CHECK(res[0] == UINT64_MAX);
    BOOST_CHECK(res[1] == 0);
    BOOST_CHECK(top == 1);

    // Add at offset 1. `top` is relative to the limbs added into.
    BOOST_CHECK(!biguint::Add(res.subspan(1), biguint::ConstLimbs{u64_max}, &top));
    BOOST_CHECK(res[0] == UINT64_MAX);
    BOOST_CHECK(res[1] == UINT64_MAX);
    BOOST_CHECK(top == 1);

    // Add one more, should carry.
    BOOST_CHECK(biguint::Add(res.subspan(1), biguint::ConstLimbs{one}));
    BOOST_CHECK(res[0] == UINT64_MAX);
    BOOST_CHECK(res[1] == 0);

    // A carry propagates through the longer operand; `top` covers limbs it did not reach.
    Bytes longer(32, 0);
    const biguint::Limbs l{longer};
    l.Set(0, UINT64_MAX);
    l.Set(2, 5);
    BOOST_CHECK(!biguint::Add(l, biguint::ConstLimbs{one}, &top));
    BOOST_CHECK(l[0] == 0 && l[1] == 1 && l[2] == 5 && l[3] == 0);
    BOOST_CHECK(top == 3);
}

BOOST_AUTO_TEST_CASE(subtract_limbs)
{
    Bytes result(16, 0xff);
    const biguint::Limbs res{result};

    const Bytes u64_max(8, 0xff), u64_zero(8, 0), one{Padded({1})};
    size_t top;

    // Subtract zero at offset 0.
    BOOST_CHECK(!biguint::Subtract(res, biguint::ConstLimbs{u64_zero}, &top));
    BOOST_CHECK(res[0] == UINT64_MAX);
    BOOST_CHECK(res[1] == UINT64_MAX);
    BOOST_CHECK(top == 2);

    // Subtract at offset 1.
    BOOST_CHECK(!biguint::Subtract(res.subspan(1), biguint::ConstLimbs{u64_max}, &top));
    BOOST_CHECK(res[0] == UINT64_MAX);
    BOOST_CHECK(res[1] == 0);
    BOOST_CHECK(top == 0);

    // Subtract at offset 0.
    BOOST_CHECK(!biguint::Subtract(res, biguint::ConstLimbs{u64_max}, &top));
    BOOST_CHECK(res[0] == 0);
    BOOST_CHECK(res[1] == 0);
    BOOST_CHECK(top == 0);

    // Subtract one more, should underflow.
    BOOST_CHECK(biguint::Subtract(res.subspan(1), biguint::ConstLimbs{one}));

    // A longer subtrahend underflows only if its excess limbs are nonzero.
    Bytes short_value{Padded({7})};
    Bytes long_zero_padded(24, 0);
    long_zero_padded[0] = 3;
    BOOST_CHECK(!biguint::Subtract(biguint::Limbs{short_value}, biguint::ConstLimbs{long_zero_padded}, &top));
    BOOST_CHECK(biguint::ConstLimbs{short_value}[0] == 4);
    BOOST_CHECK(top == 1);
    long_zero_padded[16] = 1;
    BOOST_CHECK(biguint::Subtract(biguint::Limbs{short_value}, biguint::ConstLimbs{long_zero_padded}));
}

BOOST_AUTO_TEST_CASE(mul_limbs)
{
    // Multiply powers of two by powers of two, and by zero.
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 65; j++) {
            const Bytes source{Padded(WithBit(i))};
            const biguint::ConstLimbs b{source};
            const uint64_t multiplier{j == 64 ? 0 : uint64_t{1} << j};

            // Adding into zero leaves the product, with the carry as its top limb.
            Bytes product(source.size());
            const uint64_t carry{biguint::AddMul(biguint::Limbs{product}, b, multiplier)};
            product = WithLimb(std::move(product), carry);
            Bytes expected(product.size());
            if (j != 64) expected = WithBit(i + j, expected);
            BOOST_CHECK(product == expected);

            // Subtracting it again borrows the carry.
            product.resize(source.size());
            BOOST_CHECK_EQUAL(biguint::SubMul(biguint::Limbs{product}, b, multiplier), carry);
            BOOST_CHECK(biguint::IsZero(biguint::ConstLimbs{product}));
        }
    }
}

BOOST_AUTO_TEST_CASE(shift_limbs)
{
    for (size_t limbs{0}; limbs < 5; ++limbs) {
        const Bytes original{m_rng.randbytes(8 * limbs)};
        for (unsigned bits{0}; bits < 64; ++bits) {
            // Up by up to 63 bits: the bits shifted out are returned.
            Bytes up{original};
            const uint64_t carry{biguint::ShiftUp(biguint::Limbs{up}, bits)};
            Bytes expected_up{ShiftLeftFixed(original, bits, original.size() + 8)};
            BOOST_CHECK(WithLimb(up, carry) == expected_up);
        }
        // Down by any amount, including whole bytes, whole limbs and past the end.
        for (uint64_t bits : {0U, 1U, 7U, 8U, 16U, 24U, 63U, 64U, 65U, 72U, 128U, 129U, 136U, 255U, 256U, 312U, 320U, 1000U}) {
            Bytes down{original};
            biguint::ShiftDown(biguint::Limbs{down}, bits);
            const size_t shifted_bytes{static_cast<size_t>(std::min<uint64_t>(bits / 8, original.size()))};
            Bytes expected_down(original.size());
            if (bits < 8 * original.size()) {
                expected_down = ShiftRightFixed(original, bits, original.size() - shifted_bytes);
                expected_down.resize(original.size());
            }
            BOOST_CHECK(down == expected_down);
        }
    }
}

BOOST_AUTO_TEST_CASE(compare_limbs)
{
    const Bytes a{Padded({1, 0, 0, 0, 0, 0, 0, 0, 1})}, b{Padded({2, 0, 0, 0, 0, 0, 0, 0, 1})};
    const Bytes zero(24, 0), wide_one{Padded({1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})};
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{a}, biguint::ConstLimbs{b}), -1);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{b}, biguint::ConstLimbs{a}), 1);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{a}, biguint::ConstLimbs{a}), 0);
    // Missing limbs count as zero, whichever operand is longer.
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{wide_one}, biguint::ConstLimbs{b}), -1);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{b}, biguint::ConstLimbs{wide_one}), 1);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{zero}, biguint::ConstLimbs{wide_one}), -1);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{wide_one}, biguint::ConstLimbs{zero}), 1);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{wide_one}, biguint::ConstLimbs{a}.first(1)), 0);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{zero}, biguint::ConstLimbs{}), 0);
    BOOST_CHECK_EQUAL(biguint::Compare(biguint::ConstLimbs{}, biguint::ConstLimbs{zero}), 0);
    BOOST_CHECK(biguint::IsZero(biguint::ConstLimbs{zero}));
    BOOST_CHECK(biguint::IsZero(biguint::ConstLimbs{}));
    BOOST_CHECK(!biguint::IsZero(biguint::ConstLimbs{wide_one}));
    BOOST_CHECK(!biguint::IsZero(biguint::ConstLimbs{a}.subspan(1)));
}

BOOST_AUTO_TEST_CASE(mul)
{
    constexpr size_t POWER_OF_TWO_BITS{128};
    constexpr size_t RHS_BOUNDARY_BITS{129};

    // Test 2^lhs_bit * 2^rhs_bit = 2^(lhs_bit + rhs_bit).
    for (size_t lhs_bit = 0; lhs_bit < POWER_OF_TWO_BITS; lhs_bit++) {
        for (size_t rhs_bit = 0; rhs_bit < RHS_BOUNDARY_BITS; rhs_bit++) {
            const BigUint v64a{WithBit(lhs_bit)};
            const BigUint v64b{WithBit(rhs_bit)};
            BOOST_CHECK(BigUint::OpMul(v64a, v64b).MoveToValtype() == WithBit(lhs_bit + rhs_bit));
        }

        const BigUint v64a{WithBit(lhs_bit)};
        const BigUint v64b{Bytes{}};
        BOOST_CHECK(BigUint::OpMul(v64a, v64b).MoveToValtype().empty());
    }

    // Test (2^bits - 1) * 2^shift.
    for (size_t bits = 1; bits < POWER_OF_TWO_BITS; bits++) {
        for (size_t shift = 0; shift < POWER_OF_TWO_BITS; shift++) {
            Bytes va((bits + 7) / 8, 0xff);
            const size_t high_byte_bits = bits % 8;
            if (high_byte_bits != 0) {
                va.back() = static_cast<unsigned char>((1U << high_byte_bits) - 1);
            }
            const Bytes expected{TrimTrailingZeros(ShiftLeftFixed(va, shift, (bits + shift + 7) / 8))};

            const BigUint v64a{std::move(va)};
            const BigUint v64b{WithBit(shift)};
            BOOST_CHECK(BigUint::OpMul(v64a, v64b).MoveToValtype() == expected);
        }
    }

    // (2^64 - 1)^2 = 2^128 - 2^65 + 1
    {
        const BigUint max_u64{Bytes(8, 0xff)};
        const Bytes expected{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        BOOST_CHECK(BigUint::OpMul(max_u64, max_u64).MoveToValtype() == expected);
    }

    // The product can be built in caller-provided storage.
    {
        const BigUint a{Bytes{0xff, 0xff}}, b{Bytes(9, 0x02)};
        BOOST_CHECK_EQUAL(BigUint::ProductSize(a, b), 24U);
        Bytes storage(BigUint::ProductSize(a, b));
        const unsigned char* const data{storage.data()};
        BigUint product{BigUint::OpMul(a, b, std::move(storage))};
        BOOST_CHECK(product.MoveToValtype().data() == data);
    }
}

BOOST_AUTO_TEST_CASE(op2mul)
{
    for (size_t i = 0; i < 129; i++) {
        for (size_t j = 0; j < 16; j++) {
            Bytes va;

            // Test zero case
            if (i != 128) va = WithBit(i);

            // Append empty bytes (shouldn't make a difference)
            va.insert(va.end(), j, 0);

            BigUint v64a(std::move(va));
            BigUint::Op2Mul(v64a);

            Bytes expected;
            if (i != 128) expected = WithBit(i + 1);
            BOOST_CHECK(v64a.MoveToValtype() == expected);
        }
    }

    for (size_t i = 0; i < 1000; i++) {
        size_t len1 = m_rng.randrange(500);
        Bytes v1 = m_rng.randbytes(len1);

        const Bytes expect{TrimTrailingZeros(ShiftLeftFixed(v1, 1, v1.size() + 1))};

        // BigUint version
        BigUint v64(std::move(v1));
        BigUint::Op2Mul(v64);
        BOOST_CHECK(v64.MoveToValtype() == expect);
    }
}

BOOST_AUTO_TEST_CASE(op2div)
{
    {
        constexpr size_t padded_size{64 * 1024};
        Bytes padded_one(padded_size, 0);
        padded_one.front() = 1;
        BigUint padded_value(std::move(padded_one));
        BigUint::Op2Div(padded_value);
        BOOST_CHECK(padded_value.MoveToValtype().empty());
    }

    for (size_t i = 0; i < 129; i++) {
        for (size_t j = 0; j < 16; j++) {
            Bytes va;

            // Test zero case
            if (i != 128) va = WithBit(i);

            // Append empty bytes (shouldn't make a difference)
            va.insert(va.end(), j, 0);

            BigUint v64a(std::move(va));
            BigUint::Op2Div(v64a);

            Bytes expected;
            if (i > 0 && i != 128) expected = WithBit(i - 1);
            BOOST_CHECK(v64a.MoveToValtype() == expected);
        }
    }

    for (size_t i = 0; i < 1000; i++) {
        size_t len1 = m_rng.randrange(500);
        Bytes v1 = m_rng.randbytes(len1);

        const Bytes expect{TrimTrailingZeros(ShiftRightFixed(v1, 1, v1.size()))};

        // BigUint version
        BigUint v64(std::move(v1));
        BigUint::Op2Div(v64);
        BOOST_CHECK(v64.MoveToValtype() == expect);
    }
}

BOOST_AUTO_TEST_CASE(trim_trailing_zeros)
{
    for (size_t size : {size_t{8}, size_t{9}, size_t{16}, size_t{17}, size_t{4096}}) {
        BigUint zero_value{Bytes(size, 0)};
        zero_value.TrimTrailingZeros();
        BOOST_CHECK(zero_value.MoveToValtype().empty());

        Bytes padded_one(size, 0);
        padded_one.front() = 1;
        BigUint one_value(std::move(padded_one));
        one_value.TrimTrailingZeros();
        BOOST_CHECK(one_value.MoveToValtype() == Bytes{1});
    }

    Bytes later_limb(4096, 0);
    later_limb[8] = 1;
    BigUint later_limb_value(std::move(later_limb));
    later_limb_value.TrimTrailingZeros();
    Bytes expected(9, 0);
    expected.back() = 1;
    BOOST_CHECK(later_limb_value.MoveToValtype() == expected);
}

BOOST_AUTO_TEST_CASE(to_u64_clamped)
{
    // The whole little-endian value counts: trailing zeros are padding, and
    // values beyond 64 bits clamp.
    BOOST_CHECK_EQUAL(Num({0xff, 0x00, 0x00}).ToU64Clamped(300), 255);
    BOOST_CHECK_EQUAL(Num({0x05}).ToU64Clamped(4), 4);
    BOOST_CHECK_EQUAL(Num({0, 0, 0, 0, 0, 0, 0, 0, 1}).ToU64Clamped(1000), 1000);
    BOOST_CHECK_EQUAL(Num({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}).ToU64Clamped(UINT64_MAX), UINT64_MAX);
}

BOOST_AUTO_TEST_CASE(div_mod)
{
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 129; j++) {
            const Bytes va = WithBit(i), vb = WithBit(j);

            BigUint v64a_div{Num(va)}, v64a_mod{Num(va)};
            BigUint v64b_div{Num(vb)}, v64b_mod{Num(vb)};
            BOOST_CHECK(BigUint::OpDiv(v64a_div, v64b_div));
            BOOST_CHECK(BigUint::OpMod(v64a_mod, v64b_mod));

            Bytes expected_div, expected_remainder;
            if (i >= j) {
                expected_div = WithBit(i - j);
            } else {
                expected_remainder = WithBit(i);
            }

            BOOST_CHECK(v64a_div.MoveToValtype() == expected_div);
            BOOST_CHECK(v64a_mod.MoveToValtype() == expected_remainder);
        }

        {
            const Bytes va = WithBit(i);
            BigUint v64a_div{Num(va)}, v64a_mod{Num(va)};
            BigUint v64b_div{Bytes{}}, v64b_mod{Bytes{}};
            BOOST_CHECK(!BigUint::OpDiv(v64a_div, v64b_div));
            BOOST_CHECK(!BigUint::OpMod(v64a_mod, v64b_mod));
        }
    }
}

// Divide and check both the quotient and the remainder.
static void CheckDivMod(const Bytes& dividend, const Bytes& divisor, const Bytes& expected_quotient, const Bytes& expected_remainder)
{
    BigUint quotient{Num(dividend)}, quotient_divisor{Num(divisor)};
    BOOST_CHECK(BigUint::OpDiv(quotient, quotient_divisor));
    BOOST_CHECK(quotient.MoveToValtype() == expected_quotient);

    BigUint remainder{Num(dividend)}, remainder_divisor{Num(divisor)};
    BOOST_CHECK(BigUint::OpMod(remainder, remainder_divisor));
    BOOST_CHECK(remainder.MoveToValtype() == expected_remainder);
}

BOOST_AUTO_TEST_CASE(div_mod_fuzz_regression_normalized_divisor)
{
    CheckDivMod(
        {
            0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, 0x88,
        },
        {
            0x2a, 0x01, 0x48, 0x2f, 0xff, 0xff, 0xff, 0x4e, 0x01, 0x00, 0x00,
        },
        {
            0x68,
        },
        {
            0x1b, 0x86, 0xbf, 0xca, 0x54, 0x00, 0x00, 0xdf,
        });
}

BOOST_AUTO_TEST_CASE(div_mod_trial_quotient_beta)
{
    // The high dividend word equals the high divisor word after normalization.
    // Knuth D3 first estimates qhat as beta = 2^64, then corrects it to beta - 1.
    CheckDivMod(
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b,
            0x00,
        },
        {
            0xe7, 0x26, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b,
            0x00,
        },
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        },
        {
            0xe6, 0x26, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02,
            0x1a, 0xda, 0x00, 0x00, 0x1d, 0x1d, 0xfe, 0x3a,
        });
}

BOOST_AUTO_TEST_CASE(div_mod_trial_quotient_beta_raw_division_overflow)
{
    // Same qhat == beta boundary as above, but the raw 128-bit division would
    // compute beta + 1 if it were not capped to Algorithm D's trial quotient.
    CheckDivMod(
        {
            0x50, 0x00, 0x30, 0x9d, 0x2c, 0x3f, 0xfe, 0xff,
            0x00, 0x00, 0x00, 0x00, 0x27, 0xb1, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xcf, 0xf3, 0x3b,
        },
        {
            0x3e, 0x03, 0x00, 0x00, 0x27, 0xb1, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xcf, 0xf3, 0x3b,
        },
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        },
        {
            0x8e, 0x03, 0x30, 0x9d, 0x53, 0xf0, 0xfd, 0xff,
            0xc2, 0xfc, 0xff, 0xff, 0xcf, 0xf3, 0x3b,
        });
}

BOOST_AUTO_TEST_CASE(div_mod_edge_cases)
{
    // (2^128 - 1) / (2^63 + 1), by a normalized one-limb divisor.
    CheckDivMod(Bytes(16, 0xff), {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80},
                {0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
                {0x03});

    // A quotient limb close to 2^64.
    CheckDivMod({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                Bytes(8, 0xff),
                {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
}

BOOST_AUTO_TEST_CASE(wide_math)
{
    // Values at the edges of 32-bit digits, plus random ones.
    std::vector<uint64_t> values{0, 1, 2, 0xffffffff, 0x100000000, 0x100000001, 0x7fffffffffffffff,
                                 0x8000000000000000, 0x8000000000000001, 0xfffffffeffffffff,
                                 0xffffffff00000000, 0xffffffff00000001, 0xfffffffffffffffe, UINT64_MAX};
    for (int i{0}; i < 40; ++i) values.push_back(m_rng.rand64());

    for (const uint64_t a : values) {
        for (const uint64_t b : values) {
            const biguint::Wide portable{biguint::MulWidePortable(a, b)};
            const biguint::Wide native{biguint::MulWide(a, b)};
            BOOST_CHECK_EQUAL(portable.hi, native.hi);
            BOOST_CHECK_EQUAL(portable.lo, native.lo);
#ifdef __SIZEOF_INT128__
            const unsigned __int128 product{static_cast<unsigned __int128>(a) * b};
            BOOST_CHECK_EQUAL(portable.hi, static_cast<uint64_t>(product >> 64));
            BOOST_CHECK_EQUAL(portable.lo, static_cast<uint64_t>(product));
#endif
        }
    }

    for (const uint64_t d_value : values) {
        const uint64_t d{d_value | (uint64_t{1} << 63)};
        for (const uint64_t hi_value : values) {
            const uint64_t hi{hi_value % d};
            for (const uint64_t lo : values) {
                const biguint::DivResult portable{biguint::DivWidePortable(hi, lo, d)};
                const biguint::DivResult native{biguint::DivWide(hi, lo, d)};
                BOOST_CHECK_EQUAL(portable.quotient, native.quotient);
                BOOST_CHECK_EQUAL(portable.remainder, native.remainder);
                // quotient * d + remainder == hi:lo, with remainder < d.
                BOOST_CHECK_LT(portable.remainder, d);
                const biguint::Wide product{biguint::MulWide(portable.quotient, d)};
                // Add the low limbs with an explicit carry rather than by
                // wrapping, which -fsanitize=unsigned-integer-overflow reports.
                const uint64_t room{std::numeric_limits<uint64_t>::max() - product.lo};
                const bool carry{portable.remainder > room};
                const uint64_t low{carry ? portable.remainder - room - 1 : product.lo + portable.remainder};
                BOOST_CHECK_EQUAL(low, lo);
                BOOST_CHECK_EQUAL(product.hi + carry, hi);
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
