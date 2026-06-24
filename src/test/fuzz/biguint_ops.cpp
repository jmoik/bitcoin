// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Checks BigUint arithmetic, bitwise shifts, predicates, and large multiply,
// divide, and modulo operations without a second big-integer implementation:
// sums and products modulo 2^32 and two primes, the other arithmetic through
// round trips such as a == q * b + r with r < b, and the rest against
// byte-wise references.

#include <script/biguint.h>
#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/biguint.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
using OptionalBytes = std::optional<Bytes>;

constexpr size_t MAX_NORMAL_OPERAND_SIZE{256};
constexpr size_t MIN_LARGE_OPERAND_SIZE{257};
constexpr size_t MAX_LARGE_OPERAND_SIZE{4 * 1024};

enum class ArithmeticOp : uint8_t {
    ADD,
    SUB,
    ONE_ADD,
    ONE_SUB,
    TWO_MUL,
    TWO_DIV,
    MIN,
    MAX,
    MUL,
    DIV,
    MOD,
};

enum class BitwiseShiftOp : uint8_t {
    INVERT,
    AND,
    OR,
    XOR,
    UPSHIFT,
    DOWNSHIFT,
};

//! Size of bytes without its high zero bytes.
size_t MinimalSize(const Bytes& bytes)
{
    size_t size{bytes.size()};
    while (size > 0 && bytes[size - 1] == 0) --size;
    return size;
}

bool IsMinimal(const Bytes& bytes)
{
    return MinimalSize(bytes) == bytes.size();
}

Bytes MinimalFromU64(uint64_t value)
{
    Bytes bytes;
    for (; value != 0; value >>= 8) bytes.push_back(static_cast<unsigned char>(value));
    return bytes;
}

uint64_t ToU64Clamped(const Bytes& bytes, uint64_t max)
{
    const size_t size{MinimalSize(bytes)};
    if (size > 8) return max;
    uint64_t value{0};
    for (size_t i{size}; i > 0; --i) value = (value << 8) | bytes[i - 1];
    return std::min(value, max);
}

int ReferenceCompare(const Bytes& a, const Bytes& b)
{
    const size_t a_size{MinimalSize(a)};
    const size_t b_size{MinimalSize(b)};
    if (a_size != b_size) return a_size < b_size ? -1 : 1;
    for (size_t i{a_size}; i > 0; --i) {
        if (a[i - 1] != b[i - 1]) return a[i - 1] < b[i - 1] ? -1 : 1;
    }
    return 0;
}

//! Sums and products are checked modulo 2^32, which covers their low bits, and
//! modulo the two largest primes below 2^32. Residues stay below 2^32, so
//! their sums and products fit in 64 bits.
constexpr std::array<uint64_t, 3> MODULI{uint64_t{1} << 32, 4294967291, 4294967279};

std::array<uint64_t, MODULI.size()> Residues(const Bytes& bytes)
{
    std::array<uint64_t, MODULI.size()> residues{};
    for (size_t m{0}; m < MODULI.size(); ++m) {
        for (size_t i{bytes.size()}; i > 0; --i) {
            residues[m] = (residues[m] * 256 + bytes[i - 1]) % MODULI[m];
        }
    }
    return residues;
}

OptionalBytes ExecuteArithmetic(ArithmeticOp op, const Bytes& a, const Bytes& b)
{
    BigUint va{Bytes{a}};
    BigUint vb{Bytes{b}};

    switch (op) {
    case ArithmeticOp::ADD:
        BigUint::OpAdd(va, vb);
        return {va.MoveToValtype()};
    case ArithmeticOp::SUB:
        if (!BigUint::OpSub(va, vb)) return {std::nullopt};
        return {va.MoveToValtype()};
    case ArithmeticOp::ONE_ADD:
        BigUint::Op1Add(va);
        return {va.MoveToValtype()};
    case ArithmeticOp::ONE_SUB:
        if (!BigUint::Op1Sub(va)) return {std::nullopt};
        return {va.MoveToValtype()};
    case ArithmeticOp::TWO_MUL:
        BigUint::Op2Mul(va);
        return {va.MoveToValtype()};
    case ArithmeticOp::TWO_DIV:
        BigUint::Op2Div(va);
        return {va.MoveToValtype()};
    case ArithmeticOp::MIN:
        BigUint::OpMin(va, vb);
        return {va.MoveToValtype()};
    case ArithmeticOp::MAX:
        BigUint::OpMax(va, vb);
        return {va.MoveToValtype()};
    case ArithmeticOp::MUL:
        return {BigUint::OpMul(va, vb).MoveToValtype()};
    case ArithmeticOp::DIV:
        if (!BigUint::OpDiv(va, vb)) return {std::nullopt};
        return {va.MoveToValtype()};
    case ArithmeticOp::MOD:
        if (!BigUint::OpMod(va, vb)) return {std::nullopt};
        return {va.MoveToValtype()};
    }
    Assert(false);
    return {};
}

bool IsUnary(ArithmeticOp op)
{
    return op == ArithmeticOp::ONE_ADD || op == ArithmeticOp::ONE_SUB ||
           op == ArithmeticOp::TWO_MUL || op == ArithmeticOp::TWO_DIV;
}

//! Check that result is a + b or a * b modulo each of MODULI.
void CheckResidues(ArithmeticOp op, const Bytes& a, const Bytes& b, const Bytes& result)
{
    const auto a_residues{Residues(a)};
    const auto b_residues{Residues(b)};
    const auto result_residues{Residues(result)};
    for (size_t m{0}; m < MODULI.size(); ++m) {
        const uint64_t expected{op == ArithmeticOp::ADD ? a_residues[m] + b_residues[m]
                                                        : a_residues[m] * b_residues[m]};
        Assert(result_residues[m] == expected % MODULI[m]);
    }
}

//! BigUint's a + b or a * b, checked by CheckResidues. The round trips below
//! rely on it.
Bytes CheckedAddOrMul(ArithmeticOp op, const Bytes& a, const Bytes& b)
{
    Bytes result{ExecuteArithmetic(op, a, b).value()};
    CheckResidues(op, a, b, result);
    return result;
}

//! Check a == quotient * b + remainder with remainder < b, which only the true
//! quotient and remainder of a divided by b satisfy.
void CheckDivision(const Bytes& a, const Bytes& b, const Bytes& quotient, const Bytes& remainder)
{
    Assert(IsMinimal(quotient) && IsMinimal(remainder));
    Assert(ReferenceCompare(remainder, b) < 0);
    const Bytes product{CheckedAddOrMul(ArithmeticOp::MUL, quotient, b)};
    Assert(CheckedAddOrMul(ArithmeticOp::ADD, product, remainder) == TrimTrailingZeros(a));
}

void CheckArithmetic(ArithmeticOp op, const Bytes& a, const Bytes& b)
{
    if (op == ArithmeticOp::DIV || op == ArithmeticOp::MOD) {
        const OptionalBytes quotient{ExecuteArithmetic(ArithmeticOp::DIV, a, b)};
        const OptionalBytes remainder{ExecuteArithmetic(ArithmeticOp::MOD, a, b)};
        if (MinimalSize(b) == 0) {
            Assert(!quotient && !remainder);
        } else {
            CheckDivision(a, b, quotient.value(), remainder.value());
        }
        return;
    }

    const OptionalBytes result{ExecuteArithmetic(op, a, b)};
    if (result) Assert(IsMinimal(*result));
    const Bytes one{0x01};
    const Bytes two{0x02};
    switch (op) {
    case ArithmeticOp::ADD:
    case ArithmeticOp::MUL:
        CheckResidues(op, a, b, result.value());
        return;
    case ArithmeticOp::ONE_ADD:
        Assert(result == CheckedAddOrMul(ArithmeticOp::ADD, a, one));
        return;
    case ArithmeticOp::TWO_MUL:
        Assert(result == CheckedAddOrMul(ArithmeticOp::MUL, a, two));
        return;
    case ArithmeticOp::SUB:
    case ArithmeticOp::ONE_SUB: {
        const Bytes& subtrahend{op == ArithmeticOp::SUB ? b : one};
        if (ReferenceCompare(a, subtrahend) < 0) {
            Assert(!result);
        } else {
            Assert(CheckedAddOrMul(ArithmeticOp::ADD, result.value(), subtrahend) == TrimTrailingZeros(a));
        }
        return;
    }
    case ArithmeticOp::TWO_DIV: {
        const Bytes remainder{!a.empty() && (a[0] & 1) ? one : Bytes{}};
        CheckDivision(a, two, result.value(), remainder);
        return;
    }
    case ArithmeticOp::MIN:
        Assert(result == TrimTrailingZeros(ReferenceCompare(a, b) <= 0 ? a : b));
        return;
    case ArithmeticOp::MAX:
        Assert(result == TrimTrailingZeros(ReferenceCompare(a, b) >= 0 ? a : b));
        return;
    case ArithmeticOp::DIV:
    case ArithmeticOp::MOD:
        break;
    }
    Assert(false);
}

OptionalBytes ReferenceBitwiseShift(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    switch (op) {
    case BitwiseShiftOp::INVERT: {
        Bytes result{a};
        for (unsigned char& byte : result)
            byte ^= 0xff;
        return result;
    }
    case BitwiseShiftOp::AND:
    case BitwiseShiftOp::OR:
    case BitwiseShiftOp::XOR: {
        Bytes result(std::max(a.size(), b.size()));
        for (size_t i{0}; i < result.size(); ++i) {
            const unsigned char av{i < a.size() ? a[i] : static_cast<unsigned char>(0)};
            const unsigned char bv{i < b.size() ? b[i] : static_cast<unsigned char>(0)};
            result[i] = op == BitwiseShiftOp::AND ? av & bv : op == BitwiseShiftOp::OR ? av | bv : av ^ bv;
        }
        return result;
    }
    case BitwiseShiftOp::UPSHIFT: {
        constexpr uint64_t max_bits{uint64_t{MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE} * 8};
        const uint64_t bits{ToU64Clamped(b, max_bits + 1)};
        const uint64_t a_bits{static_cast<uint64_t>(a.size()) * 8};
        if (bits > max_bits - a_bits) return std::nullopt;

        const size_t prebytes{static_cast<size_t>(bits / 8)};
        const size_t result_size{a.size() + prebytes + (bits % 8 == 0 ? 0 : 1)};
        return ShiftLeftFixed(a, bits, result_size);
    }
    case BitwiseShiftOp::DOWNSHIFT: {
        const uint64_t a_bits{static_cast<uint64_t>(a.size()) * 8};
        const uint64_t bits{ToU64Clamped(b, a_bits)};
        const size_t bytes{static_cast<size_t>(bits / 8)};
        if (bytes >= a.size()) return Bytes{};
        return ShiftRightFixed(a, bits, a.size() - bytes);
    }
    }
    Assert(false);
    return std::nullopt;
}

OptionalBytes ExecuteBitwiseShift(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    BigUint va{Bytes{a}};
    BigUint vb{Bytes{b}};

    switch (op) {
    case BitwiseShiftOp::INVERT:
        BigUint::OpInvert(va);
        break;
    case BitwiseShiftOp::AND:
        BigUint::OpAnd(va, vb);
        break;
    case BitwiseShiftOp::OR:
        BigUint::OpOr(va, vb);
        break;
    case BitwiseShiftOp::XOR:
        BigUint::OpXor(va, vb);
        break;
    case BitwiseShiftOp::UPSHIFT:
        if (!BigUint::OpUpShift(va, vb, MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE)) {
            return {std::nullopt};
        }
        break;
    case BitwiseShiftOp::DOWNSHIFT:
        BigUint::OpDownShift(va, vb);
        break;
    }
    return {va.MoveToValtype()};
}

template <size_t N>
size_t ConsumeSize(FuzzedDataProvider& provider,
                   const std::array<size_t, N>& boundaries,
                   size_t min,
                   size_t max)
{
    if (provider.ConsumeBool()) return provider.PickValueInArray(boundaries);
    return provider.ConsumeIntegralInRange<size_t>(min, max);
}

Bytes ConsumeBytesWithSize(FuzzedDataProvider& provider, size_t size)
{
    const uint8_t mode{provider.ConsumeIntegralInRange<uint8_t>(0, 3)};
    if (mode == 1) return Bytes(size, 0x00);
    if (mode == 2) return Bytes(size, 0xff);

    const unsigned char fill{provider.ConsumeIntegral<unsigned char>()};
    Bytes bytes{provider.ConsumeBytes<unsigned char>(size)};
    bytes.resize(size, fill);
    if (mode == 3 && !bytes.empty()) {
        const size_t zero_tail{provider.ConsumeIntegralInRange<size_t>(1, std::min<size_t>(8, bytes.size()))};
        std::fill(bytes.end() - zero_tail, bytes.end(), 0x00);
    }
    return bytes;
}

Bytes ConsumeNormalOperand(FuzzedDataProvider& provider)
{
    static constexpr std::array<size_t, 20> boundaries{
        0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256};
    return ConsumeBytesWithSize(provider, ConsumeSize(provider, boundaries, 0, MAX_NORMAL_OPERAND_SIZE));
}

Bytes ConsumeLargeOperand(FuzzedDataProvider& provider)
{
    static constexpr std::array<size_t, 12> boundaries{
        257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096};
    return ConsumeBytesWithSize(
        provider,
        ConsumeSize(provider, boundaries, MIN_LARGE_OPERAND_SIZE, MAX_LARGE_OPERAND_SIZE));
}

void AddNear(std::vector<uint64_t>& values, uint64_t value)
{
    if (value > 0) values.push_back(value - 1);
    values.push_back(value);
    if (value < std::numeric_limits<uint64_t>::max()) values.push_back(value + 1);
}

Bytes PadNumericOperand(FuzzedDataProvider& provider, Bytes bytes)
{
    if (provider.ConsumeBool()) {
        bytes.resize(bytes.size() + provider.ConsumeIntegralInRange<size_t>(0, 8), 0x00);
    }
    return bytes;
}

Bytes ConsumeShiftOperand(FuzzedDataProvider& provider, BitwiseShiftOp op, size_t a_size)
{
    constexpr uint64_t max_bits{uint64_t{MAX_TAPLEAF_0XC2_STACK_ELEMENT_SIZE} * 8};
    const uint64_t a_bits{static_cast<uint64_t>(a_size) * 8};
    std::vector<uint64_t> candidates{0, 1, 7, 8, 9, 15, 16, 63, 64, 65};
    AddNear(candidates, a_bits);
    AddNear(candidates, (a_bits / 64) * 64);

    if (op == BitwiseShiftOp::UPSHIFT) {
        candidates.push_back(max_bits + 1);
        candidates.push_back(provider.ConsumeIntegralInRange<uint64_t>(0, a_bits + 1024));
    } else {
        AddNear(candidates, a_bits + 64);
        candidates.push_back(provider.ConsumeIntegralInRange<uint64_t>(0, a_bits + 128));
    }

    const uint64_t value{candidates.at(provider.ConsumeIntegralInRange<size_t>(0, candidates.size() - 1))};
    return PadNumericOperand(provider, MinimalFromU64(value));
}

void CheckPredicates(FuzzedDataProvider& provider, const Bytes& a, const Bytes& b)
{
    uint64_t max;
    if (provider.ConsumeBool()) {
        max = provider.ConsumeIntegral<uint64_t>();
    } else {
        max = provider.PickValueInArray<uint64_t>({0, 1, 255, 256, 4096,
                                                   std::numeric_limits<uint32_t>::max(),
                                                   std::numeric_limits<uint64_t>::max()});
    }
    const uint64_t expected_clamped{ToU64Clamped(a, max)};
    const bool expected_zero{MinimalSize(a) == 0};
    const int expected_cmp{ReferenceCompare(a, b)};

    const BigUint va{Bytes{a}};
    const BigUint vb{Bytes{b}};
    Assert(va.ToU64Clamped(max) == expected_clamped);
    Assert(va.IsZero() == expected_zero);
    Assert(va.Compare(vb) == expected_cmp);

    BigUint trimmed{Bytes{a}};
    trimmed.TrimTrailingZeros();
    Assert(trimmed.MoveToValtype() == TrimTrailingZeros(a));
}
} // namespace

FUZZ_TARGET(biguint_arithmetic)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const ArithmeticOp op{static_cast<ArithmeticOp>(provider.ConsumeIntegralInRange<int>(
        0, static_cast<int>(ArithmeticOp::MOD)))};
    const Bytes a{ConsumeNormalOperand(provider)};
    const Bytes b{IsUnary(op) ? Bytes{} : ConsumeNormalOperand(provider)};
    CheckArithmetic(op, a, b);
}

FUZZ_TARGET(biguint_bitwise_shift)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const BitwiseShiftOp op{static_cast<BitwiseShiftOp>(provider.ConsumeIntegralInRange<int>(
        0, static_cast<int>(BitwiseShiftOp::DOWNSHIFT)))};
    const Bytes a{ConsumeNormalOperand(provider)};
    Bytes b;
    if (op == BitwiseShiftOp::UPSHIFT || op == BitwiseShiftOp::DOWNSHIFT) {
        b = ConsumeShiftOperand(provider, op, a.size());
    } else if (op != BitwiseShiftOp::INVERT) {
        b = ConsumeNormalOperand(provider);
    }
    Assert(ExecuteBitwiseShift(op, a, b) == ReferenceBitwiseShift(op, a, b));
}

FUZZ_TARGET(biguint_predicates)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const Bytes a{ConsumeNormalOperand(provider)};
    const Bytes b{ConsumeNormalOperand(provider)};
    CheckPredicates(provider, a, b);
}

FUZZ_TARGET(biguint_large_mul_divmod)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const ArithmeticOp op{provider.PickValueInArray<ArithmeticOp>({ArithmeticOp::MUL, ArithmeticOp::DIV, ArithmeticOp::MOD})};
    const Bytes a{ConsumeLargeOperand(provider)};
    const Bytes b{ConsumeLargeOperand(provider)};
    CheckArithmetic(op, a, b);
}
