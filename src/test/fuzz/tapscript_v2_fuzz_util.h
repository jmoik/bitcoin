// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_FUZZ_TAPSCRIPT_V2_FUZZ_UTIL_H
#define BITCOIN_TEST_FUZZ_TAPSCRIPT_V2_FUZZ_UTIL_H

#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>
#include <test/util/tapscript_v2_test_utils.h>
#include <util/check.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace test::tapscript_v2::fuzz {

using Bytes = std::vector<unsigned char>;

// Expected charges for the opcodes these targets generate. Prices come from
// varops.h; the composition of primitives per opcode is maintained here,
// independently of the interpreter.
inline uint64_t W(size_t size)
{
    const uint64_t size_u64{size};
    Assert(size_u64 <= std::numeric_limits<uint64_t>::max() - 7);
    return (size_u64 + 7) / 8 * 8;
}

inline uint64_t F() { return varops::FixedOpcodeCost(); }
inline uint64_t ProduceCost(size_t size) { return varops::ProduceCost(size); }
inline uint64_t ScalarCost() { return varops::ScalarOutputCost(); }
//! Witness items have no producing opcode, so evaluation prepays their lifetimes.
inline uint64_t InitialStackCost(const std::vector<Bytes>& stack)
{
    uint64_t cost{0};
    for (const Bytes& item : stack) cost += ProduceCost(item.size());
    return cost;
}
//! A literal push or a copying stack opcode: F plus one production per copy.
inline uint64_t CopyingCost(std::initializer_list<size_t> copies)
{
    uint64_t cost{F()};
    for (const size_t size : copies) cost += ProduceCost(size);
    return cost;
}
inline uint64_t MovingCost(size_t entries) { return F() + varops::MoveCost(entries); }
//! Numeric operand conversion and full scan, e.g. of a depth, count or condition.
inline uint64_t ScanCost(size_t size) { return varops::PrepCost(size) + varops::ReadCost(size); }
inline uint64_t EqualCost(size_t a, size_t b) { return F() + (a == b ? varops::ReadCost(a) : 0) + ScalarCost(); }
inline uint64_t ZeroTestCost(size_t size) { return F() + ScanCost(size) + ScalarCost(); }
inline uint64_t IfdupCost(size_t size, bool duplicated)
{
    return F() + ScanCost(size) + varops::OutputCost(size) + (duplicated ? ProduceCost(size) : 0);
}
inline uint64_t PickCost(size_t encoded_size, size_t value_size) { return F() + ScanCost(encoded_size) + ProduceCost(value_size); }
inline uint64_t RollCost(size_t encoded_size, uint64_t depth) { return F() + ScanCost(encoded_size) + varops::MoveCost(depth); }
inline uint64_t FinalCheckCost(size_t size) { return ScanCost(size); }
inline uint64_t SignatureCheckCost(bool nonempty)
{
    return nonempty ? varops::Sha256Cost(96) + varops::SignatureCost() : 0;
}

inline bool ContainsNonZero(const Bytes& bytes)
{
    return std::ranges::any_of(bytes, [](unsigned char byte) { return byte != 0; });
}

inline Bytes Normalize(Bytes bytes)
{
    while (!bytes.empty() && bytes.back() == 0)
        bytes.pop_back();
    return bytes;
}

inline Bytes Increment(Bytes bytes)
{
    bytes = Normalize(std::move(bytes));
    for (unsigned char& byte : bytes) {
        if (byte != 0xff) {
            ++byte;
            return bytes;
        }
        byte = 0;
    }
    bytes.push_back(1);
    return bytes;
}

inline Bytes ToLittleEndian(uint64_t value)
{
    Bytes bytes;
    while (value != 0) {
        bytes.push_back(static_cast<unsigned char>(value));
        value >>= 8;
    }
    return bytes;
}

inline uint64_t ToU64Ceil(const Bytes& bytes, uint64_t maximum)
{
    if (bytes.size() > 8 &&
        std::ranges::any_of(bytes.begin() + 8, bytes.end(), [](unsigned char byte) { return byte != 0; })) {
        return maximum;
    }
    uint64_t value{0};
    for (size_t i{std::min<size_t>(bytes.size(), 8)}; i > 0; --i) {
        value = (value << 8) | bytes[i - 1];
    }
    return std::min(value, maximum);
}

inline Bytes ConsumeElement(FuzzedDataProvider& provider, size_t maximum = 256)
{
    std::vector<size_t> sizes{0, 1, 2, 7, 8, 9, 31, 32, 63, 64, 127, 128, 255, 256};
    std::erase_if(sizes, [&](size_t size) { return size > maximum; });
    if (sizes.empty() || sizes.back() != maximum) sizes.push_back(maximum);
    if (!provider.ConsumeBool()) return ConsumeRandomLengthByteVector(provider, maximum);

    Bytes bytes(sizes.at(provider.ConsumeIntegralInRange<size_t>(0, sizes.size() - 1)));
    const uint8_t mode{provider.ConsumeIntegralInRange<uint8_t>(0, 3)};
    if (bytes.empty()) return bytes;
    switch (mode) {
    case 0:
        break;
    case 1:
        std::ranges::fill(bytes, 0xff);
        break;
    case 2:
        bytes.back() = 1;
        break;
    case 3: {
        const Bytes input{provider.ConsumeBytes<unsigned char>(std::min(bytes.size(), provider.remaining_bytes()))};
        std::ranges::copy(input, bytes.begin());
        break;
    }
    }
    return bytes;
}

inline void AssertStackEqual(const Stack& actual, const Stack& expected)
{
    Assert(actual == expected);
}

inline void CheckExactEval(const CScript& script,
                           const Stack& initial_stack,
                           const Stack& expected_stack,
                           uint64_t expected_cost)
{
    const BaseSignatureChecker checker;
    const EvalOutcome exact{
        EvalTapscriptV2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, checker, expected_cost)};
    Assert(exact.ok);
    Assert(exact.error == SCRIPT_ERR_OK);
    Assert(exact.remaining_budget == 0);
    AssertStackEqual(exact.stack, expected_stack);

    if (expected_cost > 0) {
        const EvalOutcome low{
            EvalTapscriptV2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, checker, expected_cost - 1)};
        Assert(!low.ok);
        Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
    }
}

inline void CheckEvalErrorBudget(const CScript& script,
                                 const Stack& initial_stack,
                                 uint64_t budget,
                                 ScriptError expected_error,
                                 uint64_t expected_remaining)
{
    const BaseSignatureChecker checker;
    const EvalOutcome outcome{
        EvalTapscriptV2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, checker, budget)};
    Assert(!outcome.ok);
    Assert(outcome.error == expected_error);
    Assert(outcome.remaining_budget == expected_remaining);
}

struct LeafSpend {
    CScript script_pub_key;
    CScriptWitness witness;
};

inline LeafSpend BuildLeafSpend(const CScript& script, const Stack& stack)
{
    CScript script_pub_key;
    CScriptWitness witness{BuildTapscriptV2Witness(script, stack, script_pub_key)};
    return {std::move(script_pub_key), std::move(witness)};
}

inline bool VerifySpend(const LeafSpend& spend,
                        script_verify_flags flags,
                        const BaseSignatureChecker& checker,
                        varops::Budget& budget,
                        ScriptError& error)
{
    error = SCRIPT_ERR_UNKNOWN_ERROR;
    return VerifyScript(CScript{}, spend.script_pub_key, &spend.witness, flags, checker, &error, budget);
}

struct VerifyOutcome {
    bool ok{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t remaining_budget{0};
};

inline VerifyOutcome VerifySpend(const LeafSpend& spend,
                                 script_verify_flags flags,
                                 const BaseSignatureChecker& checker,
                                 uint64_t budget)
{
    varops::Budget varops_budget{budget};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool ok{VerifySpend(spend, flags, checker, varops_budget, error)};
    return {ok, error, *varops_budget.Remaining()};
}

} // namespace test::tapscript_v2::fuzz

#endif // BITCOIN_TEST_FUZZ_TAPSCRIPT_V2_FUZZ_UTIL_H
