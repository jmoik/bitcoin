// Copyright (c) 2025-2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#if defined(__linux__)
#include <features.h> // IWYU pragma: keep
#endif
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <script/verify_flags.h>
#include <span.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath> // IWYU pragma: keep
#include <compare>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

// The audit counts coefficients separately from primitive composition. Derive
// these views from the single consensus formulas rather than duplicating prices.
namespace varops {
constexpr uint64_t COST_F{FixedOpcodeCost()};
constexpr uint64_t COST_PREP_FIXED{PrepCost(0)};
constexpr uint64_t COST_PREP_BYTE{(PrepCost(8) - PrepCost(0)) / 8};
constexpr uint64_t COST_OUTPUT_FIXED{OutputCost(0)};
constexpr uint64_t COST_OUTPUT_BYTE{(OutputCost(8) - OutputCost(0)) / 8};
constexpr uint64_t COST_COPY_FIXED{CopyCost(0)};
constexpr uint64_t COST_COPY_BYTE{CopyCost(1) - CopyCost(0)};
constexpr uint64_t COST_RELEASE_FIXED{2 * ReleaseCost(8) - ReleaseCost(16)};
constexpr uint64_t COST_RELEASE_BYTE{(ReleaseCost(16) - ReleaseCost(8)) / 8};
constexpr uint64_t COST_READ_FIXED{ReadCost(0)};
constexpr uint64_t COST_READ{(ReadCost(8) - ReadCost(0)) / 8};
constexpr uint64_t COST_ARITH_FIXED{ArithCost(0)};
constexpr uint64_t COST_ARITH_BYTE{ArithCost(1) - ArithCost(0)};
constexpr uint64_t COST_BIT_FIXED{BitCost(0)};
constexpr uint64_t COST_BIT{BitCost(1) - BitCost(0)};
constexpr uint64_t COST_MOVE_FIXED{MoveCost(0)};
constexpr uint64_t COST_MOVE{MoveCost(1) - MoveCost(0)};
constexpr uint64_t COST_MUL_ROW_FIXED{MulRowCost(0)};
constexpr uint64_t COST_MUL_ROW{MulRowCost(1) - MulRowCost(0)};
constexpr uint64_t COST_DIV_FIXED{DivCoreCost(0, 0)};
constexpr uint64_t COST_DIV_CELL{DivCoreCost(1, 1) - DivCoreCost(0, 0)};
constexpr uint64_t COST_H256_FIXED{Sha256Cost(0)};
constexpr uint64_t COST_H256_BYTE{Sha256Cost(1) - Sha256Cost(0)};
constexpr uint64_t COST_H160_FIXED{Ripemd160Cost(0)};
constexpr uint64_t COST_H160_BYTE{Ripemd160Cost(1) - Ripemd160Cost(0)};
constexpr uint64_t COST_H1_FIXED{Sha1Cost(0)};
constexpr uint64_t COST_H1_BYTE{Sha1Cost(1) - Sha1Cost(0)};
constexpr uint64_t COST_SIG{SignatureCost()};
constexpr uint64_t COST_TWEAK{TweakCost()};
constexpr uint64_t COST_SELECT_FIXED{TxSelectCost(0)};
constexpr uint64_t COST_SELECT_ITEM{TxSelectCost(1) - TxSelectCost(0)};
constexpr uint64_t COST_DECODE_FIXED{MacroDecodeCost(0)};
constexpr uint64_t COST_DECODE{MacroDecodeCost(1) - MacroDecodeCost(0)};
constexpr uint64_t COST_SCALAR_OUTPUT{ScalarOutputCost()};
} // namespace varops

namespace {

constexpr size_t SCRIPT_BYTES{MAX_BLOCK_WEIGHT};
constexpr uint64_t TOTAL_VAROPS_BUDGET{uint64_t{MAX_BLOCK_WEIGHT} * varops::BUDGET_PER_WEIGHT_UNIT};
// Avoid amplifying fixed harness overhead from semantic one-shot cases.
constexpr uint64_t MIN_FULL_VAROPS_SAMPLE_BUDGET{TOTAL_VAROPS_BUDGET / 100};
constexpr uint64_t MAX_FIXTURE_POOL_BYTES{512U * 1024U * 1024U};
constexpr size_t MAX_THREE_WAY_ELEMENT_SIZE{(MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - 1) / 6};
constexpr int SIGNATURES_PER_BLOCK{80'000};
constexpr int SCHNORR_BASELINE_SAMPLES{7};
constexpr uint64_t ROUND_SEED{0x475352};
constexpr size_t CLI_PROGRESS_INTERVAL{50};
constexpr script_verify_flags BENCH_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY};

enum class ExecutionDomain {
    PRE_GSR_TAPSCRIPT,
    GSR_TAPSCRIPT_V2,
    RAW_SCHNORR,
};

enum class HeadlineRole {
    PRE_BASELINE,
    NEW_GSR,
    COMMON_V2,
    DIAGNOSTIC,
};

enum class RepeatMode {
    MAX_SUCCESS,
    VAROP_REJECTION,
    FIXED,
};

enum class SaturationExpectation {
    SCRIPT_BYTES,
    VAROPS_BUDGET,
};

enum class TimingStage {
    SCHNORR_BASELINE,
    STABLE,
};

enum class MeasurementMode {
    REALISTIC,
    FULL_VAROPS,
};

using SaturationBoundary = std::pair<size_t, SaturationExpectation>;
using SaturationBoundaries = std::array<SaturationBoundary, 2>;

struct Options {
    std::set<opcodetype> selected_opcodes;
    int stable_rounds{5};
    uint32_t sample_budget_percent{100};
    bool silent{false}, list_opcodes{false};
    bool verify_costs{false};
    bool exclude_experimental{false};
    std::string output_file;
    std::string coverage_manifest;
    std::string case_filter;
};

static uint64_t SampleBudget(const Options& options)
{
    return TOTAL_VAROPS_BUDGET * options.sample_budget_percent / 100;
}

struct CryptoFixture {
    ECC_Context ecc_context{};
    uint256 message{uint256::ONE};
    XOnlyPubKey pubkey;
    valtype pubkey_bytes;
    valtype signature;

    CryptoFixture()
    {
        CKey key;
        std::array<unsigned char, 32> secret{};
        secret.back() = 1;
        key.Set(secret.begin(), secret.end(), false);
        if (!key.IsValid()) {
            throw std::runtime_error("failed to construct benchmark private key");
        }
        pubkey = XOnlyPubKey{key.GetPubKey()};
        pubkey_bytes.assign(pubkey.begin(), pubkey.end());
        signature.resize(64);
        if (!key.SignSchnorr(message, signature, nullptr, message)) {
            throw std::runtime_error("failed to construct benchmark Schnorr signature");
        }
    }
};

struct TransactionFixture {
    // Script-only OP_TX context; this benchmark does not verify UTXO commitments.
    const CTransaction tx;
    const std::vector<CTxOut> spent_outputs;
    const valtype control_block;

    TransactionFixture(const CMutableTransaction& mutable_tx, valtype control_block_in)
        : tx{mutable_tx}, spent_outputs(tx.vin.size()), control_block{std::move(control_block_in)} {}
};

class BenchSignatureChecker final : public BaseSignatureChecker
{
public:
    explicit BenchSignatureChecker(const CryptoFixture& fixture, const TransactionFixture* transaction = nullptr)
        : m_fixture{fixture}, m_transaction{transaction} {}

    bool CheckSchnorrSignature(std::span<const unsigned char> sig,
                               std::span<const unsigned char> pubkey, SigVersion,
                               ScriptExecutionData&, ScriptError* error) const override
    {
        const bool valid_key{pubkey.size() == m_fixture.pubkey_bytes.size() &&
                             std::equal(pubkey.begin(), pubkey.end(), m_fixture.pubkey_bytes.begin())};
        const bool valid{valid_key && m_fixture.pubkey.VerifySchnorr(m_fixture.message, sig)};
        if (!valid && error) *error = SCRIPT_ERR_SCHNORR_SIG;
        return valid;
    }

    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }

    std::optional<ScriptTransactionData> GetTransactionData() const override
    {
        if (!m_transaction) return std::nullopt;
        const CTransaction& tx{m_transaction->tx};
        return ScriptTransactionData{static_cast<uint32_t>(tx.version), tx.vin, tx.vout,
                                     tx.nLockTime, 0, m_transaction->spent_outputs};
    }

private:
    const CryptoFixture& m_fixture;
    const TransactionFixture* m_transaction;
};

using StackFactory = std::function<std::vector<valtype>(const CryptoFixture&)>;

struct CaseOptions {
    ScriptError expected_error{SCRIPT_ERR_OK};
    RepeatMode repeat_mode{RepeatMode::MAX_SUCCESS};
    uint64_t fixed_repetitions{0}, max_repetitions{std::numeric_limits<uint64_t>::max()};
    std::optional<size_t> cleanup_items;
    std::string saturation_hint;
    std::optional<uint64_t> expected_varops_per_repeat;
    std::optional<SaturationExpectation> expected_saturation;
    std::string sequence_label;
    std::optional<size_t> empty_witness_items;
    std::optional<bool> op_tx_collate;
    std::optional<size_t> op_tx_result_values;
};

struct CaseSpec {
    std::string name;
    opcodetype opcode{OP_INVALIDOPCODE};
    std::string opcode_name, sequence_opcodes, operand_shape, operand_pattern;
    HeadlineRole role{HeadlineRole::DIAGNOSTIC};
    // A newly legal v2 workload, which need not use a newly introduced opcode.
    bool new_in_v2{false};
    ScriptError expected_error{SCRIPT_ERR_OK};
    RepeatMode repeat_mode{RepeatMode::MAX_SUCCESS};
    uint64_t fixed_repetitions{0}, max_repetitions{std::numeric_limits<uint64_t>::max()};
    CScript sequence;
    StackFactory stack_factory;
    std::optional<size_t> cleanup_items;
    std::string saturation_hint;
    std::optional<uint64_t> expected_varops_per_repeat;
    std::optional<SaturationExpectation> expected_saturation;
    std::optional<size_t> empty_witness_items;
    std::optional<bool> op_tx_collate;
    std::optional<size_t> op_tx_result_values;
};

struct MaterializedCase {
    const CaseSpec* spec{nullptr};
    std::vector<valtype> initial_stack;
    CScript script;
    uint64_t repetitions{0}, varops_per_repeat{0};
    std::string saturation;
    std::shared_ptr<const TransactionFixture> transaction;
};

struct EvalOutcome {
    bool success{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t varops_consumed{0};
};

static uint64_t IndependentWordSize(size_t size)
{
    return (size + 7) / 8 * 8;
}

static uint64_t InitialProducerCost(const std::vector<valtype>& stack)
{
    uint64_t total{0};
    if constexpr (varops::PRODUCER_LIFETIME_EXPERIMENT) {
        for (const auto& value : stack) total += varops::COST_COPY_FIXED + varops::COST_COPY_BYTE * value.size();
    }
    return total;
}

static uint64_t IndependentCharge(unsigned __int128 cost)
{
    if (cost > std::numeric_limits<uint64_t>::max()) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(cost);
}

static void IndependentAdd(unsigned __int128& q, uint64_t coefficient, uint64_t units = 1)
{
    q += static_cast<unsigned __int128>(coefficient) * units;
}

static void IndependentPrep(unsigned __int128& q, size_t size)
{
    IndependentAdd(q, varops::COST_PREP_FIXED);
    IndependentAdd(q, varops::COST_PREP_BYTE, IndependentWordSize(size));
}

static void IndependentRead(unsigned __int128& q, size_t size)
{
    IndependentAdd(q, varops::COST_READ_FIXED);
    IndependentAdd(q, varops::COST_READ, IndependentWordSize(size));
}

static void IndependentProduced(unsigned __int128& q, size_t size)
{
    IndependentAdd(q, varops::COST_OUTPUT_FIXED);
    IndependentAdd(q, varops::COST_OUTPUT_BYTE, IndependentWordSize(size));
}

static uint64_t IndependentDecodeU64(const valtype& value, uint64_t maximum)
{
    uint64_t result{0};
    const size_t limit{std::min<size_t>(value.size(), sizeof(result))};
    for (size_t i{0}; i < limit; ++i) result |= uint64_t{value[i]} << (8 * i);
    if (value.size() > sizeof(result) &&
        std::ranges::any_of(value.begin() + sizeof(result), value.end(),
                            [](unsigned char byte) { return byte != 0; })) {
        return maximum;
    }
    return std::min(result, maximum);
}

static const valtype& IndependentTop(const ValtypeStack& stack, size_t depth = 0)
{
    return stack.at(stack.size() - depth - 1);
}

class IndependentCostAudit final : public varops::CostAudit
{
    enum class Deferred {
        NONE,
        PRODUCED,
        B_COPY_OUTPUT,
        SUBSTR_OUTPUT,
        IFDUP,
        OP_TX_OUTPUT,
    };

    struct Pending {
        opcodetype opcode{OP_INVALIDOPCODE};
        opcodetype target{OP_INVALIDOPCODE};
        unsigned __int128 q{0};
        Deferred deferred{Deferred::NONE};
        size_t before_size{0};
        size_t input_size{0};
    };

    const CaseSpec& m_spec;
    std::optional<Pending> m_pending;
    std::string m_mismatch;
    uint64_t m_expected_total{0};
    uint64_t m_actual_total{0};

    void Compare(opcodetype opcode, uint64_t expected, uint64_t actual)
    {
        m_expected_total += expected;
        m_actual_total += actual;
        if (m_mismatch.empty() && expected != actual) {
            m_mismatch = strprintf("%s: independent=%u runtime=%u",
                                   GetOpName(opcode), expected, actual);
        }
    }

    static void AddCopy(unsigned __int128& q, size_t size)
    {
        IndependentAdd(q, varops::COST_COPY_FIXED);
        IndependentAdd(q, varops::COST_COPY_BYTE, size);
    }

    static void AddRelease(unsigned __int128& q, size_t size)
    {
        if (size == 0) return;
        IndependentAdd(q, varops::COST_RELEASE_FIXED);
        IndependentAdd(q, varops::COST_RELEASE_BYTE, IndependentWordSize(size));
    }

    static void AddMove(unsigned __int128& q, size_t entries)
    {
        IndependentAdd(q, varops::COST_MOVE_FIXED);
        IndependentAdd(q, varops::COST_MOVE, entries);
    }

public:
    explicit IndependentCostAudit(const CaseSpec& spec) : m_spec{spec} {}

    void BeginOpcode(opcodetype opcode, const ValtypeStack& stack,
                     const ValtypeStack& altstack, opcodetype target) override
    {
        if (m_pending && m_mismatch.empty()) {
            m_mismatch = "nested candidate audit opcode";
        }
        Pending pending{opcode, target, 0, Deferred::NONE, stack.size(), 0};
        IndependentAdd(pending.q, varops::COST_F);

        if (opcode >= OP_0 && opcode <= OP_PUSHDATA4) {
            pending.deferred = Deferred::B_COPY_OUTPUT;
        } else if (opcode >= OP_1NEGATE && opcode <= OP_16) {
            IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
        } else {
            switch (opcode) {
            case OP_NOP: case OP_IF: case OP_NOTIF: case OP_ELSE: case OP_ENDIF:
            case OP_CODESEPARATOR:
                break;
            case OP_TOALTSTACK: case OP_FROMALTSTACK:
                AddMove(pending.q, 1);
                break;
            case OP_SWAP:
                AddMove(pending.q, 2);
                break;
            case OP_ROT:
                AddMove(pending.q, 3);
                break;
            case OP_2SWAP:
                AddMove(pending.q, 4);
                break;
            case OP_2ROT:
                AddMove(pending.q, 6);
                break;
            case OP_DROP:
                AddRelease(pending.q, IndependentTop(stack).size());
                break;
            case OP_2DROP:
                AddRelease(pending.q, IndependentTop(stack, 1).size());
                AddRelease(pending.q, IndependentTop(stack).size());
                break;
            case OP_NIP:
                AddRelease(pending.q, IndependentTop(stack, 1).size());
                break;
            case OP_VERIFY:
                IndependentPrep(pending.q, IndependentTop(stack).size());
                IndependentRead(pending.q, IndependentTop(stack).size());
                break;
            case OP_DUP:
                AddCopy(pending.q, IndependentTop(stack).size());
                break;
            case OP_2DUP:
                AddCopy(pending.q, IndependentTop(stack, 1).size());
                AddCopy(pending.q, IndependentTop(stack).size());
                break;
            case OP_3DUP:
                AddCopy(pending.q, IndependentTop(stack, 2).size());
                AddCopy(pending.q, IndependentTop(stack, 1).size());
                AddCopy(pending.q, IndependentTop(stack).size());
                break;
            case OP_OVER:
                AddCopy(pending.q, IndependentTop(stack, 1).size());
                break;
            case OP_2OVER:
                AddCopy(pending.q, IndependentTop(stack, 3).size());
                AddCopy(pending.q, IndependentTop(stack, 2).size());
                break;
            case OP_TUCK:
                AddCopy(pending.q, IndependentTop(stack).size());
                break;
            case OP_IFDUP: {
                const size_t size{IndependentTop(stack).size()};
                IndependentPrep(pending.q, size);
                IndependentRead(pending.q, size);
                IndependentProduced(pending.q, size);
                pending.input_size = size;
                pending.deferred = Deferred::IFDUP;
                break;
            }
            case OP_DEPTH: case OP_SIZE:
                IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                break;
            case OP_PICK: case OP_ROLL: {
                const valtype& depth_value{IndependentTop(stack)};
                IndependentPrep(pending.q, depth_value.size());
                IndependentRead(pending.q, depth_value.size());
                const uint64_t depth{IndependentDecodeU64(depth_value, stack.size() - 1)};
                if (opcode == OP_ROLL) {
                    IndependentAdd(pending.q, varops::COST_MOVE_FIXED);
                    IndependentAdd(pending.q, varops::COST_MOVE, depth);
                } else {
                    pending.deferred = Deferred::B_COPY_OUTPUT;
                }
                break;
            }
            case OP_EQUAL: case OP_EQUALVERIFY: {
                const size_t left{IndependentTop(stack, 1).size()};
                const size_t right{IndependentTop(stack).size()};
                if (left == right) IndependentRead(pending.q, left);
                IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                break;
            }
            case OP_1ADD: case OP_1SUB: case OP_NOT: case OP_0NOTEQUAL: {
                const size_t size{IndependentTop(stack).size()};
                IndependentPrep(pending.q, size);
                if (opcode == OP_NOT || opcode == OP_0NOTEQUAL) {
                    IndependentRead(pending.q, size);
                    IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                } else {
                    IndependentAdd(pending.q, varops::COST_ARITH_FIXED);
                    IndependentAdd(pending.q, varops::COST_ARITH_BYTE,
                                   IndependentWordSize(size));
                    pending.deferred = Deferred::PRODUCED;
                }
                break;
            }
            case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR:
            case OP_NUMEQUAL: case OP_NUMEQUALVERIFY: case OP_NUMNOTEQUAL:
            case OP_LESSTHAN: case OP_GREATERTHAN: case OP_LESSTHANOREQUAL:
            case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX: {
                const size_t left{IndependentTop(stack, 1).size()};
                const size_t right{IndependentTop(stack).size()};
                const uint64_t words{std::max(IndependentWordSize(left),
                                              IndependentWordSize(right))};
                IndependentPrep(pending.q, left);
                IndependentPrep(pending.q, right);
                if (opcode == OP_ADD || opcode == OP_SUB) {
                    IndependentAdd(pending.q, varops::COST_ARITH_FIXED);
                    IndependentAdd(pending.q, varops::COST_ARITH_BYTE, words);
                    pending.deferred = Deferred::PRODUCED;
                } else if (opcode == OP_BOOLAND || opcode == OP_BOOLOR) {
                    IndependentRead(pending.q, left);
                    IndependentRead(pending.q, right);
                    IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                } else if (opcode == OP_MIN || opcode == OP_MAX) {
                    IndependentAdd(pending.q, varops::COST_READ_FIXED);
                    IndependentAdd(pending.q, varops::COST_READ, words);
                    AddRelease(pending.q, std::max(left, right));
                    pending.deferred = Deferred::PRODUCED;
                } else {
                    IndependentAdd(pending.q, varops::COST_READ_FIXED);
                    IndependentAdd(pending.q, varops::COST_READ, words);
                    IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                }
                break;
            }
            case OP_WITHIN: {
                const size_t value{IndependentTop(stack, 2).size()};
                const size_t minimum{IndependentTop(stack, 1).size()};
                const size_t maximum{IndependentTop(stack).size()};
                IndependentPrep(pending.q, value);
                IndependentPrep(pending.q, minimum);
                IndependentPrep(pending.q, maximum);
                IndependentAdd(pending.q, varops::COST_READ_FIXED, 2);
                IndependentAdd(pending.q, varops::COST_READ,
                               std::max(IndependentWordSize(value), IndependentWordSize(minimum)) +
                                   std::max(IndependentWordSize(value), IndependentWordSize(maximum)));
                IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                break;
            }
            case OP_RIPEMD160: case OP_SHA1: case OP_SHA256:
            case OP_HASH160: case OP_HASH256: {
                const size_t input{IndependentTop(stack).size()};
                const size_t output{opcode == OP_SHA256 || opcode == OP_HASH256 ? 32U : 20U};
                if (opcode == OP_SHA1) {
                    IndependentAdd(pending.q, varops::COST_H1_FIXED);
                    IndependentAdd(pending.q, varops::COST_H1_BYTE, input);
                } else if (opcode == OP_RIPEMD160) {
                    IndependentAdd(pending.q, varops::COST_H160_FIXED);
                    IndependentAdd(pending.q, varops::COST_H160_BYTE, input);
                } else if (opcode == OP_SHA256) {
                    IndependentAdd(pending.q, varops::COST_H256_FIXED);
                    IndependentAdd(pending.q, varops::COST_H256_BYTE, input);
                } else if (opcode == OP_HASH160) {
                    IndependentAdd(pending.q, varops::COST_H256_FIXED);
                    IndependentAdd(pending.q, varops::COST_H256_BYTE, input);
                    IndependentAdd(pending.q, varops::COST_H160_FIXED);
                    IndependentAdd(pending.q, varops::COST_H160_BYTE, 32);
                } else {
                    IndependentAdd(pending.q, varops::COST_H256_FIXED, 2);
                    IndependentAdd(pending.q, varops::COST_H256_BYTE, input + 32);
                }
                IndependentAdd(pending.q, varops::COST_COPY_FIXED);
                IndependentAdd(pending.q, varops::COST_COPY_BYTE, output);
                break;
            }
            case OP_CHECKSIG: case OP_CHECKSIGVERIFY: {
                const valtype& signature{IndependentTop(stack, 1)};
                if (!signature.empty()) {
                    IndependentAdd(pending.q, varops::COST_H256_FIXED);
                    IndependentAdd(pending.q, varops::COST_H256_BYTE, 96);
                    IndependentAdd(pending.q, varops::COST_SIG);
                }
                IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                break;
            }
            case OP_CHECKSIGADD: {
                const valtype& signature{IndependentTop(stack, 2)};
                const size_t number_size{IndependentTop(stack, 1).size()};
                IndependentPrep(pending.q, number_size);
                if (!signature.empty()) {
                    IndependentAdd(pending.q, varops::COST_H256_FIXED);
                    IndependentAdd(pending.q, varops::COST_H256_BYTE, 96);
                    IndependentAdd(pending.q, varops::COST_SIG);
                    IndependentAdd(pending.q, varops::COST_ARITH_FIXED);
                    IndependentAdd(pending.q, varops::COST_ARITH_BYTE,
                                   IndependentWordSize(number_size));
                }
                pending.deferred = Deferred::PRODUCED;
                break;
            }
            case OP_CHECKSIGFROMSTACK: {
                const valtype& signature{IndependentTop(stack, 2)};
                if (!signature.empty()) {
                    IndependentAdd(pending.q, varops::COST_H256_FIXED, 2);
                    IndependentAdd(pending.q, varops::COST_H256_BYTE,
                                   IndependentTop(stack, 1).size() + 96);
                    IndependentAdd(pending.q, varops::COST_SIG);
                }
                IndependentAdd(pending.q, varops::COST_SCALAR_OUTPUT);
                break;
            }
            case OP_TWEAKADD:
                IndependentAdd(pending.q, varops::COST_TWEAK);
                AddCopy(pending.q, 32);
                break;
            case OP_CHECKLOCKTIMEVERIFY: case OP_CHECKSEQUENCEVERIFY: {
                const size_t size{IndependentTop(stack).size()};
                IndependentPrep(pending.q, size);
                IndependentRead(pending.q, size);
                IndependentProduced(pending.q, size);
                break;
            }
            case OP_BYTEREV:
                IndependentAdd(pending.q, varops::COST_BIT_FIXED);
                IndependentAdd(pending.q, varops::COST_BIT,
                               IndependentTop(stack).size());
                break;
            case OP_CAT: {
                const valtype& left{IndependentTop(stack, 1)};
                const valtype& right{IndependentTop(stack)};
                IndependentAdd(pending.q, varops::COST_COPY_FIXED);
                IndependentAdd(pending.q, varops::COST_COPY_BYTE,
                               left.size() + right.size());
                break;
            }
            case OP_SUBSTR:
                AddRelease(pending.q, IndependentTop(stack, 2).size());
                IndependentPrep(pending.q, IndependentTop(stack, 1).size());
                IndependentRead(pending.q, IndependentTop(stack, 1).size());
                AddRelease(pending.q, IndependentTop(stack, 1).size());
                IndependentPrep(pending.q, IndependentTop(stack).size());
                IndependentRead(pending.q, IndependentTop(stack).size());
                AddRelease(pending.q, IndependentTop(stack).size());
                pending.deferred = Deferred::SUBSTR_OUTPUT;
                break;
            case OP_LEFT: {
                const valtype& offset_value{IndependentTop(stack)};
                IndependentPrep(pending.q, offset_value.size());
                IndependentRead(pending.q, offset_value.size());
                break;
            }
            case OP_RIGHT: {
                const size_t data_size{IndependentTop(stack, 1).size()};
                const valtype& offset_value{IndependentTop(stack)};
                const uint64_t offset{IndependentDecodeU64(offset_value, data_size)};
                IndependentPrep(pending.q, offset_value.size());
                IndependentRead(pending.q, offset_value.size());
                IndependentAdd(pending.q, varops::COST_COPY_BYTE, offset);
                break;
            }
            case OP_INVERT: case OP_2MUL: case OP_2DIV: {
                const size_t size{IndependentTop(stack).size()};
                IndependentPrep(pending.q, size);
                IndependentAdd(pending.q, varops::COST_BIT_FIXED);
                IndependentAdd(pending.q, varops::COST_BIT,
                               IndependentWordSize(size));
                pending.deferred = Deferred::PRODUCED;
                break;
            }
            case OP_AND: case OP_OR: case OP_XOR: case OP_MUL: case OP_DIV:
            case OP_MOD: case OP_LSHIFT: case OP_RSHIFT: {
                const size_t left{IndependentTop(stack, 1).size()};
                const size_t right{IndependentTop(stack).size()};
                const uint64_t left_words{IndependentWordSize(left)};
                const uint64_t right_words{IndependentWordSize(right)};
                IndependentPrep(pending.q, left);
                IndependentPrep(pending.q, right);
                if (opcode == OP_LSHIFT || opcode == OP_RSHIFT) {
                    IndependentRead(pending.q, right);
                    IndependentAdd(pending.q, varops::COST_BIT_FIXED);
                    IndependentAdd(pending.q, varops::COST_BIT, left_words);
                } else if (opcode == OP_MUL) {
                    const uint64_t rows{std::max(left_words, right_words) / 8};
                    const uint64_t row_limbs{std::min(left_words, right_words) / 8};
                    if constexpr (varops::PRODUCER_LIFETIME_EXPERIMENT) {
                        AddCopy(pending.q, left_words + right_words);
                        IndependentPrep(pending.q, left_words + right_words);
                        AddCopy(pending.q, (row_limbs + 1) * 8);
                    }
                    IndependentAdd(pending.q, varops::COST_MUL_ROW_FIXED, rows);
                    IndependentAdd(pending.q, varops::COST_MUL_ROW, rows * row_limbs);
                    IndependentAdd(pending.q, varops::COST_ARITH_FIXED, rows);
                    IndependentAdd(pending.q, varops::COST_ARITH_BYTE,
                                   rows * (row_limbs + 1) * 8);
                } else if (opcode == OP_DIV || opcode == OP_MOD) {
                    const uint64_t left_limbs{left_words / 8};
                    const uint64_t right_limbs{right_words / 8};
                    const uint64_t steps{right_limbs == 1 ? left_limbs : (left_limbs > right_limbs ? left_limbs - right_limbs : 1)};
                    IndependentAdd(pending.q, varops::COST_DIV_FIXED);
                    IndependentAdd(pending.q, varops::COST_DIV_CELL,
                                   steps * right_limbs);
                    AddRelease(pending.q, std::max(left, right));
                } else {
                    IndependentAdd(pending.q, varops::COST_BIT_FIXED);
                    IndependentAdd(pending.q, varops::COST_BIT,
                                   std::max(left_words, right_words));
                }
                pending.deferred = Deferred::PRODUCED;
                break;
            }
            case OP_TX:
                if (!m_spec.empty_witness_items) {
                    if (m_mismatch.empty()) m_mismatch = "OP_TX case lacks independent fixture metadata";
                } else {
                    IndependentAdd(pending.q, varops::COST_SELECT_FIXED);
                    const uint64_t selected_items{*m_spec.empty_witness_items + 3};
                    IndependentAdd(pending.q, varops::COST_SELECT_ITEM, selected_items);
                    pending.deferred = Deferred::OP_TX_OUTPUT;
                }
                break;
            default:
                if (m_mismatch.empty()) {
                    m_mismatch = "no independent formula for " + GetOpName(opcode);
                }
                break;
            }
        }
        m_pending = std::move(pending);
        (void)altstack;
    }

    void EndOpcode(opcodetype opcode, const ValtypeStack& stack,
                   const ValtypeStack& altstack, opcodetype target,
                   uint64_t actual_charge) override
    {
        if (!m_pending || m_pending->opcode != opcode || m_pending->target != target) {
            if (m_mismatch.empty()) m_mismatch = "candidate audit begin/end mismatch";
            return;
        }
        Pending pending{std::move(*m_pending)};
        m_pending.reset();
        switch (pending.deferred) {
        case Deferred::NONE:
            break;
        case Deferred::PRODUCED:
            IndependentProduced(pending.q, IndependentTop(stack).size());
            if (varops::PRODUCER_LIFETIME_EXPERIMENT && opcode == OP_MUL) {
                pending.q -= varops::COST_COPY_FIXED + varops::COST_COPY_BYTE * IndependentWordSize(IndependentTop(stack).size());
            }
            break;
        case Deferred::B_COPY_OUTPUT:
            AddCopy(pending.q, IndependentTop(stack).size());
            break;
        case Deferred::SUBSTR_OUTPUT: {
            const size_t output_size{IndependentTop(stack).size()};
            AddCopy(pending.q, output_size);
            break;
        }
        case Deferred::IFDUP:
            if (stack.size() > pending.before_size) AddCopy(pending.q, pending.input_size);
            break;
        case Deferred::OP_TX_OUTPUT: {
            const size_t outputs{m_spec.op_tx_collate.value_or(true) ? 1 :
                m_spec.op_tx_result_values.value_or(*m_spec.empty_witness_items + 2)};
            for (size_t i{0}; i < outputs; ++i) {
                if constexpr (varops::PRODUCER_LIFETIME_EXPERIMENT) {
                    IndependentAdd(pending.q, varops::COST_COPY_FIXED);
                }
                IndependentAdd(pending.q, varops::COST_COPY_BYTE, IndependentTop(stack, i).size());
            }
            break;
        }
        }
        Compare(opcode, IndependentCharge(pending.q), actual_charge);
        (void)altstack;
    }

    void StandaloneCharge(opcodetype opcode, uint64_t feature_units,
                          uint64_t actual_charge) override
    {
        unsigned __int128 q{0};
        if (opcode == OP_CALLMACRO) IndependentAdd(q, varops::COST_F);
        IndependentAdd(q, varops::COST_DECODE_FIXED);
        IndependentAdd(q, varops::COST_DECODE, feature_units);
        Compare(opcode, IndependentCharge(q), actual_charge);
    }

    void FinalCheck(size_t value_size, uint64_t actual_charge) override
    {
        unsigned __int128 q{0};
        IndependentPrep(q, value_size);
        IndependentRead(q, value_size);
        Compare(OP_INVALIDOPCODE, IndependentCharge(q), actual_charge);
    }

    bool Passed() const { return m_mismatch.empty() && !m_pending; }
    void InitialStack(const ValtypeStack& stack, uint64_t actual_charge) override
    {
        unsigned __int128 q{0};
        for (size_t i = 0; i < stack.size(); ++i) AddCopy(q, stack.at(i).size());
        Compare(OP_INVALIDOPCODE, IndependentCharge(q), actual_charge);
    }
    const std::string& Mismatch() const { return m_mismatch; }
    uint64_t ExpectedTotal() const { return m_expected_total; }
    uint64_t ActualTotal() const { return m_actual_total; }
};

class ExecutedOpcodeCounter final : public varops::CostAudit
{
public:
    uint64_t count{0};

    void BeginOpcode(opcodetype, const ValtypeStack&,
                     const ValtypeStack&, opcodetype) override
    {
        ++count;
    }
    void EndOpcode(opcodetype, const ValtypeStack&, const ValtypeStack&, opcodetype, uint64_t) override {}
    void StandaloneCharge(opcodetype opcode, uint64_t, uint64_t) override
    {
        // A fragment call expands into body instructions but is itself charged
        // before the cursor returns an opcode to the interpreter.
        if (opcode == OP_CALLMACRO) ++count;
    }
    void FinalCheck(size_t, uint64_t) override {}
};

struct TimingSample {
    MeasurementMode mode{MeasurementMode::REALISTIC};
    TimingStage stage{TimingStage::STABLE};
    int round{0};
    size_t order{0};
    double wall_sec{0};
};

struct CaseSample {
    EvalOutcome outcome;
    TimingSample timing;
    std::optional<uint64_t> executed_opcodes;
};

struct SampleStats {
    double median{0}, minimum{0}, maximum{0}, mdape{0};
};

struct FullVaropsResult {
    std::string status{"not-measured"};
    uint64_t script_bytes{0}, script_executions{0}, measured_varops{0};
    double scale{0}, median_sec{0}, mdape{0};
    std::optional<TimingStage> aggregate_stage;
    double wall_min_sec{0}, wall_max_sec{0};
};

struct BenchResult {
    std::string name;
    double median_sec{0};
    double mdape{0};
    uint64_t varops_consumed{0};
    ExecutionDomain domain{ExecutionDomain::GSR_TAPSCRIPT_V2};
    HeadlineRole role{HeadlineRole::DIAGNOSTIC};
    bool new_in_v2{false};
    std::string opcode_name;
    std::string sequence_opcodes;
    std::string operand_shape;
    std::string operand_pattern;
    uint64_t script_bytes{0};
    uint64_t initial_stack_items{0};
    uint64_t initial_stack_bytes{0};
    ScriptError expected_error{SCRIPT_ERR_OK};
    ScriptError actual_error{SCRIPT_ERR_OK};
    std::string saturation;
    uint64_t repetitions{0};
    uint64_t varops_per_repeat{0};
    std::optional<uint64_t> executed_opcodes;
    std::optional<TimingStage> aggregate_stage;
    double wall_min_sec{0};
    double wall_max_sec{0};
    std::vector<TimingSample> samples;
    FullVaropsResult full_varops;
};

struct CorpusCounts {
    size_t requested_opcodes{0}, generated_cases{0}, completed_cases{0};
};

using ItemFactory = std::function<valtype()>;

static std::string DomainName(ExecutionDomain domain)
{
    switch (domain) {
    case ExecutionDomain::PRE_GSR_TAPSCRIPT: return "pre-gsr-tapscript-v1";
    case ExecutionDomain::GSR_TAPSCRIPT_V2: return "gsr-tapscript-v2";
    case ExecutionDomain::RAW_SCHNORR: return "raw-schnorr";
    }
    return "unknown";
}

static std::string RoleName(HeadlineRole role)
{
    switch (role) {
    case HeadlineRole::PRE_BASELINE: return "pre-baseline";
    case HeadlineRole::NEW_GSR: return "new-gsr";
    case HeadlineRole::COMMON_V2: return "common-v2";
    case HeadlineRole::DIAGNOSTIC: return "diagnostic";
    }
    return "unknown";
}

static ExecutionDomain DomainFor(HeadlineRole role) { return role == HeadlineRole::PRE_BASELINE ? ExecutionDomain::PRE_GSR_TAPSCRIPT : ExecutionDomain::GSR_TAPSCRIPT_V2; }

static std::string FormatBytes(uint64_t bytes)
{
    if (bytes >= 1024 * 1024 && bytes % (1024 * 1024) == 0) {
        return strprintf("%uMB", bytes / (1024 * 1024));
    }
    if (bytes >= 1024 && bytes % 1024 == 0) {
        return strprintf("%uKB", bytes / 1024);
    }
    return strprintf("%uB", bytes);
}

static std::string OpcodeName(opcodetype opcode)
{
    return opcode == OP_0 ? "OP_0" : GetOpName(opcode);
}

static std::string SequenceOpcodeNames(const CScript& sequence)
{
    std::string names;
    CScript::const_iterator pc{sequence.begin()};
    while (pc != sequence.end()) {
        opcodetype opcode;
        valtype pushed_data;
        if (!sequence.GetOp(pc, opcode, pushed_data)) {
            throw std::runtime_error("invalid benchmark sequence");
        }

        if (!names.empty()) names += "+";
        if (opcode == OP_0) {
            names += "OP_0";
        } else if (opcode > OP_0 && opcode < OP_PUSHDATA1) {
            names += strprintf("OP_PUSHBYTES_%u", pushed_data.size());
        } else if (opcode == OP_1NEGATE) {
            names += "OP_1NEGATE";
        } else if (opcode >= OP_1 && opcode <= OP_16) {
            names += strprintf("OP_%u", CScript::DecodeOP_N(opcode));
        } else {
            names += GetOpName(opcode);
        }
    }
    return names;
}

static uint64_t CandidateHashOpcodeCost(opcodetype opcode, size_t input_size)
{
    const size_t output_size{
        opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 ? 20U : 32U};
    unsigned __int128 q{0};
    IndependentAdd(q, varops::COST_F);
    switch (opcode) {
    case OP_SHA1:
        IndependentAdd(q, varops::COST_H1_FIXED);
        IndependentAdd(q, varops::COST_H1_BYTE, input_size);
        break;
    case OP_RIPEMD160:
        IndependentAdd(q, varops::COST_H160_FIXED);
        IndependentAdd(q, varops::COST_H160_BYTE, input_size);
        break;
    case OP_SHA256:
        IndependentAdd(q, varops::COST_H256_FIXED);
        IndependentAdd(q, varops::COST_H256_BYTE, input_size);
        break;
    case OP_HASH160:
        IndependentAdd(q, varops::COST_H256_FIXED);
        IndependentAdd(q, varops::COST_H256_BYTE, input_size);
        IndependentAdd(q, varops::COST_H160_FIXED);
        IndependentAdd(q, varops::COST_H160_BYTE, 32);
        break;
    case OP_HASH256:
        IndependentAdd(q, varops::COST_H256_FIXED, 2);
        IndependentAdd(q, varops::COST_H256_BYTE, input_size + 32);
        break;
    default:
        throw std::runtime_error("not a hash opcode");
    }
    IndependentAdd(q, varops::COST_COPY_FIXED);
    IndependentAdd(q, varops::COST_COPY_BYTE, output_size);
    return IndependentCharge(q);
}

static uint64_t CandidateDropCost(size_t value_size)
{
    if (value_size == 0) {
        return varops::COST_F;
    }
    return varops::COST_F + varops::COST_RELEASE_FIXED +
           varops::COST_RELEASE_BYTE * varops::detail::WordSize(value_size);
}

static uint64_t CandidateCleanupCost(std::span<const valtype> stack, size_t cleanup_items)
{
    if (cleanup_items > stack.size()) throw std::runtime_error("cleanup exceeds initial stack");
    uint64_t cost{0};
    for (size_t i{0}; i < cleanup_items; ++i) {
        cost += CandidateDropCost(stack[stack.size() - 1 - i].size());
    }
    return cost;
}

static uint64_t SequenceExecutionCost(const CScript& sequence)
{
    uint64_t cost{0};
    CScript::const_iterator pc{sequence.begin()};
    while (pc != sequence.end()) {
        opcodetype opcode;
        valtype data;
        if (!sequence.GetOp(pc, opcode, data)) throw std::runtime_error("invalid benchmark sequence");
        cost += varops::ExecutionCost(opcode);
        if (opcode >= OP_RIPEMD160 && opcode <= OP_HASH256) {
            // Hash input size is unknown at static-model time; the candidate
            // hash+insert charge is asserted per-case instead, so skip the
            // flat byte charge here to avoid double-counting.
            continue;
        }
        cost += data.size() * varops::COST_COPYING;
    }
    return cost;
}

static valtype PaddedNumber(uint64_t value, size_t size)
{
    valtype bytes(std::max<size_t>(size, 1), 0);
    for (size_t i{0}; i < std::min<size_t>(sizeof(value), bytes.size()); ++i) {
        bytes[i] = static_cast<unsigned char>(value & 0xff);
        value >>= 8;
    }
    if (size == 0) bytes.clear();
    return bytes;
}

static valtype PatternBytes(size_t size, std::string_view pattern)
{
    if (pattern == "zero") return valtype(size, 0x00);
    if (pattern == "one-low" || pattern == "padded-low") return PaddedNumber(1, size);
    if (pattern == "late-nonzero") {
        valtype out(size, 0x00);
        if (!out.empty()) out.back() = 0x01;
        return out;
    }
    if (pattern == "alternating") {
        valtype out(size);
        for (size_t i{0}; i < size; ++i)
            out[i] = (i & 1) ? 0x55 : 0xaa;
        return out;
    }
    return valtype(size, 0xff);
}

static uint64_t StackPayloadBytes(const std::vector<valtype>& stack)
{
    uint64_t total{0};
    for (const valtype& item : stack)
        total += item.size();
    return total;
}

static uint64_t StackFixtureBytes(const std::vector<valtype>& stack) { return StackPayloadBytes(stack) + uint64_t{stack.size()} * sizeof(valtype); }

static void ReleaseAllocatorCaches()
{
#if defined(__APPLE__)
    malloc_zone_pressure_relief(nullptr, 0);
#elif defined(__GLIBC__)
    malloc_trim(0);
#endif
}

static bool InitialStackAllowed(ExecutionDomain domain, const std::vector<valtype>& stack)
{
    if (domain == ExecutionDomain::RAW_SCHNORR) return stack.empty();
    if (domain == ExecutionDomain::PRE_GSR_TAPSCRIPT) {
        if (stack.size() > MAX_STACK_SIZE) return false;
        return std::ranges::all_of(stack, [](const valtype& item) {
            return item.size() <= MAX_SCRIPT_ELEMENT_SIZE;
        });
    }

    if (stack.size() > MAX_TAPSCRIPT_V2_STACK_SIZE) return false;
    uint64_t total{0};
    for (const valtype& item : stack) {
        if (item.size() > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) return false;
        if (item.size() > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - total) return false;
        total += item.size();
    }
    return true;
}

static bool NumericOperandAllowed(ExecutionDomain domain, size_t size, bool timelock)
{
    if (domain == ExecutionDomain::GSR_TAPSCRIPT_V2) {
        return size <= MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE;
    }
    return size <= (timelock ? 5U : 4U);
}

static SaturationBoundaries FindCrossoverPair(size_t sequence_bytes, size_t cleanup_items, size_t maximum,
                                              const std::function<uint64_t(size_t)>& sequence_cost)
{
    if (sequence_bytes == 0 || cleanup_items + 1 >= SCRIPT_BYTES || maximum < 2) {
        throw std::runtime_error("invalid crossover search bounds");
    }
    const uint64_t script_limit{(SCRIPT_BYTES - cleanup_items - 1) / sequence_bytes};
    const uint64_t suffix_cost{
        (cleanup_items + 1) * varops::COST_PER_OPCODE + varops::CompareZeroCost(1)};
    const uint64_t available_budget{TOTAL_VAROPS_BUDGET - suffix_cost};
    const auto script_limited = [&](size_t size) {
        const uint64_t cost{sequence_cost(size)};
        return cost == 0 || available_budget / cost >= script_limit;
    };
    if (!script_limited(1) || script_limited(maximum)) {
        // A new candidate can move the crossover outside the legal size range.
        // Retain endpoint probes without inventing a transition.
        const auto bound = [&](size_t size) {
            return script_limited(size) ? SaturationExpectation::SCRIPT_BYTES : SaturationExpectation::VAROPS_BUDGET;
        };
        return {{{1, bound(1)}, {maximum, bound(maximum)}}};
    }

    size_t low{1};
    size_t high{maximum};
    while (low < high) {
        const size_t mid{low + (high - low) / 2};
        if (script_limited(mid)) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return {{{low - 1, SaturationExpectation::SCRIPT_BYTES},
             {low, SaturationExpectation::VAROPS_BUDGET}}};
}

static std::string_view SaturationName(SaturationExpectation expectation) { return expectation == SaturationExpectation::SCRIPT_BYTES ? "script-bytes" : "varops-budget"; }
static void Check(bool condition, std::string_view error)
{
    if (!condition) throw std::runtime_error(std::string{error});
}

static void RunBoundarySelfChecks()
{
    const std::vector<valtype> pre_1000(MAX_STACK_SIZE, valtype{});
    const std::vector<valtype> pre_1001(MAX_STACK_SIZE + 1, valtype{});
    const std::vector<valtype> v2_32768(MAX_TAPSCRIPT_V2_STACK_SIZE, valtype{});
    const std::vector<valtype> v2_32769(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    Check(InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, pre_1000) &&
              !InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, pre_1001) &&
              InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, v2_32768) &&
              !InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, v2_32769) &&
              InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, {valtype(520)}) &&
              !InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, {valtype(521)}) &&
              InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, {valtype(521)}),
          "internal initial-stack boundary classification failed");
    Check(NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 4, false) &&
              !NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 5, false) &&
              NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 5, true) &&
              NumericOperandAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, 521, false),
          "internal numeric boundary classification failed");
    const auto crossover{FindCrossoverPair(1, 1, 10'000, [](size_t size) { return 2 * size; })};
    Check(crossover[0].first == 5'000 && crossover[1].first == 5'001,
          "internal crossover classification failed");
    Check(6 * MAX_THREE_WAY_ELEMENT_SIZE + 1 <= MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE &&
              6 * (MAX_THREE_WAY_ELEMENT_SIZE + 1) + 1 > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE,
          "internal three-way stack boundary classification failed");
    // Multiple precharge sites in one logical opcode must deduct only new cost.
    varops::Budget rounding_budget{10};
    varops::Meter rounding_meter;
    rounding_meter.Add(1);
    Check(rounding_meter.Spend(rounding_budget) && *rounding_budget.Remaining() == 9,
          "candidate first deduction failed");
    Check(rounding_meter.Spend(rounding_budget) && *rounding_budget.Remaining() == 9,
          "candidate unchanged charge was deducted twice");
    rounding_meter.Add(2);
    Check(rounding_meter.Spend(rounding_budget) && *rounding_budget.Remaining() == 7,
          "candidate second deduction was not applied");
}

struct PreparedExecution {
    std::vector<valtype> legacy_stack;
    std::optional<ValtypeStack> v2_stack;
    ScriptExecutionData execdata;
    std::unique_ptr<varops::Budget> budget;
    uint64_t initial_budget{0};
};

static PreparedExecution PrepareExecution(const MaterializedCase& test_case, bool timed = false,
                                          uint64_t budget = TOTAL_VAROPS_BUDGET)
{
    PreparedExecution execution;
    const bool legacy{DomainFor(test_case.spec->role) == ExecutionDomain::PRE_GSR_TAPSCRIPT};
    if (legacy || timed) {
        execution.execdata.m_validation_weight_left = MAX_BLOCK_WEIGHT;
        execution.execdata.m_validation_weight_left_init = true;
    }
    if (legacy) {
        execution.legacy_stack = test_case.initial_stack;
    } else {
        execution.v2_stack.emplace(test_case.initial_stack);
        execution.budget = std::make_unique<varops::Budget>(budget);
        execution.initial_budget = budget;
        if (const auto& transaction{test_case.transaction}) {
            execution.execdata.m_annex_init = true;
            execution.execdata.m_annex_present = false;
            execution.execdata.m_tapscript_init = true;
            execution.execdata.m_tapscript = test_case.script;
            execution.execdata.m_tapleaf_hash_init = true;
            execution.execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT_V2, test_case.script);
            execution.execdata.m_control_block_init = true;
            execution.execdata.m_control_block = transaction->control_block;
            execution.execdata.m_taptree_root_init = true;
            execution.execdata.m_taptree_root = ComputeTaprootMerkleRoot(transaction->control_block,
                                                                         execution.execdata.m_tapleaf_hash);
            execution.execdata.m_codeseparator_pos_init = true;
            execution.execdata.m_codeseparator_pos = 0xffffffff;
        }
    }
    return execution;
}

static EvalOutcome ExecutePrepared(const MaterializedCase& test_case, const BenchSignatureChecker& checker,
                                   PreparedExecution& execution)
{
    EvalOutcome outcome;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    if (DomainFor(test_case.spec->role) == ExecutionDomain::PRE_GSR_TAPSCRIPT) {
        bool success{EvalScript(execution.legacy_stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                checker, SigVersion::TAPSCRIPT, execution.execdata, &error)};
        if (success && execution.legacy_stack.size() != 1) {
            success = false;
            error = SCRIPT_ERR_CLEANSTACK;
        } else if (success && !CastToBool(execution.legacy_stack.back())) {
            success = false;
            error = SCRIPT_ERR_EVAL_FALSE;
        }
        outcome.success = success;
        outcome.error = success ? SCRIPT_ERR_OK : error;
        return outcome;
    }

    bool success{EvalTapscriptV2(*execution.v2_stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                 checker, execution.execdata, *execution.budget, &error)};
    if (success) success = CheckTapscriptV2ScriptResult(*execution.v2_stack, *execution.budget, &error);
    outcome.success = success;
    outcome.error = error;
    outcome.varops_consumed = execution.initial_budget - *execution.budget->Remaining();
    return outcome;
}

static EvalOutcome Evaluate(const MaterializedCase& test_case, const BenchSignatureChecker& checker,
                            uint64_t budget = TOTAL_VAROPS_BUDGET)
{
    PreparedExecution execution{PrepareExecution(test_case, false, budget)};
    return ExecutePrepared(test_case, checker, execution);
}

static CScript BuildScript(const CScript& sequence, uint64_t repetitions,
                           size_t cleanup_items)
{
    if (cleanup_items >= SCRIPT_BYTES) {
        throw std::runtime_error("cleanup suffix exceeds script size limit");
    }
    const size_t suffix_size{cleanup_items + 1};
    if (!sequence.empty() && repetitions > (SCRIPT_BYTES - suffix_size) / sequence.size()) {
        throw std::runtime_error("sequence repetitions exceed script size limit");
    }

    CScript script;
    script.reserve(repetitions * sequence.size() + suffix_size);
    for (uint64_t i{0}; i < repetitions; ++i) {
        script.insert(script.end(), sequence.begin(), sequence.end());
    }
    if (cleanup_items != 0) {
        script.insert(script.end(), cleanup_items, static_cast<unsigned char>(OP_DROP));
    }
    script << OP_1;
    if (script.size() > SCRIPT_BYTES) {
        throw std::runtime_error("script construction exceeded size limit");
    }
    return script;
}

static valtype V2ControlBlock()
{
    valtype control_block(TAPROOT_CONTROL_BASE_SIZE, 0);
    control_block[0] = TAPROOT_LEAF_TAPSCRIPT_V2;
    return control_block;
}

static CMutableTransaction EmptyWitnessTransaction(size_t empty_items, const CScript& script)
{
    CMutableTransaction tx;
    tx.vin.resize(2);
    const valtype control_block{V2ControlBlock()};
    const valtype selector{0, 1, 0, 0x30, 0x80, 0}; // Collate input 1's witness items.
    tx.vin[0].scriptWitness.stack = {valtype{1}, selector,
                                    valtype{script.begin(), script.end()}, control_block};
    auto& source_witness{tx.vin[1].scriptWitness.stack};
    source_witness.assign(empty_items, valtype{});
    // An immediate-success leaf makes the large source witness plausible.
    source_witness.push_back(valtype{static_cast<unsigned char>(OP_1NEGATE)});
    source_witness.push_back(control_block);
    tx.vout.emplace_back(0, CScript{} << OP_RETURN);
    return tx;
}

static std::shared_ptr<const TransactionFixture> MakeOpTxContext(size_t empty_items, const CScript& script)
{
    CMutableTransaction tx{EmptyWitnessTransaction(empty_items, script)};
    constexpr int32_t TARGET_WEIGHT{MAX_BLOCK_WEIGHT - 10'000};
    const int32_t initial_weight{GetTransactionWeight(CTransaction{tx})};
    if (initial_weight >= TARGET_WEIGHT) throw std::runtime_error("OP_TX fixture exceeds weight target");
    tx.vout[0].scriptPubKey.resize(1 + (TARGET_WEIGHT - initial_weight) / 4);
    while (GetTransactionWeight(CTransaction{tx}) > TARGET_WEIGHT) {
        tx.vout[0].scriptPubKey.pop_back();
    }
    if (GetTransactionWeight(CTransaction{tx}) < TARGET_WEIGHT - 3) {
        throw std::runtime_error("OP_TX fixture did not reach weight target");
    }
    return std::make_shared<TransactionFixture>(tx, V2ControlBlock());
}

static uint64_t CalibrateRepeatVarops(const CaseSpec& spec, const std::vector<valtype>& stack,
                                      const CryptoFixture& fixture)
{
    if (DomainFor(spec.role) != ExecutionDomain::GSR_TAPSCRIPT_V2 || spec.sequence.empty()) return 0;
    MaterializedCase calibration;
    calibration.spec = &spec;
    calibration.initial_stack = stack;
    calibration.repetitions = 1;
    calibration.script = spec.sequence;
    const size_t cleanup_items{spec.cleanup_items.value_or(stack.size())};
    if (cleanup_items != 0) {
        calibration.script.insert(calibration.script.end(), cleanup_items, static_cast<unsigned char>(OP_DROP));
    }
    calibration.script << OP_1;
    if (spec.empty_witness_items) {
        calibration.transaction = MakeOpTxContext(*spec.empty_witness_items, calibration.script);
    }
    BenchSignatureChecker checker{fixture, calibration.transaction.get()};
    const EvalOutcome outcome{Evaluate(calibration, checker)};
    if (!outcome.success || outcome.error != SCRIPT_ERR_OK) {
        throw std::runtime_error(strprintf("one-sequence calibration failed for %s: %s",
                                           spec.name, ScriptErrorString(outcome.error)));
    }
    const uint64_t suffix_cost{
        InitialProducerCost(stack) + CandidateCleanupCost(stack, cleanup_items) +
        varops::COST_F + varops::COST_SCALAR_OUTPUT +
        varops::COST_PREP_FIXED + varops::COST_PREP_BYTE * 8 +
        varops::COST_READ_FIXED + varops::COST_READ * 8};
    if (outcome.varops_consumed < suffix_cost) {
        throw std::runtime_error("calibration consumed less than the cleanup and final-result cost");
    }
    return outcome.varops_consumed - suffix_cost;
}

static MaterializedCase Materialize(const CaseSpec& spec, const CryptoFixture& fixture,
                                    uint64_t budget_ceiling = TOTAL_VAROPS_BUDGET)
{
    MaterializedCase materialized;
    materialized.spec = &spec;
    materialized.initial_stack = spec.stack_factory(fixture);
    if (!InitialStackAllowed(DomainFor(spec.role), materialized.initial_stack)) {
        throw std::runtime_error(strprintf("%s has an invalid initial stack for %s",
                                           spec.name, DomainName(DomainFor(spec.role))));
    }

    const size_t cleanup_items{spec.cleanup_items.value_or(materialized.initial_stack.size())};
    const size_t suffix_size{cleanup_items + 1};
    const uint64_t script_limit{spec.sequence.empty() ? 0 : (SCRIPT_BYTES - suffix_size) / spec.sequence.size()};
    if (spec.expected_error == SCRIPT_ERR_OK || spec.repeat_mode == RepeatMode::VAROP_REJECTION) {
        materialized.varops_per_repeat = CalibrateRepeatVarops(spec, materialized.initial_stack, fixture);
    }
    if (spec.expected_varops_per_repeat && materialized.varops_per_repeat != *spec.expected_varops_per_repeat) {
        throw std::runtime_error(strprintf("sequence varops mismatch for %s: expected %u, got %u",
                                           spec.name, *spec.expected_varops_per_repeat,
                                           materialized.varops_per_repeat))
            ;
    }

    if (spec.repeat_mode == RepeatMode::FIXED) {
        materialized.repetitions = spec.fixed_repetitions;
        materialized.saturation = spec.saturation_hint;
    } else if (spec.repeat_mode == RepeatMode::VAROP_REJECTION) {
        if (materialized.varops_per_repeat == 0) {
            throw std::runtime_error(strprintf("%s requests varops rejection with a zero-cost sequence", spec.name));
        }
        materialized.repetitions = TOTAL_VAROPS_BUDGET / materialized.varops_per_repeat + 1;
        materialized.saturation = "varops-limit";
    } else {
        uint64_t budget_limit{std::numeric_limits<uint64_t>::max()};
        if (DomainFor(spec.role) == ExecutionDomain::GSR_TAPSCRIPT_V2 && materialized.varops_per_repeat != 0) {
            const uint64_t suffix_cost{
                InitialProducerCost(materialized.initial_stack) + CandidateCleanupCost(materialized.initial_stack, cleanup_items) +
                varops::COST_F + varops::COST_SCALAR_OUTPUT +
                varops::COST_PREP_FIXED + varops::COST_PREP_BYTE * 8 +
                varops::COST_READ_FIXED + varops::COST_READ * 8};
            budget_limit = suffix_cost <= budget_ceiling ?
                (budget_ceiling - suffix_cost) / materialized.varops_per_repeat : 0;
        }
        materialized.repetitions = std::min({script_limit, budget_limit, spec.max_repetitions});
        if (budget_limit < script_limit && materialized.repetitions == budget_limit) {
            materialized.saturation = "varops-budget";
        } else if (materialized.repetitions == spec.max_repetitions && spec.max_repetitions < script_limit) {
            materialized.saturation = spec.saturation_hint.empty() ? "explicit-limit" : spec.saturation_hint;
        } else {
            materialized.saturation = "script-bytes";
        }
    }

    if (budget_ceiling == TOTAL_VAROPS_BUDGET && spec.expected_saturation &&
        materialized.saturation != SaturationName(*spec.expected_saturation)) {
        throw std::runtime_error(strprintf("saturation mismatch for %s: expected %s, got %s",
                                           spec.name, SaturationName(*spec.expected_saturation),
                                           materialized.saturation));
    }

    if (!spec.sequence.empty() && materialized.repetitions == 0) {
        if (budget_ceiling != TOTAL_VAROPS_BUDGET) return materialized; // Cannot sample even one sequence.
        throw std::runtime_error(strprintf("%s cannot execute its target sequence", spec.name));
    }
    if (!spec.sequence.empty() && materialized.repetitions > script_limit) {
        throw std::runtime_error(strprintf("%s cannot reach its requested termination inside 4MB", spec.name));
    }
    materialized.script = BuildScript(spec.sequence, materialized.repetitions, cleanup_items);
    if (spec.empty_witness_items) {
        materialized.transaction = MakeOpTxContext(*spec.empty_witness_items, materialized.script);
    }
    return materialized;
}

static CScript Ops(std::initializer_list<opcodetype> opcodes)
{
    CScript script;
    for (const opcodetype opcode : opcodes)
        script << opcode;
    return script;
}

static void AddCase(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                    std::string case_label, std::string shape,
                    std::string pattern, CScript sequence, StackFactory stack_factory,
                    CaseOptions options = {})
{
    const std::string opcode_name{OpcodeName(opcode)};
    const std::string sequence_opcodes{
        options.sequence_label.empty() ? SequenceOpcodeNames(sequence) : options.sequence_label};
    const std::string name{strprintf("%s/%s/%s/%s/%s/%s/%s", DomainName(DomainFor(role)), opcode_name,
                                     sequence_opcodes, case_label, shape, pattern, ScriptErrorString(options.expected_error))};
    specs.push_back({name, opcode, opcode_name, sequence_opcodes, std::move(shape), std::move(pattern),
                     role, role == HeadlineRole::NEW_GSR, options.expected_error, options.repeat_mode,
                     options.fixed_repetitions, options.max_repetitions, std::move(sequence),
                     std::move(stack_factory), options.cleanup_items, std::move(options.saturation_hint),
                     options.expected_varops_per_repeat, options.expected_saturation,
                     options.empty_witness_items, options.op_tx_collate,
                     options.op_tx_result_values});
}

static CaseOptions FixedCase(ScriptError error, uint64_t repetitions, std::optional<size_t> cleanup_items,
                             std::string saturation)
{
    CaseOptions options{};
    options.expected_error = error;
    options.repeat_mode = RepeatMode::FIXED;
    options.fixed_repetitions = repetitions;
    options.max_repetitions = repetitions;
    options.cleanup_items = cleanup_items;
    options.saturation_hint = std::move(saturation);
    return options;
}

static CaseOptions VaropsRejection(std::optional<uint64_t> expected_cost = std::nullopt)
{
    CaseOptions options{};
    options.expected_error = SCRIPT_ERR_VAROP_COUNT;
    options.repeat_mode = RepeatMode::VAROP_REJECTION;
    options.expected_varops_per_repeat = expected_cost;
    return options;
}

static ItemFactory CompactItem(valtype item)
{
    const size_t size{item.size()};
    if (item.size() <= 1024) {
        return [item = std::move(item)] { return item; };
    }

    if (std::ranges::all_of(item, [&](unsigned char byte) { return byte == item.front(); })) {
        const unsigned char fill{item.front()};
        return [size, fill] { return valtype(size, fill); };
    }

    if (std::ranges::all_of(item, [index = size_t{0}](unsigned char byte) mutable {
            return byte == ((index++ & 1) ? 0x55 : 0xaa);
        })) {
        return [size] {
            valtype expanded(size);
            for (size_t index{0}; index < size; ++index)
                expanded[index] = (index & 1) ? 0x55 : 0xaa;
            return expanded;
        };
    }

    std::vector<std::pair<size_t, unsigned char>> exceptions;
    for (size_t index{0}; index < size; ++index) {
        if (item[index] != 0) exceptions.emplace_back(index, item[index]);
        if (exceptions.size() > 64) {
            return [item = std::move(item)] { return item; };
        }
    }
    return [size, exceptions = std::move(exceptions)] {
        valtype expanded(size, 0);
        for (const auto& [index, byte] : exceptions) {
            expanded[index] = byte;
        }
        return expanded;
    };
}

static StackFactory FixedStack(std::vector<valtype> stack)
{
    const uint64_t expanded_bytes{StackPayloadBytes(stack)};
    std::vector<ItemFactory> factories;
    factories.reserve(stack.size());
    for (valtype& item : stack)
        factories.push_back(CompactItem(std::move(item)));
    stack.clear();
    stack.shrink_to_fit();
    if (expanded_bytes >= 1024U * 1024U) ReleaseAllocatorCaches();
    return [factories = std::move(factories)](const CryptoFixture&) {
        std::vector<valtype> expanded;
        expanded.reserve(factories.size());
        for (const ItemFactory& factory : factories)
            expanded.push_back(factory());
        return expanded;
    };
}

static void AddPreAndV2Cases(std::vector<CaseSpec>& specs, opcodetype opcode,
                             std::string case_label, std::string shape, std::string pattern,
                             const CScript& sequence, StackFactory factory)
{
    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            case_label, shape, pattern, sequence, factory);
    AddCase(specs, opcode, HeadlineRole::COMMON_V2,
            std::move(case_label), std::move(shape), std::move(pattern), sequence, std::move(factory));
}

static void AddCostCase(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                        std::string case_label, std::string shape, std::string pattern,
                        const CScript& sequence, StackFactory factory, uint64_t expected_varops_per_repeat,
                        std::optional<SaturationExpectation> expected_saturation = std::nullopt)
{
    CaseOptions options{};
    // Candidate static formulas are attached by the family-specific builders.
    // Legacy-sized crossover probes remain useful corpus cases, but must not
    // claim candidate parity or a candidate saturation boundary.
    (void)expected_varops_per_repeat;
    (void)expected_saturation;
    AddCase(specs, opcode, role, std::move(case_label), std::move(shape), std::move(pattern),
            sequence, std::move(factory), std::move(options));
}

template <typename Cost, typename Stack, typename Shape>
static void AddCostCrossovers(std::vector<CaseSpec>& specs, opcodetype opcode,
                              std::string_view label, std::string_view pattern,
                              const CScript& sequence, size_t cleanup_items, size_t maximum,
                              Cost cost, Stack stack, Shape shape)
{
    const uint64_t execution_cost{SequenceExecutionCost(sequence)};
    const auto total_cost = [&](size_t size) { return execution_cost + cost(size); };
    for (const auto& [size, saturation] :
         FindCrossoverPair(sequence.size(), cleanup_items, maximum, total_cost)) {
        AddCostCase(specs, opcode, HeadlineRole::NEW_GSR, std::string{label}, shape(size),
                    std::string{pattern}, sequence, stack(size), cost(size), saturation);
    }
}

static CScript OneToOneSequence(opcodetype opcode, bool three_way) { return three_way ? Ops({OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}) : Ops({OP_DUP, opcode, OP_DROP}); }

static uint64_t OneToOneTargetCost(opcodetype opcode, size_t size)
{
    switch (opcode) {
    case OP_1ADD: return varops::AddCost(size, 1);
    case OP_1SUB: return varops::SubCost(size, 1);
    case OP_NOT:
    case OP_0NOTEQUAL: return varops::CompareZeroCost(size);
    case OP_INVERT: return varops::InvertCost(size);
    case OP_2MUL: return varops::TwoMulCost(size);
    case OP_2DIV: return varops::TwoDivCost(size);
    case OP_RIPEMD160:
    case OP_SHA1:
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256: return size * varops::COST_HASH;
    default: throw std::runtime_error("unsupported one-to-one opcode");
    }
}

static uint64_t OneToOneSequenceCost(opcodetype opcode, size_t size, bool three_way,
                                     std::string_view pattern = {})
{
    const uint64_t transforms{three_way ? 3U : 1U};
    // Independently count complete logical-opcode formulas from whole-varop terms.
    const uint64_t copy_opcode{varops::COST_F + transforms *
        (varops::COST_COPY_FIXED + varops::COST_COPY_BYTE * size)};
    switch (opcode) {
    case OP_NOT:
    case OP_0NOTEQUAL: {
        const bool input_nonzero{pattern != "zero"};
        const size_t output_size{(opcode == OP_NOT ? !input_nonzero : input_nonzero) ? 1U : 0U};
        const uint64_t target{varops::COST_F + varops::COST_PREP_FIXED +
            varops::COST_PREP_BYTE * varops::detail::WordSize(size) +
            varops::COST_READ_FIXED + varops::COST_READ * varops::detail::WordSize(size) +
            varops::COST_SCALAR_OUTPUT};
        return copy_opcode + transforms * (target + CandidateDropCost(output_size));
    }
    case OP_1ADD:
    case OP_1SUB: {
        const uint64_t words{varops::detail::WordSize(size)};
        const bool low{pattern == "padded-low" || pattern == "one-low"};
        const size_t output_size{low ? (opcode == OP_1SUB ? 0U : 1U) :
                                      (opcode == OP_1SUB && pattern == "late-nonzero" && size != 0 ? size - 1 : size)};
        const uint64_t output_words{varops::detail::WordSize(output_size)};
        const uint64_t target{varops::COST_F + varops::COST_PREP_FIXED +
            varops::COST_PREP_BYTE * words + varops::COST_ARITH_FIXED +
            varops::COST_ARITH_BYTE * words + varops::COST_OUTPUT_FIXED +
            varops::COST_OUTPUT_BYTE * output_words};
        return copy_opcode + transforms * (target + CandidateDropCost(output_size));
    }
    case OP_INVERT:
    case OP_2MUL:
    case OP_2DIV: {
        const uint64_t words{varops::detail::WordSize(size)};
        const bool low{pattern == "padded-low" || pattern == "one-low"};
        const size_t output_size{
            low && opcode == OP_2DIV ? 0U :
            low && opcode == OP_2MUL ? 1U :
            opcode == OP_2DIV && pattern == "late-nonzero" && size != 0 ? size - 1 : size};
        const uint64_t output_words{varops::detail::WordSize(output_size)};
        const uint64_t target{varops::COST_F + varops::COST_PREP_FIXED +
            varops::COST_PREP_BYTE * words + varops::COST_BIT_FIXED +
            varops::COST_BIT * words + varops::COST_OUTPUT_FIXED +
            varops::COST_OUTPUT_BYTE * output_words};
        return copy_opcode + transforms * (target + CandidateDropCost(output_size));
    }
    case OP_RIPEMD160:
    case OP_SHA1:
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256: {
        const size_t output_size{
            opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160 ? 20U : 32U};
        unsigned __int128 hash_q{0};
        IndependentAdd(hash_q, varops::COST_F);
        if (opcode == OP_SHA1) {
            IndependentAdd(hash_q, varops::COST_H1_FIXED);
            IndependentAdd(hash_q, varops::COST_H1_BYTE, size);
        } else if (opcode == OP_RIPEMD160) {
            IndependentAdd(hash_q, varops::COST_H160_FIXED);
            IndependentAdd(hash_q, varops::COST_H160_BYTE, size);
        } else if (opcode == OP_SHA256) {
            IndependentAdd(hash_q, varops::COST_H256_FIXED);
            IndependentAdd(hash_q, varops::COST_H256_BYTE, size);
        } else if (opcode == OP_HASH160) {
            IndependentAdd(hash_q, varops::COST_H256_FIXED);
            IndependentAdd(hash_q, varops::COST_H256_BYTE, size);
            IndependentAdd(hash_q, varops::COST_H160_FIXED);
            IndependentAdd(hash_q, varops::COST_H160_BYTE, 32);
        } else {
            IndependentAdd(hash_q, varops::COST_H256_FIXED, 2);
            IndependentAdd(hash_q, varops::COST_H256_BYTE, size + 32);
        }
        IndependentAdd(hash_q, varops::COST_COPY_FIXED);
        IndependentAdd(hash_q, varops::COST_COPY_BYTE, output_size);
        const uint64_t hash_opcode{IndependentCharge(hash_q)};
        return copy_opcode + transforms * (hash_opcode + CandidateDropCost(output_size));
    }
    default:
        break;
    }
    return transforms * size * varops::COST_COPYING +
           transforms * OneToOneTargetCost(opcode, size);
}

static uint64_t TruthCopyCost(size_t size) { return size * varops::COST_COPYING + varops::CompareZeroCost(size); }
static StackFactory OneToOneStack(size_t size, std::string_view pattern, bool three_way) { return FixedStack(std::vector<valtype>(three_way ? 3U : 1U, PatternBytes(size, pattern))); }

static void AddOneToOneSpec(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                            std::string_view family, size_t size, std::string pattern, bool three_way,
                            std::optional<SaturationExpectation> expected_saturation = std::nullopt)
{
    const CScript sequence{OneToOneSequence(opcode, three_way)};
    const std::string case_label{strprintf("%s-%s", family, three_way ? "3way" : "single")};
    const std::optional<uint64_t> expected_varops_per_repeat{
        DomainFor(role) == ExecutionDomain::GSR_TAPSCRIPT_V2 ?
            std::optional<uint64_t>{
                OneToOneSequenceCost(opcode, size, three_way, pattern)
            } : std::nullopt};
    StackFactory factory{OneToOneStack(size, pattern, three_way)};
    CaseOptions options{};
    options.expected_varops_per_repeat = expected_varops_per_repeat;
    AddCase(specs, opcode, role, case_label, FormatBytes(size), std::move(pattern), sequence,
            std::move(factory), std::move(options));
}

static void AddOneToOneCrossovers(std::vector<CaseSpec>& specs, opcodetype opcode,
                                  HeadlineRole role, std::string_view label, std::string_view pattern,
                                  size_t maximum, bool three_way,
                                  std::optional<HeadlineRole> script_role = std::nullopt)
{
    const CScript sequence{OneToOneSequence(opcode, three_way)};
    const auto cost{[=](size_t size) {
        return OneToOneSequenceCost(opcode, size, three_way, pattern);
    }};
    for (const auto& [size, saturation] :
         FindCrossoverPair(sequence.size(), three_way ? 3 : 1, maximum, cost)) {
        if (script_role) {
            AddOneToOneSpec(specs, opcode, *script_role, label, size, std::string{pattern},
                            three_way, SaturationExpectation::SCRIPT_BYTES);
        }
        AddOneToOneSpec(specs, opcode, role, label, size, std::string{pattern}, three_way, saturation);
    }
}

static std::vector<size_t> SelectSizes(std::initializer_list<size_t> full,
                                       size_t maximum = std::numeric_limits<size_t>::max())
{
    std::vector<size_t> sizes{full};
    std::erase_if(sizes, [maximum](size_t size) { return size > maximum; });
    std::sort(sizes.begin(), sizes.end());
    sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
    return sizes;
}

static std::vector<size_t> PreDataSizes() { return SelectSizes({0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 519, 520}); }
static std::vector<size_t> V2LargeSizes(size_t maximum) { return SelectSizes({521, 1024, 4096, 65536, 262144, 1048576, 2000000, maximum}, maximum); }

static void AddUnaryDataCases(std::vector<CaseSpec>& specs, opcodetype opcode,
                              bool restored, size_t maximum = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
    if (!restored) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                        "unary-preserve", 4, "padded-low", true);
        AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                        "unary-preserve", 4, "padded-low", true);
    }
    const std::vector<size_t> v2_sizes{
        restored ? SelectSizes({17, 521, maximum}, maximum) :
                   SelectSizes({521, maximum}, maximum)};
    for (size_t size : v2_sizes) {
        const std::string pattern{size == maximum ? "late-nonzero" : "padded-low"};
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-preserve", size,
                        pattern, size <= MAX_THREE_WAY_ELEMENT_SIZE);
    }
    if ((opcode == OP_2MUL || opcode == OP_2DIV)) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-preserve", maximum,
                        "padded-low", false);
    }
    AddOneToOneCrossovers(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover",
                          "padded-low", MAX_THREE_WAY_ELEMENT_SIZE, true);
}

static void AddBinaryDataCases(std::vector<CaseSpec>& specs, opcodetype opcode,
                               bool restored, size_t maximum = 2'000'000)
{
    const bool verify_opcode{opcode == OP_EQUALVERIFY || opcode == OP_NUMEQUALVERIFY};
    const bool byte_compare{opcode == OP_EQUAL || opcode == OP_EQUALVERIFY};
    const CScript sequence{verify_opcode ? Ops({OP_2DUP, opcode}) : Ops({OP_2DUP, opcode, OP_DROP})};
    if (opcode == OP_ADD) {
        valtype right{PatternBytes(17, "alternating")};
        right.back() &= 0x7f;
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "arithmetic-pilot", "1Bx17B", "short-long", sequence,
                FixedStack({valtype{1}, std::move(right)}));
        for (size_t size : {8U, 16U}) {
            // 2DUP reserves input word padding, but ff...ff + 1 still
            // needs another word for its result on every repetition.
            AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                        "carry-boundary", strprintf("1Bx%uB", size), "all-ff-plus-one",
                        sequence, FixedStack({valtype{1}, valtype(size, 0xff)}),
                        varops::AddCost(1, size) + (1 + size) * varops::COST_COPYING);
        }
    }
    if (!restored) {
        const size_t size{byte_compare ? MAX_SCRIPT_ELEMENT_SIZE : 4};
        const std::string pattern{byte_compare ? "equal" : "padded-low"};
        valtype first{PatternBytes(size, byte_compare ? "alternating" : "padded-low")};
        valtype second{first};
        if (opcode == OP_SUB) first = PaddedNumber(3, size);
        if (opcode == OP_SUB) second = PaddedNumber(1, size);
        AddPreAndV2Cases(specs, opcode, "binary-preserve",
                         FormatBytes(size) + "x" + FormatBytes(size), pattern,
                         sequence, FixedStack({first, second}));
    }
    const std::vector<size_t> v2_sizes{restored ? std::vector<size_t>{1, maximum} :
                                                 std::vector<size_t>{maximum}};
    for (size_t size : v2_sizes) {
        valtype first{PatternBytes(size, "alternating")};
        valtype second{first};
        if (opcode == OP_SUB) {
            first = PaddedNumber(3, size);
            second = PaddedNumber(1, size);
        }
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(size) + "x" + FormatBytes(size), "equal-dense",
                sequence, FixedStack({first, second}));
    }
    if ((opcode == OP_MIN || opcode == OP_MAX)) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(maximum) + "x" + FormatBytes(maximum), "equal-padded-low",
                sequence, FixedStack({PaddedNumber(1, maximum), PaddedNumber(1, maximum)}));
        // Leave weight for the script and transaction; outputs can fund the remaining budget.
        constexpr size_t FUNDED_SIZE{1'950'000};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(FUNDED_SIZE) + "x" + FormatBytes(FUNDED_SIZE),
                "equal-padded-low-funded", sequence,
                FixedStack({PaddedNumber(1, FUNDED_SIZE), PaddedNumber(1, FUNDED_SIZE)}));
        const valtype dense{PatternBytes(FUNDED_SIZE, "alternating")};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(FUNDED_SIZE) + "x" + FormatBytes(FUNDED_SIZE),
                "equal-dense-funded", sequence, FixedStack({dense, dense}));
    }
    if (maximum >= 65536 && opcode != OP_EQUALVERIFY) {
        const bool numeric_verify{opcode == OP_NUMEQUALVERIFY};
        const bool subtraction{opcode == OP_SUB};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", "64KBx1B", "asymmetric-long-short", sequence,
                FixedStack({subtraction ? PaddedNumber(3, 65536) : (numeric_verify ? PaddedNumber(1, 65536) : PatternBytes(65536, "alternating")),
                            subtraction ? PaddedNumber(1, 1) : PatternBytes(1, "one-low")}));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", "1Bx64KB", "asymmetric-short-long", sequence,
                FixedStack({subtraction ? PaddedNumber(3, 1) : PatternBytes(1, "one-low"),
                            subtraction ? PaddedNumber(1, 65536) : (numeric_verify ? PaddedNumber(1, 65536) : PatternBytes(65536, "alternating"))}));
    }
}

static void AddStackOpcodeCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const auto add_shared_case = [&](std::string case_label, CScript sequence, std::vector<valtype> stack) {
        AddPreAndV2Cases(specs, opcode, std::move(case_label), "32B", "dense", sequence,
                         FixedStack(std::move(stack)));
    };
    switch (opcode) {
    case OP_TOALTSTACK:
    case OP_FROMALTSTACK:
        add_shared_case("altstack-roundtrip", Ops({OP_TOALTSTACK, OP_FROMALTSTACK}), {PatternBytes(32, "dense")});
        break;
    case OP_DROP: add_shared_case("dup-drop", Ops({OP_DUP, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_2DROP: add_shared_case("2dup-2drop", Ops({OP_2DUP, OP_2DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_DUP: add_shared_case("dup-drop", Ops({OP_DUP, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_2DUP: add_shared_case("2dup-2drop", Ops({OP_2DUP, OP_2DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_3DUP: add_shared_case("3dup-cleanup", Ops({OP_3DUP, OP_2DROP, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_OVER: add_shared_case("over-drop", Ops({OP_OVER, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_2OVER: add_shared_case("2over-2drop", Ops({OP_2OVER, OP_2DROP}), std::vector<valtype>(4, PatternBytes(32, "dense"))); break;
    case OP_IFDUP: {
        const CScript true_sequence{Ops({OP_IFDUP, OP_DROP})};
        AddPreAndV2Cases(specs, opcode, "ifdup-drop", "1B", "true", true_sequence,
                         FixedStack({valtype{1}}));
        const CScript false_sequence{Ops({OP_IFDUP})};
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "ifdup-true", "520B", "late-nonzero", true_sequence,
                FixedStack({PatternBytes(520, "late-nonzero")}));
        AddCostCase(specs, opcode, HeadlineRole::COMMON_V2,
                    "ifdup-true", "520B", "late-nonzero", true_sequence,
                    FixedStack({PatternBytes(520, "late-nonzero")}), TruthCopyCost(520));
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "ifdup-false", "520B", "zero", false_sequence,
                FixedStack({PatternBytes(520, "zero")}));
        AddCostCase(specs, opcode, HeadlineRole::COMMON_V2,
                    "ifdup-false", "520B", "zero", false_sequence,
                    FixedStack({PatternBytes(520, "zero")}), TruthCopyCost(520));

        AddCostCrossovers(specs, opcode, "ifdup-true-crossover", "late-nonzero", true_sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TruthCopyCost, [](size_t size) { return FixedStack({PatternBytes(size, "late-nonzero")}); }, FormatBytes);
        AddCostCrossovers(specs, opcode, "ifdup-false-crossover", "zero", false_sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TruthCopyCost, [](size_t size) { return FixedStack({PatternBytes(size, "zero")}); }, FormatBytes);
        AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "ifdup-true-scale-tail", "4MB", "late-nonzero", true_sequence,
                    FixedStack({PatternBytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero")}),
                    TruthCopyCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
        break;
    }
    case OP_NIP: add_shared_case("2dup-nip-drop", Ops({OP_2DUP, OP_NIP, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_TUCK: add_shared_case("tuck-drop-swap", Ops({OP_TUCK, OP_DROP, OP_SWAP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_SWAP: add_shared_case("swap-twice", Ops({OP_SWAP, OP_SWAP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_2SWAP: add_shared_case("2swap-twice", Ops({OP_2SWAP, OP_2SWAP}), std::vector<valtype>(4, PatternBytes(32, "dense"))); break;
    case OP_ROT: add_shared_case("rot-thrice", Ops({OP_ROT, OP_ROT, OP_ROT}), std::vector<valtype>(3, PatternBytes(32, "dense"))); break;
    case OP_2ROT: add_shared_case("2rot-thrice", Ops({OP_2ROT, OP_2ROT, OP_2ROT}), std::vector<valtype>(6, PatternBytes(32, "dense"))); break;
    case OP_DEPTH: add_shared_case("depth-drop", Ops({OP_DEPTH, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_PICK: {
        add_shared_case("pick-depth-1", Ops({OP_DUP, OP_PICK, OP_DROP}),
                        {PatternBytes(32, "dense"), PatternBytes(32, "alternating"), Val64(1).MoveToValtype()});
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "pick-max-depth-one-shot", "32768-items", "heterogeneous-buried", Ops({OP_PICK}), [](const CryptoFixture&) {
                        std::vector<valtype> stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{0x01});
                        stack.front() = PatternBytes(520, "late-nonzero");
                        stack.push_back(Val64(MAX_TAPSCRIPT_V2_STACK_SIZE - 2).MoveToValtype());
                        return stack; }, FixedCase(SCRIPT_ERR_OK, 1, MAX_TAPSCRIPT_V2_STACK_SIZE, "stack-depth"));
        break;
    }
    case OP_ROLL: {
        CScript roll_one;
        roll_one << OP_1 << OP_ROLL << OP_SWAP;
        add_shared_case("roll-depth-1-neutral", roll_one, {PatternBytes(32, "dense"), PatternBytes(32, "alternating")});
        CaseOptions deep_stack_options{};
        deep_stack_options.expected_saturation = SaturationExpectation::SCRIPT_BYTES;
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "deep-stack", "1000x4B", "dense",
                Ops({OP_DEPTH, OP_1SUB, OP_ROLL}),
                FixedStack(std::vector<valtype>(1000, PatternBytes(4, "dense"))),
                std::move(deep_stack_options));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "roll-max-depth-one-shot", "32768-items", "heterogeneous-buried", Ops({OP_ROLL}), [](const CryptoFixture&) {
                        std::vector<valtype> stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{0x01});
                        stack.front() = PatternBytes(520, "late-nonzero");
                        stack.push_back(Val64(MAX_TAPSCRIPT_V2_STACK_SIZE - 2).MoveToValtype());
                        return stack; }, FixedCase(SCRIPT_ERR_OK, 1, MAX_TAPSCRIPT_V2_STACK_SIZE - 1, "stack-depth"));
        break;
    }
    default: throw std::runtime_error("unhandled stack opcode registry entry");
    }

    if ((opcode == OP_DUP || opcode == OP_2DUP || opcode == OP_OVER)) {
        const CScript sequence{opcode == OP_DUP  ? Ops({OP_DUP, OP_DROP}) :
                               opcode == OP_2DUP ? Ops({OP_2DUP, OP_2DROP}) :
                                                   Ops({OP_OVER, OP_DROP})};
        const size_t count{opcode == OP_DUP ? 1U : 2U};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "large-copy", opcode == OP_DUP ? "4MB" : "2MBx2", "late-nonzero", sequence,
                [count](const CryptoFixture&) { return std::vector<valtype>(count, PatternBytes(4'000'000 / count, "late-nonzero")); });
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "large-copy-varops-reject", opcode == OP_DUP ? "4MB" : "2MBx2", "late-nonzero", sequence, [count](const CryptoFixture&) { return std::vector<valtype>(count, PatternBytes(4'000'000 / count, "late-nonzero")); }, VaropsRejection());
    }
}

static void AddHashCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    for (size_t size : {0U, 1U, 32U, 33U, 55U, 56U, 64U, 65U, 520U}) {
        const CScript sequence{OneToOneSequence(opcode, false)};
        CaseOptions options{FixedCase(SCRIPT_ERR_OK, 1, 1, "cost-parity-boundary")};
        options.expected_varops_per_repeat = OneToOneSequenceCost(opcode, size, false, "late-nonzero");
        AddCase(specs, opcode, HeadlineRole::DIAGNOSTIC, "hash-padding-boundary",
                FormatBytes(size), "late-nonzero", sequence,
                OneToOneStack(size, "late-nonzero", false), std::move(options));
    }
    for (size_t size : {1U, MAX_SCRIPT_ELEMENT_SIZE}) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                        "hash-preserve", size, "late-nonzero", true);
        AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                        "hash-preserve", size, "late-nonzero", true);
    }
    if (opcode == OP_RIPEMD160 || opcode == OP_SHA1) {
        return;
    }
    AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-preserve",
                    MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero", false);
    AddOneToOneCrossovers(specs, opcode, HeadlineRole::COMMON_V2, "hash-crossover",
                          "late-nonzero", MAX_SCRIPT_ELEMENT_SIZE, true);
}

static void AddOpTxCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    // A second input supplies the witness data, so its contents do not change
    // when the benchmark script is repeated to reach the varops boundary.
    const valtype selector{0, 1, 0, 0x30, 0x80, 0}; // Collate input 1's witness items.
    const CScript sequence{Ops({OP_2DUP, OP_TX, OP_DROP})};
    for (size_t empty_items : {256U, 8192U, 30000U}) {
        constexpr int32_t TARGET_WEIGHT{MAX_BLOCK_WEIGHT - 10'000};
        const int32_t base_weight{GetTransactionWeight(CTransaction{EmptyWitnessTransaction(empty_items, {})})};
        if (base_weight + 11 >= TARGET_WEIGHT) throw std::runtime_error("OP_TX fixture exceeds weight target");

        CaseOptions options{};
        options.cleanup_items = 2;
        options.empty_witness_items = empty_items;
        options.op_tx_collate = true;
        options.op_tx_result_values = empty_items + 2; // source witness also carries OP_1 and its control block
        // Include the script in the transaction's witness weight. Leave eight
        // weight units for the script-length CompactSize growth and rounding.
        options.max_repetitions = (TARGET_WEIGHT - base_weight - 8 - 3) / sequence.size();
        options.saturation_hint = "transaction-weight";
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "collated-empty-witness", strprintf("%u-empty-items", empty_items),
                "other-input", sequence,
                FixedStack({valtype{1}, selector}), std::move(options));
    }
}

static void AddSpliceCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    if (opcode == OP_CAT) {
        const CScript sequence{Ops({OP_2DUP, OP_CAT, OP_DROP})};
        const std::vector<std::pair<size_t, size_t>> shapes{{0, 1}, {1, 1}, {520, 520}, {521, 521}, {65536, 1}, {1, 65536}, {1048576, 1048576}, {2000000, 2000000}};
        for (const auto& [left, right] : shapes) {
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "cat-preserve", FormatBytes(left) + "+" + FormatBytes(right), "asymmetric-dense", sequence,
                    FixedStack({PatternBytes(left, "alternating"), PatternBytes(right, "late-nonzero")}));
        }
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "cat-element-reject", "2000001B+2000001B", "dense", Ops({OP_CAT}),
                FixedStack({PatternBytes(2'000'001, "dense"), PatternBytes(2'000'001, "dense")}),
                FixedCase(SCRIPT_ERR_STACK_ELEMENT_SIZE, 1, 0, "stack-element-limit"));
        // Lifetime calibration showed allocator discontinuities here. Test the
        // actual evaluator's rounded-copy growth path, not only host vectors.
        for (size_t total : {65535U, 65536U, 65537U, 86658U, 135402U, 169252U, 211565U, 330570U}) {
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "cat-allocation-boundary", FormatBytes(total), "half-plus-half", sequence,
                    FixedStack({PatternBytes(total / 2, "alternating"), PatternBytes(total - total / 2, "dense")}));
        }
        // SUBSTR creates an exact-sized result rather than DUP's rounded spare
        // capacity. Recreate that state in Script on every iteration before CAT.
        for (size_t total : {65536U, 65537U, 65538U, 65543U, 65544U, 65545U, 65552U,
                             86657U, 86658U, 86659U, 86666U, 135394U, 135401U, 135402U,
                             135403U, 135410U, 169252U, 211565U, 330570U}) {
            CScript tight{Ops({OP_2DUP, OP_SWAP, OP_0})};
            tight << PaddedNumber(total / 2, 8) << OP_SUBSTR << OP_SWAP << OP_CAT << OP_DROP;
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "cat-tight-allocation", FormatBytes(total), "substr-recreates-tight-buffer", tight,
                    FixedStack({PatternBytes(total / 2, "alternating"), PatternBytes(total - total / 2, "dense")}));
        }
        return;
    }

    // Leave room for duplicated, heavily padded offset/length operands while
    // keeping the data operand as close to the 4MB element limit as possible.
    constexpr size_t data_size{3'998'900};
    if (opcode == OP_SUBSTR) {
        const CScript sequence{Ops({OP_3DUP, OP_SUBSTR, OP_DROP})};
        const std::vector<std::tuple<uint64_t, uint64_t, std::string>> params{
            {0, 1, "zero-one"},
            {1, data_size / 2, "one-mid"},
            {data_size / 2, data_size, "mid-past-end"},
        };
        for (const auto& [begin, length, pattern] : params) {
            const size_t numeric_size{pattern == "mid-past-end" ? 521U : 8U};
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "substr-preserve", FormatBytes(data_size) + ":" + pattern, numeric_size > 8 ? "padded-lengths" : "minimal-lengths",
                    sequence, FixedStack({PatternBytes(data_size, "alternating"), PaddedNumber(begin, numeric_size), PaddedNumber(length, numeric_size)}));
        }
        return;
    }

    // Leave room for the script and transaction overhead in a 4 MWU block.
    constexpr size_t funded_data_size{3'950'000};
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    for (const auto& [offset, label] : std::vector<std::pair<uint64_t, std::string>>{
             {0, "zero"}, {1, "one"}, {funded_data_size / 2, "mid"}, {funded_data_size, "end"}, {funded_data_size + 1, "past-end"}}) {
        const size_t numeric_size{label == "past-end" ? 521U : 8U};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "splice-preserve", FormatBytes(funded_data_size) + ":" + label,
                numeric_size > 8 ? "padded-offset" : "minimal-offset", sequence,
                FixedStack({PatternBytes(funded_data_size, "alternating"), PaddedNumber(offset, numeric_size)}));
    }
}

static size_t LargestAffordable(const std::function<uint64_t(size_t)>& cost, size_t maximum)
{
    size_t low{1};
    size_t high{maximum};
    const uint64_t target{TOTAL_VAROPS_BUDGET * 9 / 10};
    while (low < high) {
        const size_t mid{low + (high - low + 1) / 2};
        if (cost(mid) <= target)
            low = mid;
        else
            high = mid - 1;
    }
    return low;
}

static uint64_t MulSequenceCost(size_t left, size_t right)
{
    const uint64_t left_words{varops::detail::WordSize(left)};
    const uint64_t right_words{varops::detail::WordSize(right)};
    const uint64_t rows{std::max(left_words, right_words) / 8};
    const uint64_t row_limbs{std::min(left_words, right_words) / 8};
    const size_t output_size{left + right};
    const uint64_t storage{varops::PRODUCER_LIFETIME_EXPERIMENT ?
        varops::CopyCost(left_words + right_words) + varops::PrepCost(left_words + right_words) +
        varops::CopyCost((row_limbs + 1) * 8) - varops::CopyCost(varops::WordSpan(output_size)) : 0};
    return storage + 3 * varops::COST_F + 2 * varops::COST_COPY_FIXED +
           varops::COST_COPY_BYTE * (left + right) +
           2 * varops::COST_PREP_FIXED +
           varops::COST_PREP_BYTE * (left_words + right_words) +
           rows * (varops::COST_MUL_ROW_FIXED + varops::COST_MUL_ROW * row_limbs +
                   varops::COST_ARITH_FIXED + varops::COST_ARITH_BYTE * (row_limbs + 1) * 8) +
           varops::COST_OUTPUT_FIXED +
           varops::COST_OUTPUT_BYTE * varops::detail::WordSize(output_size);
}

static void AddMulCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    std::vector<std::pair<size_t, size_t>> shapes{{1, 1}, {109, 109}};
    const size_t largest{LargestAffordable([](size_t size) { return MulSequenceCost(size, size); }, 2'000'000)};
    shapes.insert(shapes.end(), {{108, 108}, {110, 110}, {65536, 1}, {1, 65536}, {largest > 1 ? largest - 1 : largest, largest}, {largest, largest}});
    for (const auto& [left, right] : shapes) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-preserve", FormatBytes(left) + "x" + FormatBytes(right), "dense", sequence,
                FixedStack({PatternBytes(left, "alternating"), PatternBytes(right, "late-nonzero")}));
    }
    for (unsigned int ratio : {1U, 4U, 16U, 0U}) {
        const auto right_size{[ratio](size_t left) {
            return ratio == 0 ? size_t{1} : std::max<size_t>(1, left / ratio);
        }};
        const auto sequence_cost{[&](size_t left) {
            return MulSequenceCost(left, right_size(left));
        }};
        const std::string pattern{ratio == 1 ? "balanced-dense" :
                                  ratio == 0 ? "asymmetric-one-byte" :
                                               strprintf("asymmetric-%u-to-1", ratio)};
        AddCostCrossovers(specs, opcode, "mul-crossover", pattern, sequence, 2, 2'000'000, sequence_cost, [&](size_t left) { return FixedStack({PatternBytes(left, "alternating"),
                                                                                                                                                PatternBytes(right_size(left), "late-nonzero")}); }, [&](size_t left) { return FormatBytes(left) + "x" + FormatBytes(right_size(left)); });
    }
    constexpr size_t tail_left{2'000'000};
    constexpr size_t tail_right{1};
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-scale-tail", FormatBytes(tail_left) + "x1B", "asymmetric-long-short",
                sequence, FixedStack({PatternBytes(tail_left, "alternating"), PatternBytes(tail_right, "late-nonzero")}),
                MulSequenceCost(tail_left, tail_right));

    const size_t rejected{largest + 1};
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "mul-varops-reject", FormatBytes(rejected), "dense", sequence,
            FixedStack({PatternBytes(rejected, "alternating"), PatternBytes(rejected, "late-nonzero")}),
            VaropsRejection());
}

static valtype DivisorTopClear(size_t size) { return valtype(size, 0x7f); }

static valtype DivisorTopLimbOne(size_t size)
{
    valtype divisor(size, 0);
    if (size == 0) return divisor;
    divisor.front() = 0xff;
    const size_t top_limb_start{(size - 1) / sizeof(uint64_t) * sizeof(uint64_t)};
    divisor[top_limb_start] = 0x01;
    return divisor;
}

static uint64_t DivModSequenceCost(opcodetype opcode, size_t dividend, size_t divisor)
{
    const uint64_t dividend_words{varops::detail::WordSize(dividend)};
    const uint64_t divisor_words{varops::detail::WordSize(divisor)};
    const uint64_t dividend_limbs{dividend_words / 8};
    const uint64_t divisor_limbs{divisor_words / 8};
    const uint64_t steps{divisor_limbs == 1 ? dividend_limbs : (dividend_limbs > divisor_limbs ? dividend_limbs - divisor_limbs : 1)};
    // OP_2DUP, target, OP_DROP.  The output is at most the dividend size;
    // the dense benchmark fixtures used here retain that padded width.
    return 3 * varops::COST_F + 2 * varops::COST_COPY_FIXED +
           varops::COST_COPY_BYTE * (dividend + divisor) +
           2 * varops::COST_PREP_FIXED +
           varops::COST_PREP_BYTE * (dividend_words + divisor_words) +
           varops::COST_DIV_FIXED +
           varops::COST_DIV_CELL * steps * divisor_limbs +
           varops::COST_OUTPUT_FIXED + varops::COST_OUTPUT_BYTE * dividend_words;
}

static void AddDivModCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    const auto add = [&](valtype dividend, valtype divisor, std::string shape, std::string pattern) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-preserve", std::move(shape), std::move(pattern), sequence,
                FixedStack({std::move(dividend), std::move(divisor)}));
    };
    add(valtype{0x0a}, valtype{0x03}, "1Bx1B", "normalization-short");
    add(PatternBytes(17, "dense"), DivisorTopClear(9), "17Bx9B", "normalization-top-clear");
    // Small normalization and scratch-storage boundaries found by the
    // dense operand sweep; retain them in the full-budget corpus.
    for (const auto& [left, right] : std::array<std::pair<size_t, size_t>, 9>{
             {{9, 1}, {18, 9}, {25, 24}, {26, 25}, {34, 17}, {57, 57}, {65, 57}, {113, 57}, {129, 121}}}) {
        add(PatternBytes(left, "dense"), DivisorTopClear(right),
            FormatBytes(left) + "x" + FormatBytes(right), "small-normalization-boundary");
    }
    valtype short_high_limb{DivisorTopClear(17)};
    short_high_limb.back() = 1;
    add(PatternBytes(34, "dense"), std::move(short_high_limb), "34Bx17B", "normalization-top-byte-one");
    // Reproduce the prepared-kernel sweep's 65/64-limb allocation boundary
    // through normal interpreter execution, including operand restoration.
    const auto seeded = [](size_t size, uint64_t seed) {
        valtype value(size);
        for (auto& byte : value) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            byte = static_cast<unsigned char>(seed);
        }
        value.back() |= 0x80;
        return value;
    };
    for (uint64_t seed : {17U, 127U}) {
        for (bool top_one : {false, true}) {
            valtype divisor{seeded(64 * 8, seed + 5)};
            if (top_one) {
                std::fill(divisor.end() - 8, divisor.end(), 0);
                divisor[divisor.size() - 8] = 1;
            } else {
                divisor.back() = 0x40;
            }
            add(seeded(65 * 8, seed), std::move(divisor), "520Bx512B",
                strprintf("wide-normalization-%s-seed%u", top_one ? "top-one" : "top-clear", seed));
        }
    }
    add(PatternBytes(8, "one-low"), PatternBytes(16, "late-nonzero"), "8Bx16B", "dividend-smaller");
    const valtype addback_dividend{
        0x71, 0x0a, 0x7f, 0x30, 0x34, 0x4d, 0x13, 0x98, 0xb1, 0x15, 0xd5, 0x64, 0xac, 0xc8, 0x9d, 0x56,
        0x5a, 0x64, 0xdc, 0x11, 0x21, 0xf7, 0x22, 0x7c, 0xf9, 0x7f, 0x16, 0xbc, 0xeb, 0xe8, 0x95, 0x85};
    const valtype addback_divisor{
        0xcd, 0x07, 0x2c, 0xd8, 0xbe, 0x6f, 0x9f, 0x62, 0xac, 0x4c, 0x09, 0xc2, 0x82, 0x06, 0xe7, 0xe3,
        0x55, 0x94, 0xaa, 0x6b, 0x34, 0x2f, 0x5d, 0x8a};
    add(addback_dividend, addback_divisor, "32Bx24B", "knuth-d6-add-back");
    const valtype correction_dividend{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b, 0x00};
    const valtype correction_divisor{
        0xe7, 0x26, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b, 0x00};
    add(correction_dividend, correction_divisor, "25Bx17B", "knuth-d3-quotient-correction");

    enum class DivisorPattern { DENSE,
                                TOP_CLEAR,
                                TOP_LIMB_ONE };
    struct RectangularCase {
        unsigned int ratio;
        DivisorPattern pattern;
        std::string_view name;
    };
    const std::array rectangular_cases{
        RectangularCase{4, DivisorPattern::DENSE, "asymmetric-quarter-dense"},
        RectangularCase{16, DivisorPattern::DENSE, "asymmetric-sixteenth-dense"},
        RectangularCase{0, DivisorPattern::DENSE, "asymmetric-one-byte"},
        RectangularCase{4, DivisorPattern::TOP_CLEAR, "asymmetric-quarter-top-clear"},
        RectangularCase{16, DivisorPattern::TOP_LIMB_ONE, "asymmetric-sixteenth-top-limb-one"},
    };
    for (const RectangularCase& rectangular : rectangular_cases) {
        const auto divisor_size{[&](size_t dividend) {
            return rectangular.ratio == 0 ? size_t{1} : std::max<size_t>(1, dividend / rectangular.ratio);
        }};
        const auto sequence_cost{[&](size_t dividend) {
            return DivModSequenceCost(opcode, dividend, divisor_size(dividend));
        }};
        AddCostCrossovers(specs, opcode, "divmod-crossover", rectangular.name, sequence, 2, 2'000'000, sequence_cost, [&](size_t dividend) {
                              const size_t size{divisor_size(dividend)};
                              valtype divisor{rectangular.pattern == DivisorPattern::TOP_CLEAR ? DivisorTopClear(size) :
                                              rectangular.pattern == DivisorPattern::TOP_LIMB_ONE ? DivisorTopLimbOne(size) :
                                                                                                   PatternBytes(size, "dense")};
                              return FixedStack({PatternBytes(dividend, "dense"), std::move(divisor)}); }, [&](size_t dividend) { return FormatBytes(dividend) + "x" + FormatBytes(divisor_size(dividend)); });
    }
    constexpr size_t tail_dividend{65536};
    constexpr size_t tail_divisor{16384};
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-scale-tail", "64KBx16KB", "asymmetric-quarter-top-clear", sequence,
                FixedStack({PatternBytes(tail_dividend, "dense"), DivisorTopClear(tail_divisor)}),
                DivModSequenceCost(opcode, tail_dividend, tail_divisor));

    const size_t largest{LargestAffordable([opcode](size_t size) {
        return opcode == OP_DIV ? varops::DivCost(size, size) : varops::ModCost(size, size);
    },
                                           2'000'000)};
    for (size_t size : {largest > 1 ? largest - 1 : largest, largest, largest + 1}) {
        add(PatternBytes(size, "dense"), DivisorTopLimbOne(size),
            FormatBytes(size) + "x" + FormatBytes(size), "largest-normalized");
    }
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "divmod-varops-reject", FormatBytes(largest), "largest-normalized", sequence,
            FixedStack({PatternBytes(largest, "dense"), DivisorTopLimbOne(largest)}),
            VaropsRejection());
}

static uint64_t ShiftSequenceCost(opcodetype opcode, size_t size, uint64_t shift)
{
    const size_t shift_size{Val64(shift).MoveToValtype().size()};
    const uint64_t copy_cost{(size + shift_size) * varops::COST_COPYING};
    const uint64_t prebytes{shift / 8};
    if (opcode == OP_RSHIFT) {
        return copy_cost + varops::LengthConversionCost(shift_size) +
               (prebytes < size ? size - prebytes : 0) * varops::COST_COPYING;
    }
    if (opcode != OP_LSHIFT) throw std::runtime_error("unsupported shift opcode");
    return copy_cost + varops::LengthConversionCost(shift_size) + prebytes * varops::COST_FAST +
           size * varops::COST_COPYING +
           (shift % 8 == 0 ? 0 : varops::UnalignedUpShiftCost(size, prebytes));
}

static void AddShiftCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    std::vector<std::pair<size_t, uint64_t>> shapes{{1, 1}, {17, 9}, {17, 56}, {17, 65}};
    shapes.insert(shapes.end(), {{1024, 8}, {1024, 1032}, {1024, 1033}, {65536, 524288}, {1, uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1} * 8}});
    for (const auto& [size, shift] : shapes) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-preserve", FormatBytes(size) + ":" + strprintf("%ubits", shift),
                shift % 8 == 0 ? "byte-aligned" : "unaligned", sequence,
                FixedStack({PatternBytes(size, "late-nonzero"), Val64(shift).MoveToValtype()}));
    }
    for (uint64_t shift : {8U, 65U}) {
        const auto sequence_cost{[opcode, shift](size_t size) {
            return ShiftSequenceCost(opcode, size, shift);
        }};
        AddCostCrossovers(specs, opcode, "shift-crossover", shift % 8 == 0 ? "byte-aligned" : "unaligned", sequence, 2, 2'000'000, sequence_cost, [=](size_t size) { return FixedStack({PatternBytes(size, "late-nonzero"),
                                                                                                                                                                                        Val64(shift).MoveToValtype()}); }, [=](size_t size) { return FormatBytes(size) + ":" + strprintf("%ubits", shift); });
    }
    constexpr size_t tail_size{2'000'000};
    constexpr uint64_t tail_shift{1};
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-scale-tail", FormatBytes(tail_size) + ":1bit", "unaligned", sequence,
                FixedStack({PatternBytes(tail_size, "late-nonzero"),
                            Val64(tail_shift).MoveToValtype()}),
                ShiftSequenceCost(opcode, tail_size, tail_shift));
    if (opcode == OP_LSHIFT) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-element-reject", "1B:past-4MB", "past-end", Ops({OP_LSHIFT}),
                FixedStack({valtype{1}, Val64(uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE} * 8).MoveToValtype()}),
                FixedCase(SCRIPT_ERR_STACK_ELEMENT_SIZE, 1, 0, "stack-element-limit"));
    }
}

static void AddSignatureCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{opcode == OP_CHECKSIG       ? Ops({OP_2DUP, OP_CHECKSIG, OP_DROP}) :
                           opcode == OP_CHECKSIGVERIFY ? Ops({OP_2DUP, OP_CHECKSIGVERIFY}) :
                                                         Ops({OP_3DUP, OP_CHECKSIGADD, OP_DROP})};
    const auto valid_factory = [opcode](const CryptoFixture& fixture) {
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{fixture.signature, valtype{}, fixture.pubkey_bytes};
        return std::vector<valtype>{fixture.signature, fixture.pubkey_bytes};
    };
    CaseOptions pre_baseline_options{};
    pre_baseline_options.max_repetitions = SIGNATURES_PER_BLOCK;
    pre_baseline_options.saturation_hint = "validation-weight";
    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            "signature-preserve", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", sequence, valid_factory,
            std::move(pre_baseline_options));
    AddCase(specs, opcode, HeadlineRole::COMMON_V2,
            "signature-preserve", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", sequence, valid_factory);

    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            "signature-validation-weight-reject", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", sequence, valid_factory,
            FixedCase(SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, SIGNATURES_PER_BLOCK + 1,
                      std::nullopt, "validation-weight-limit"));

    const auto empty_factory = [opcode](const CryptoFixture& fixture) {
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{valtype{}, PaddedNumber(1, 521), fixture.pubkey_bytes};
        return std::vector<valtype>{valtype{}, fixture.pubkey_bytes};
    };
    const bool empty_verify_failure{opcode == OP_CHECKSIGVERIFY};
    CaseOptions empty_options{empty_verify_failure ? FixedCase(SCRIPT_ERR_CHECKSIGVERIFY, 1, 0, "semantic-failure") : CaseOptions{}};
    AddCase(specs, opcode,
            empty_verify_failure ? HeadlineRole::DIAGNOSTIC : (opcode == OP_CHECKSIGADD ? HeadlineRole::NEW_GSR : HeadlineRole::COMMON_V2),
            "signature-empty", opcode == OP_CHECKSIGADD ? "0B+521B+32B" : "0B+32B",
            "empty-signature", sequence, empty_factory, std::move(empty_options));

    const auto invalid_factory = [opcode](const CryptoFixture& fixture) {
        valtype invalid{fixture.signature};
        invalid.front() ^= 1;
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{invalid, valtype{}, fixture.pubkey_bytes};
        return std::vector<valtype>{invalid, fixture.pubkey_bytes};
    };
    AddCase(specs, opcode, HeadlineRole::DIAGNOSTIC,
            "signature-invalid", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "invalid-fixed-message", sequence, invalid_factory,
            FixedCase(SCRIPT_ERR_SCHNORR_SIG, 1, 0, "semantic-failure"));
}

static uint64_t TimelockSequenceCost(size_t size) { return varops::LengthConversionCost(size); }

static void AddTimelockCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({opcode})};
    for (size_t size : std::array{4U, 5U}) {
        AddPreAndV2Cases(specs, opcode, "timelock-preserve", FormatBytes(size), "padded-one", sequence,
                         FixedStack({PaddedNumber(1, size)}));
    }
    for (size_t size : V2LargeSizes(65536)) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "timelock-preserve", FormatBytes(size), "padded-one", sequence,
                FixedStack({PaddedNumber(1, size)}));
    }
    AddCostCrossovers(specs, opcode, "timelock-crossover", "padded-one", sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TimelockSequenceCost, [](size_t size) { return FixedStack({PaddedNumber(1, size)}); }, FormatBytes);
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "timelock-scale-tail", "4MB", "padded-one", sequence,
                FixedStack({PaddedNumber(1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)}),
                TimelockSequenceCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
}

static CScript RepeatedDupDropBody(size_t body_size)
{
    if (body_size == 0 || body_size % 2 != 0) {
        throw std::runtime_error("function DUP/DROP body size must be positive and even");
    }
    CScript body;
    body.reserve(body_size);
    while (body.size() < body_size)
        body << OP_DUP << OP_DROP;
    return body;
}

static CScript RepeatedSequenceBody(const CScript& sequence, size_t body_size)
{
    if (sequence.empty() || body_size % sequence.size() != 0) {
        throw std::runtime_error("function body size must be a multiple of its sequence size");
    }
    CScript body;
    body.reserve(body_size);
    while (body.size() < body_size) {
        body.insert(body.end(), sequence.begin(), sequence.end());
    }
    return body;
}

static CScript FunctionCalls(const CScript& body, size_t calls)
{
    CScript sequence;
    sequence << OP_MACRO;
    if (body.size() < 253) {
        sequence.push_back(body.size());
    } else if (body.size() <= 0xffff) {
        sequence.push_back(0xfd);
        sequence.push_back(body.size() & 0xff);
        sequence.push_back(body.size() >> 8);
    } else if (body.size() <= 0xffffffffULL) {
        sequence.push_back(0xfe);
        for (unsigned int shift : {0U, 8U, 16U, 24U}) {
            sequence.push_back(body.size() >> shift);
        }
    } else {
        throw std::runtime_error("function benchmark body exceeds CompactSize 32-bit range");
    }
    sequence.insert(sequence.end(), body.begin(), body.end());
    for (size_t call{0}; call < calls; ++call) {
        sequence << OP_CALLMACRO;
        sequence.push_back(0);
    }
    return sequence;
}

static void AddFunctionCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const auto add_with_stack = [&](const CScript& body, size_t calls, std::vector<valtype> stack,
                                    std::string case_label, std::string shape, std::string pattern,
                                    std::string saturation) {
        CScript sequence{FunctionCalls(body, calls)};
        CaseOptions options{FixedCase(SCRIPT_ERR_OK, 1, stack.size(), std::move(saturation))};
        options.sequence_label = strprintf("DEFINE_%uB+%u_CALLS", body.size(), calls);
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, std::move(case_label),
                strprintf("%uB-body/%u-calls/%s", body.size(), calls, std::move(shape)),
                std::move(pattern), std::move(sequence), FixedStack(std::move(stack)), std::move(options));
    };
    const auto add = [&](const CScript& body, size_t calls, size_t item_size,
                         std::string case_label, std::string saturation) {
        add_with_stack(body, calls,
                       {PatternBytes(item_size, item_size == 0 ? "zero" : "one-low")},
                       std::move(case_label), FormatBytes(item_size),
                       item_size == 0 ? "empty-item" : "padded-one", std::move(saturation));
    };

    for (size_t body_size : {2U, 32U, 256U}) {
        const CScript body{RepeatedDupDropBody(body_size)};
        const size_t definition_size{FunctionCalls(body, 0).size()};
        const size_t call_size{2};
        const size_t script_calls{(SCRIPT_BYTES - definition_size - 2) / call_size};
        const size_t body_calls{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / body.size()};
        const size_t calls{std::min(script_calls, body_calls)};
        add(body, calls, 1, "function-dup-drop-body-scaling",
            calls == body_calls ? "function-body-bytes" : "script-bytes");
        if (body_size == 32) {
            add(body, calls, 0, "function-dup-drop-item-scaling", "function-body-bytes");
            add(body, calls, 10, "function-dup-drop-item-scaling", "function-body-bytes");
        }
    }

    CScript push_body;
    push_body << valtype(10, 0x42) << OP_DROP;
    add(push_body, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / push_body.size(), 0,
        "function-push-drop-body", "function-body-bytes");

    constexpr size_t hash_body_size{252};
    for (const opcodetype target : {OP_RIPEMD160, OP_SHA1}) {
        constexpr size_t item_size{519};
        constexpr size_t stack_items{3};
        const CScript hash_sequence{Ops({OP_3DUP, target, OP_DROP, target, OP_DROP, target, OP_DROP})};
        const CScript body{RepeatedSequenceBody(hash_sequence, hash_body_size)};
        const uint64_t hash_sequence_cost{OneToOneSequenceCost(target, item_size, true, "late-nonzero")};
        const uint64_t body_cost{body.size() / hash_sequence.size() * hash_sequence_cost};
        // Cleanup and final truth checks are outside the calls.
        const uint64_t fixed_cost{
            (3 + stack_items + 1) * varops::COST_F +
            varops::COST_PREP_FIXED + varops::COST_PREP_BYTE * 8 +
            varops::COST_READ_FIXED + varops::COST_READ * 8};
        const uint64_t call_cost{
            varops::COST_F + varops::COST_DECODE_FIXED +
            varops::COST_DECODE * hash_body_size + body_cost};
        const uint64_t definition_cost{
            varops::COST_DECODE_FIXED + varops::COST_DECODE * hash_body_size};
        const size_t calls{static_cast<size_t>((TOTAL_VAROPS_BUDGET - fixed_cost - definition_cost) / call_cost)};
        add_with_stack(body, calls,
                       std::vector<valtype>(stack_items, PatternBytes(item_size, "late-nonzero")),
                       "function-slow-" + OpcodeName(target), "3x519B", "late-nonzero",
                       "varops-budget");
    }

    const CScript div_body{RepeatedSequenceBody(Ops({OP_2DUP, OP_DIV, OP_DROP}), 255)};
    add_with_stack(div_body, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / div_body.size(),
                   {PatternBytes(17, "dense"), DivisorTopClear(9)},
                   "function-slow-OP_DIV", "17Bx9B", "normalization-top-clear", "function-body-bytes");

    // Cheap sustaining sequences found by the per-opcode calibration probes.
    // Preserve the initial values without unnecessary per-iteration copies.
    const auto add_probe = [&](std::string label, const CScript& sequence,
                               std::vector<valtype> stack, std::string shape,
                               opcodetype target = OP_INVALIDOPCODE) {
        const CScript body{RepeatedSequenceBody(sequence, (256 / sequence.size()) * sequence.size())};
        size_t calls{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / body.size()};
        if (target == OP_SHA1 || target == OP_RIPEMD160 || target == OP_SHA256 ||
            target == OP_HASH160 || target == OP_HASH256) {
            const size_t digest_size{target == OP_SHA1 || target == OP_RIPEMD160 || target == OP_HASH160 ? 20U : 32U};
            const uint64_t sequence_cost{
                sequence.size() == 1 ? CandidateHashOpcodeCost(target, digest_size) :
                OneToOneSequenceCost(target, digest_size, false, "dense")};
            const uint64_t body_cost{body.size() / sequence.size() * sequence_cost};
            const uint64_t call_cost{
                varops::COST_F + varops::COST_DECODE_FIXED +
                varops::COST_DECODE * body.size() + body_cost};
            calls = std::min(calls, static_cast<size_t>(TOTAL_VAROPS_BUDGET / call_cost));
        }
        add_with_stack(body, calls,
                       std::move(stack), "function-probe-" + label, std::move(shape),
                       "calibration-worst-pattern", "function-body-bytes");
    };
    for (size_t size : {1U, 17U}) {
        add_probe("div-identity", Ops({OP_1, OP_DIV}), {PatternBytes(size, "dense")}, FormatBytes(size));
    }
    add_probe("mul-identity", Ops({OP_1, OP_MUL}), {PatternBytes(9, "dense")}, "9B");
    add_probe("mod-half-divisor", Ops({OP_2DUP, OP_MOD, OP_DROP}),
              {PatternBytes(7, "dense"), DivisorTopClear(3)}, "7Bx3B");
    for (const auto target : {OP_SHA256, OP_SHA1, OP_RIPEMD160, OP_HASH160, OP_HASH256}) {
        const size_t digest_size{target == OP_SHA256 || target == OP_HASH256 ? 32U : 20U};
        add_probe("chain-" + OpcodeName(target), Ops({target}),
                  {PatternBytes(digest_size, "dense")}, FormatBytes(digest_size), target);
        add_probe("tiny-" + OpcodeName(target), Ops({OP_DUP, target, OP_DROP}),
                  {valtype{1}}, "1B", target);
    }
    for (const auto target : {OP_NUMEQUALVERIFY, OP_EQUALVERIFY}) {
        add_probe(OpcodeName(target), Ops({OP_2DUP, target}),
                  {PatternBytes(17, "dense"), PatternBytes(17, "dense")}, "17Bx17B");
    }
    for (const auto target : {OP_BOOLAND, OP_BOOLOR}) {
        add_probe(OpcodeName(target), Ops({OP_2DUP, target, OP_DROP}),
                  {PaddedNumber(1, 17), PaddedNumber(1, 17)}, "17Bx17B");
    }
    add_probe("within", Ops({OP_3DUP, OP_WITHIN, OP_DROP}),
              std::vector<valtype>(3, PatternBytes(55, "dense")), "55Bx55Bx55B");
    for (const size_t body_size : {0U, 1U}) {
        CScript body;
        body.insert(body.end(), body_size, OP_NOP);
        add_with_stack(body, 65'536, {}, "function-probe-call-overhead",
                       "no-operands", "empty-or-nop", "invocation-overhead");
    }
    for (const size_t literal_size : {4096U, 65536U}) {
        CScript body;
        body << valtype(literal_size, 0x42) << OP_DROP;
        add_with_stack(body, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / body.size(), {},
                       "function-probe-large-literal", FormatBytes(literal_size),
                       "repeated-push-copy", "function-body-bytes");
    }

}
static void AddControlAndFloorCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const auto forced_push = [](opcodetype push_opcode, size_t size) {
        CScript sequence;
        sequence.push_back(static_cast<unsigned char>(push_opcode));
        if (push_opcode == OP_PUSHDATA1) {
            sequence.push_back(static_cast<unsigned char>(size));
        } else if (push_opcode == OP_PUSHDATA2) {
            sequence.push_back(static_cast<unsigned char>(size & 0xff));
            sequence.push_back(static_cast<unsigned char>((size >> 8) & 0xff));
        } else {
            for (unsigned int shift : {0U, 8U, 16U, 24U}) {
                sequence.push_back(static_cast<unsigned char>((size >> shift) & 0xff));
            }
        }
        sequence.insert(sequence.end(), size, 0x42);
        sequence << OP_DROP;
        return sequence;
    };

    switch (opcode) {
    case OP_NOP:
    case OP_CODESEPARATOR:
        AddPreAndV2Cases(specs, opcode, "interpreter-floor", "no-operands", "executed", Ops({opcode}), FixedStack({}));
        if (opcode == OP_NOP) {
            AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "max-initial-stack", "1000-items", "empty-items", Ops({OP_NOP}),
                    FixedStack(std::vector<valtype>(MAX_STACK_SIZE, valtype{})));
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "max-initial-stack", "32768-items", "empty-items", Ops({OP_NOP}),
                    FixedStack(std::vector<valtype>(MAX_TAPSCRIPT_V2_STACK_SIZE, valtype{})));
        }
        break;
    case OP_0:
        AddPreAndV2Cases(specs, opcode, "push-drop", "0B", "push-parse", Ops({OP_0, OP_DROP}), FixedStack({}));
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "push-stack-reject", "1001-pushes", "empty-items", Ops({OP_0}), FixedStack({}),
                FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_STACK_SIZE + 1, 0, "stack-count-limit"));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "push-stack-reject", "32769-pushes", "empty-items", Ops({OP_0}), FixedStack({}),
                FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_TAPSCRIPT_V2_STACK_SIZE + 1, 0, "stack-count-limit"));
        break;
    case OP_PUSHDATA1:
        AddPreAndV2Cases(specs, opcode, "pushdata1-drop", "76B", "forced-push-encoding",
                         forced_push(OP_PUSHDATA1, 76), FixedStack({}));
        break;
    case OP_PUSHDATA2:
        AddPreAndV2Cases(specs, opcode, "pushdata2-drop", "520B", "forced-push-encoding",
                         forced_push(OP_PUSHDATA2, 520), FixedStack({}));
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "pushdata2-element-reject", "521B", "forced-push-encoding",
                forced_push(OP_PUSHDATA2, 521), FixedStack({}),
                FixedCase(SCRIPT_ERR_PUSH_SIZE, 1, 0, "push-element-limit"));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata2-drop", "521B", "forced-push-encoding",
                forced_push(OP_PUSHDATA2, 521), FixedStack({}));
        break;
    case OP_PUSHDATA4:
        AddPreAndV2Cases(specs, opcode, "pushdata4-drop", "1B", "forced-nonminimal-encoding",
                         forced_push(OP_PUSHDATA4, 1), FixedStack({}));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata4-drop", "64KB", "forced-push-encoding",
                         forced_push(OP_PUSHDATA4, 65536), FixedStack({}));
        // Leave room for PUSHDATA4's five-byte prefix, DROP and the final OP_1.
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata4-drop", FormatBytes(SCRIPT_BYTES - 7), "maximum-script-literal",
                forced_push(OP_PUSHDATA4, SCRIPT_BYTES - 7), FixedStack({}));
        break;
    case OP_VERIFY: {
        AddPreAndV2Cases(specs, opcode, "true-verify", "1B", "true", Ops({OP_1, OP_VERIFY}), FixedStack({}));
        const CScript sequence{Ops({OP_DUP, OP_VERIFY})};
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "verify-preserve", "520B", "late-nonzero", sequence,
                FixedStack({PatternBytes(520, "late-nonzero")}));
        AddCostCase(specs, opcode, HeadlineRole::COMMON_V2,
                    "verify-preserve", "520B", "late-nonzero", sequence,
                    FixedStack({PatternBytes(520, "late-nonzero")}), TruthCopyCost(520));
        AddCostCrossovers(specs, opcode, "verify-crossover", "late-nonzero", sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TruthCopyCost, [](size_t size) { return FixedStack({PatternBytes(size, "late-nonzero")}); }, FormatBytes);
        AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "verify-scale-tail", "4MB", "late-nonzero", sequence,
                    FixedStack({PatternBytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero")}),
                    TruthCopyCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
        break;
    }
    case OP_IF:
        AddPreAndV2Cases(specs, opcode, "executed-if", "1B", "true-branch", Ops({OP_1, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        AddPreAndV2Cases(specs, opcode, "skipped-if", "0B", "false-branch", Ops({OP_0, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        break;
    default: throw std::runtime_error("unhandled control opcode registry entry");
    }
}

static void AddSizeCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_SIZE, OP_DROP})};
    for (size_t size : PreDataSizes()) {
        AddPreAndV2Cases(specs, opcode, "size-preserve", FormatBytes(size), "late-nonzero", sequence,
                         FixedStack({PatternBytes(size, "late-nonzero")}));
    }
    for (size_t size : V2LargeSizes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "size-preserve", FormatBytes(size), "late-nonzero", sequence,
                FixedStack({PatternBytes(size, "late-nonzero")}));
    }
}

static uint64_t WithinSequenceCost(size_t size) { return 3 * size * varops::COST_COPYING + varops::WithinCost(size, size, size); }

static void AddWithinCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_3DUP, OP_WITHIN, OP_DROP})};
    AddPreAndV2Cases(specs, opcode, "within-preserve", "4Bx4Bx4B", "inside-range", sequence,
                     FixedStack({PaddedNumber(2, 4), PaddedNumber(1, 4), PaddedNumber(3, 4)}));
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "within-preserve", "521Bx521Bx521B", "inside-range-padded", sequence,
            FixedStack({PaddedNumber(2, 521), PaddedNumber(1, 521), PaddedNumber(3, 521)}));
    AddCostCrossovers(specs, opcode, "within-crossover", "inside-range-padded", sequence, 3, MAX_THREE_WAY_ELEMENT_SIZE, WithinSequenceCost, [](size_t size) { return FixedStack({PaddedNumber(2, size), PaddedNumber(1, size),
                                                                                                                                                                                  PaddedNumber(3, size)}); }, [](size_t size) { return FormatBytes(size) + "x" + FormatBytes(size) + "x" + FormatBytes(size); });
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "within-scale-tail",
                FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE) + "x" +
                    FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE) + "x" +
                    FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE),
                "inside-range-padded", sequence,
                FixedStack({PaddedNumber(2, MAX_THREE_WAY_ELEMENT_SIZE),
                            PaddedNumber(1, MAX_THREE_WAY_ELEMENT_SIZE),
                            PaddedNumber(3, MAX_THREE_WAY_ELEMENT_SIZE)}),
                WithinSequenceCost(MAX_THREE_WAY_ELEMENT_SIZE));
}

using CaseGenerator = void (*)(std::vector<CaseSpec>&, opcodetype);

struct OpcodeEntry {
    opcodetype opcode;
    CaseGenerator generate;
};

static const std::vector<OpcodeEntry>& OpcodeRegistry()
{
    static const std::vector<OpcodeEntry> registry{[] {
        std::vector<OpcodeEntry> entries;
        const auto add = [&](CaseGenerator generate, std::initializer_list<opcodetype> opcodes) {
            for (opcodetype opcode : opcodes)
                entries.push_back({opcode, generate});
        };
        const CaseGenerator unary_common{[](auto& out, auto op) { AddUnaryDataCases(out, op, false); }};
        const CaseGenerator unary_restored{[](auto& out, auto op) { AddUnaryDataCases(out, op, true); }};
        const CaseGenerator binary_common{[](auto& out, auto op) { AddBinaryDataCases(out, op, false); }};
        const CaseGenerator binary_restored{[](auto& out, auto op) { AddBinaryDataCases(out, op, true); }};

        add(AddControlAndFloorCases, {OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_IF, OP_VERIFY, OP_NOP, OP_CODESEPARATOR});
        add(AddFunctionCases, {OP_MACRO});
        add(AddStackOpcodeCases, {OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP,
                                  OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK});
        add(unary_common, {OP_1ADD, OP_1SUB, OP_NOT, OP_0NOTEQUAL});
        add(unary_restored, {OP_INVERT, OP_2MUL, OP_2DIV});
        add(binary_common, {OP_EQUAL, OP_EQUALVERIFY, OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
                            OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
                            OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX});
        add(binary_restored, {OP_AND, OP_OR, OP_XOR});
        add(AddHashCases, {OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256});
        add(AddOpTxCases, {OP_TX});
        add(AddSpliceCases, {OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT});
        add(AddMulCases, {OP_MUL});
        add(AddDivModCases, {OP_DIV, OP_MOD});
        add(AddShiftCases, {OP_LSHIFT, OP_RSHIFT});
        add(AddSizeCases, {OP_SIZE});
        add(AddWithinCases, {OP_WITHIN});
        add(AddSignatureCases, {OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD});
        add(AddTimelockCases, {OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY});
        return entries;
    }()};
    return registry;
}

static std::map<std::string, opcodetype> SupportedOpcodeMap()
{
    std::map<std::string, opcodetype> out;
    for (const OpcodeEntry& entry : OpcodeRegistry())
        out.emplace(OpcodeName(entry.opcode), entry.opcode);
    return out;
}

static std::pair<std::string, std::string> BaselineFormula(opcodetype opcode)
{
    if (opcode >= OP_0 && opcode <= OP_PUSHDATA4) return {"F + COPY(n)", "F,COPY.fixed,COPY.byte"};
    switch (opcode) {
    case OP_NOP: case OP_IF: case OP_CODESEPARATOR:
        return {"F", "F"};
    case OP_TOALTSTACK: case OP_FROMALTSTACK:
        return {"F + MOVE(1)", "F,MOVE.fixed,MOVE.entry"};
    case OP_SWAP:
        return {"F + MOVE(2)", "F,MOVE.fixed,MOVE.entry"};
    case OP_ROT:
        return {"F + MOVE(3)", "F,MOVE.fixed,MOVE.entry"};
    case OP_2SWAP:
        return {"F + MOVE(4)", "F,MOVE.fixed,MOVE.entry"};
    case OP_2ROT:
        return {"F + MOVE(6)", "F,MOVE.fixed,MOVE.entry"};
    case OP_DROP: return {"F + RELEASE(W(x))", "F,RELEASE.fixed,RELEASE.byte"};
    case OP_2DROP: return {"F + RELEASE(W(x1)) + RELEASE(W(x2))", "F,RELEASE.fixed,RELEASE.byte"};
    case OP_NIP: return {"F + RELEASE(W(x1))", "F,RELEASE.fixed,RELEASE.byte"};
    case OP_VERIFY: return {"F + PREP(n) + READ(W(n))", "F,PREP.fixed,PREP.byte,READ"};
    case OP_DUP: case OP_2DUP: case OP_3DUP: case OP_OVER: case OP_2OVER: case OP_TUCK:
        return {"F + sum(COPY(n_i))", "F,COPY.fixed,COPY.byte"};
    case OP_IFDUP:
        return {"F + PREP(n) + READ(W(n)) + OUTPUT(n) + optional COPY(n)",
            "F,PREP.fixed,PREP.byte,READ,OUTPUT.fixed,OUTPUT.byte,COPY.fixed,COPY.byte"};
    case OP_DEPTH: case OP_SIZE: return {"F + OUTPUT(8)", "F,OUTPUT(8)"};
    case OP_PICK: return {"F + PREP(depth) + READ(W(depth)) + COPY(n)", "F,PREP.fixed,PREP.byte,READ,COPY.fixed,COPY.byte"};
    case OP_ROLL: return {"F + PREP(depth) + READ(W(depth)) + MOVE(entries)", "F,PREP.fixed,PREP.byte,READ,MOVE"};
    case OP_EQUAL: case OP_EQUALVERIFY:
        return {"F + conditional READ(W(n)) + OUTPUT(8)", "F,READ,OUTPUT(8)"};
    case OP_NOT: case OP_0NOTEQUAL:
        return {"F + PREP(n) + READ(W(n)) + OUTPUT(8)", "F,PREP.fixed,PREP.byte,READ,OUTPUT(8)"};
    case OP_1ADD: case OP_1SUB: case OP_ADD: case OP_SUB:
        return {"F + PREP(operands) + ARITH(W) + OUTPUT(out)",
            "F,PREP.fixed,PREP.byte,ARITH.fixed,ARITH.byte,OUTPUT.fixed,OUTPUT.byte"};
    case OP_BOOLAND: case OP_BOOLOR: case OP_NUMEQUAL: case OP_NUMEQUALVERIFY:
    case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN:
    case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_WITHIN:
        return {"F + PREP(operands) + READ(comparisons) + OUTPUT(8)", "F,PREP.fixed,PREP.byte,READ,OUTPUT(8)"};
    case OP_MIN: case OP_MAX:
        return {"F + PREP(operands) + READ(W) + OUTPUT(out) + RELEASE(max input)",
            "F,PREP.fixed,PREP.byte,READ,OUTPUT.fixed,OUTPUT.byte,RELEASE.fixed,RELEASE.byte"};
    case OP_INVERT: case OP_2MUL: case OP_2DIV: case OP_AND: case OP_OR: case OP_XOR:
    case OP_LSHIFT: case OP_RSHIFT: case OP_BYTEREV:
        return {"F + PREP(operands) + BIT(bytes) + OUTPUT(out)",
            "F,PREP.fixed,PREP.byte,READ,BIT,OUTPUT.fixed,OUTPUT.byte"};
        case OP_MUL: return {"F + PREP(a,b) + u*(MULROW(v) + ARITH(8*(v+1))) + OUTPUT(out)", "F,PREP.fixed,PREP.byte,MULROW,ARITH.fixed,ARITH.byte,OUTPUT.fixed,OUTPUT.byte"};
        case OP_DIV: case OP_MOD: return {"F + PREP(a,b) + DIVCORE(s,v) + OUTPUT(out) + RELEASE(max input)", "F,PREP.fixed,PREP.byte,DIVCORE.fixed,DIVCORE.cell,OUTPUT.fixed,OUTPUT.byte,RELEASE.fixed,RELEASE.byte"};
    case OP_CAT: return {"F + COPY(a+b)", "F,COPY.fixed,COPY.byte"};
    case OP_SUBSTR:
        return {"F + PREP(indices) + READ(indices) + COPY(out) + RELEASE(W(source), W(indices))",
                "F,PREP.fixed,PREP.byte,READ,COPY.fixed,COPY.byte,RELEASE.fixed,RELEASE.byte"};
    case OP_LEFT: return {"F + PREP(index) + READ(W(index))", "F,PREP.fixed,PREP.byte,READ"};
    case OP_RIGHT: return {"F + PREP(index) + READ(W(index)) + COPY.byte*offset", "F,PREP.fixed,PREP.byte,READ,COPY.byte"};
    case OP_SHA1:
        return {"F + H1(n) + COPY(digest)", "F,H1.fixed,H1.byte,COPY.fixed,COPY.byte"};
    case OP_RIPEMD160:
        return {"F + H160(n) + COPY(digest)", "F,H160.fixed,H160.byte,COPY.fixed,COPY.byte"};
    case OP_SHA256:
        return {"F + H256(n) + COPY(digest)", "F,H256.fixed,H256.byte,COPY.fixed,COPY.byte"};
    case OP_HASH160:
        return {"F + H256(n) + H160(32) + COPY(digest)", "F,H256.fixed,H256.byte,H160.fixed,H160.byte,COPY.fixed,COPY.byte"};
    case OP_HASH256:
        return {"F + H256(n) + H256(32) + COPY(digest)", "F,H256.fixed,H256.byte (n),H256.fixed,H256.byte (32),COPY.fixed,COPY.byte"};
    case OP_CHECKSIG: case OP_CHECKSIGVERIFY: case OP_CHECKSIGADD:
        return {"F + optional H256 + SIG + result work", "F,H256.fixed,H256.byte,SIG,OUTPUT(8),PREP.fixed,PREP.byte,ARITH.fixed,ARITH.byte,OUTPUT.fixed,OUTPUT.byte,COPY.fixed,COPY.byte"};
    case OP_CHECKLOCKTIMEVERIFY: case OP_CHECKSEQUENCEVERIFY:
        return {"F + PREP(n) + READ(W(n)) + OUTPUT(n)", "F,PREP.fixed,PREP.byte,READ,OUTPUT.fixed,OUTPUT.byte"};
    case OP_TX:
        return {"F + SELECT(selected records/items) + COPY.byte*returned_bytes",
                "F,SELECT.fixed,SELECT.item,COPY.byte"};
    case OP_MACRO: return {"DECODE(body bytes) once; CALLMACRO: F + DECODE(body bytes)", "F,DECODE"};
    default: return {"unwired", ""};
    }
}

static std::pair<std::string, std::string> CandidateFormula(opcodetype opcode)
{
    if constexpr (!varops::PRODUCER_LIFETIME_EXPERIMENT) return BaselineFormula(opcode);
    // NUMERIC_RESULT(n) = PRODUCE(W(n)) + NORMALIZE(n). Initial witness
    // production is charged once per script, not again in each opcode formula.
    switch (opcode) {
    case OP_DROP: case OP_2DROP: case OP_NIP: return {"F", "F"};
    case OP_BYTEREV: return {"F + BIT(n)", "F,BIT"};
    case OP_MIN: case OP_MAX:
        return {"F + PREP(operands) + READ(W) + NUMERIC_RESULT(out)", "F,PREP,READ,PRODUCE,NORMALIZE"};
    case OP_DIV: case OP_MOD:
        return {"F + PREP(a,b) + DIVCORE(s,v) + NUMERIC_RESULT(out)", "F,PREP,DIVCORE,PRODUCE,NORMALIZE"};
    case OP_MUL:
        return {"F + PREP(a,b) + PRODUCE(8*(u+v)) + PREP(8*(u+v)) + PRODUCE(8*(v+1)) + u*(MULROW(v) + ARITH(8*(v+1))) + NORMALIZE(out)",
                "F,PREP,PRODUCE,MULROW,ARITH,NORMALIZE"};
    case OP_SUBSTR:
        return {"F + PREP(indices) + READ(indices) + PRODUCE(out)", "F,PREP,READ,PRODUCE"};
    case OP_LSHIFT: case OP_RSHIFT:
        return {"F + PREP(operands) + READ(shift) + BIT(W(input)) + NUMERIC_RESULT(out)", "F,PREP,READ,BIT,PRODUCE,NORMALIZE"};
    case OP_TX: case OP_MACRO:
        return {"postponed extension; excluded from frozen calibration", "postponed"};
    default: break;
    }
    auto result{BaselineFormula(opcode)};
    for (std::string* text : {&result.first, &result.second}) {
        for (const auto& [from, to] : {std::pair{std::string{"COPY"}, std::string{"PRODUCE"}},
                                      std::pair{std::string{"OUTPUT"}, std::string{"NUMERIC_RESULT"}}}) {
            size_t pos{0};
            while ((pos = text->find(from, pos)) != std::string::npos) {
                text->replace(pos, from.size(), to);
                pos += to.size();
            }
        }
    }
    return result;
}

struct ParityCoverage {
    size_t successful_cases{0};
    size_t static_formula_cases{0};
};

static void WriteCoverageManifest(
    const std::string& path,
    const std::map<opcodetype, ParityCoverage>& parity)
{
    std::ofstream out{path};
    if (!out) throw std::runtime_error("cannot open coverage manifest: " + path);
    const auto quote = [](std::string_view value) {
        std::string escaped{"\""};
        for (const char c : value) {
            if (c == '"') escaped += '"';
            escaped += c;
        }
        return escaped + '"';
    };
    out << "opcode,candidate formula,coefficients used,parity-test status\n";
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        const auto [formula, coefficients]{CandidateFormula(entry.opcode)};
        const auto found{parity.find(entry.opcode)};
        const ParityCoverage coverage{found == parity.end() ? ParityCoverage{} : found->second};
        const std::string status{
            formula == "unwired" ? "unwired" :
            coverage.successful_cases != 0 && coverage.static_formula_cases == coverage.successful_cases ?
                strprintf("independent formula parity exact (%u/%u successful cases)",
                          coverage.static_formula_cases, coverage.successful_cases) :
                strprintf("independent formula parity incomplete (%u/%u successful cases)",
                          coverage.static_formula_cases, coverage.successful_cases)};
        out << quote(OpcodeName(entry.opcode)) << ',' << quote(formula) << ',' << quote(coefficients) << ','
            << quote(status) << '\n';
    }
}

static std::vector<CaseSpec> GenerateCaseSpecs(const Options& options)
{
    std::vector<CaseSpec> specs;
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        const opcodetype opcode{entry.opcode};
        if (options.exclude_experimental && (opcode == OP_TX || opcode == OP_MACRO)) continue;
        if (!options.selected_opcodes.empty() && !options.selected_opcodes.contains(opcode)) continue;
        entry.generate(specs, opcode);
    }

    if (options.selected_opcodes.empty() || options.selected_opcodes.contains(OP_DUP)) {
        AddCase(specs, OP_DUP, HeadlineRole::PRE_BASELINE,
                "empty-dup-stack-reject", "1001-items", "empty-items", Ops({OP_DUP}),
                FixedStack({valtype{}}), FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_STACK_SIZE, 0, "stack-count-limit"));
        AddCase(specs, OP_DUP, HeadlineRole::NEW_GSR,
                "empty-dup-stack-reject", "32769-items", "empty-items", Ops({OP_DUP}),
                FixedStack({valtype{}}),
                FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_TAPSCRIPT_V2_STACK_SIZE, 0, "stack-count-limit"));
        AddCase(specs, OP_DUP, HeadlineRole::NEW_GSR,
                "total-stack-reject", "4MB-item", "dense", Ops({OP_DUP, OP_DUP}),
                FixedStack({PatternBytes(4'000'000, "dense")}),
                FixedCase(SCRIPT_ERR_TOTAL_STACK_SIZE, 1, 0, "total-stack-limit"));
    }

    // A short successful run can be extrapolated; a one-shot boundary or a
    // rejection path cannot. Keep those cases in the full-budget protocol.
    if (options.sample_budget_percent != 100) {
        std::erase_if(specs, [](const CaseSpec& spec) {
            return spec.expected_error != SCRIPT_ERR_OK || spec.repeat_mode != RepeatMode::MAX_SUCCESS;
        });
    }

    if (!options.case_filter.empty()) {
        if (std::ranges::none_of(specs, [&](const CaseSpec& spec) {
                return spec.role != HeadlineRole::PRE_BASELINE &&
                       spec.name.find(options.case_filter) != std::string::npos;
            })) {
            throw std::runtime_error("case filter matched no non-baseline case");
        }
        std::erase_if(specs, [&](const CaseSpec& spec) {
            return spec.role != HeadlineRole::PRE_BASELINE &&
                   spec.name.find(options.case_filter) == std::string::npos;
        });
    }
    std::sort(specs.begin(), specs.end(), [](const CaseSpec& left, const CaseSpec& right) { return left.name < right.name; });
    const std::vector<CaseSpec>::iterator duplicate{std::adjacent_find(specs.begin(), specs.end(), [](const CaseSpec& left, const CaseSpec& right) {
        return left.name == right.name;
    })};
    if (duplicate != specs.end()) throw std::runtime_error("duplicate generated case name: " + duplicate->name);
    return specs;
}

static ankerl::nanobench::Bench SetupBenchmark()
{
    ankerl::nanobench::Bench bench;
    bench.output(nullptr).epochs(1).epochIterations(1);
    return bench;
}

static std::string_view TimingStageName(TimingStage stage)
{
    switch (stage) {
    case TimingStage::SCHNORR_BASELINE: return "schnorr-baseline";
    case TimingStage::STABLE: return "stable";
    }
    return "unknown";
}

static std::string_view MeasurementModeName(MeasurementMode mode)
{
    switch (mode) {
    case MeasurementMode::REALISTIC: return "realistic";
    case MeasurementMode::FULL_VAROPS: return "full-varops";
    }
    return "unknown";
}

static SampleStats CalculateStats(std::vector<double> values)
{
    if (values.empty()) throw std::runtime_error("cannot aggregate an empty sample set");
    std::sort(values.begin(), values.end());
    const size_t middle{values.size() / 2};
    const double median{values.size() % 2 == 0 ? (values[middle - 1] + values[middle]) / 2 : values[middle]};
    std::vector<double> errors;
    errors.reserve(values.size());
    for (double value : values) {
        if (value == 0) {
            errors.push_back(median == 0 ? 0 : std::numeric_limits<double>::infinity());
        } else {
            errors.push_back(std::abs((value - median) / value));
        }
    }
    std::sort(errors.begin(), errors.end());
    const size_t error_middle{errors.size() / 2};
    const double mdape{errors.size() % 2 == 0 ? (errors[error_middle - 1] + errors[error_middle]) / 2 : errors[error_middle]};
    return {median, values.front(), values.back(), mdape};
}

static void AggregateSamples(BenchResult& result, TimingStage stage, MeasurementMode mode)
{
    std::vector<double> values;
    for (const TimingSample& sample : result.samples) {
        if (sample.stage == stage && sample.mode == mode) values.push_back(sample.wall_sec);
    }
    const SampleStats stats{CalculateStats(std::move(values))};
    if (mode == MeasurementMode::REALISTIC) {
        result.median_sec = stats.median;
        result.wall_min_sec = stats.minimum;
        result.wall_max_sec = stats.maximum;
        result.mdape = stats.mdape;
        result.aggregate_stage = stage;
        return;
    }
    result.full_varops.median_sec = stats.median;
    result.full_varops.wall_min_sec = stats.minimum;
    result.full_varops.wall_max_sec = stats.maximum;
    result.full_varops.mdape = stats.mdape;
    result.full_varops.aggregate_stage = stage;
}

static void RunGlobalWarmup(const CryptoFixture& fixture)
{
    const CScript warmup_script{BuildScript(Ops({OP_NOP}), 1, 0)};
    ValtypeStack warmup_stack;
    BenchSignatureChecker checker{fixture};
    ScriptExecutionData execdata;
    varops::Budget budget{TOTAL_VAROPS_BUDGET};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    if (!EvalTapscriptV2(warmup_stack, warmup_script, BENCH_SCRIPT_VERIFY_FLAGS,
                         checker, execdata, budget, &error)) {
        throw std::runtime_error("global benchmark warmup failed: " + ScriptErrorString(error));
    }
}

static BenchResult ResultMetadata(const MaterializedCase& test_case)
{
    const CaseSpec& spec{*test_case.spec};
    BenchResult result;
    result.name = spec.name;
    result.domain = DomainFor(spec.role);
    result.role = spec.role;
    result.new_in_v2 = spec.new_in_v2;
    result.opcode_name = spec.opcode_name;
    result.sequence_opcodes = spec.sequence_opcodes;
    result.operand_shape = spec.operand_shape;
    result.operand_pattern = spec.operand_pattern;
    result.script_bytes = test_case.script.size();
    result.initial_stack_items = test_case.initial_stack.size();
    result.initial_stack_bytes = StackPayloadBytes(test_case.initial_stack);
    result.expected_error = spec.expected_error;
    result.actual_error = SCRIPT_ERR_UNKNOWN_ERROR;
    result.saturation = test_case.saturation;
    result.repetitions = test_case.repetitions;
    result.varops_per_repeat = test_case.varops_per_repeat;
    return result;
}

static void CheckDeclaredOutcome(const MaterializedCase& test_case, const EvalOutcome& outcome,
                                 std::string_view stage)
{
    if (outcome.error != test_case.spec->expected_error || outcome.success != (test_case.spec->expected_error == SCRIPT_ERR_OK)) {
        throw std::runtime_error(strprintf("%s mismatch for %s: expected %s, got %s",
                                           stage, test_case.spec->name,
                                           ScriptErrorString(test_case.spec->expected_error),
                                           ScriptErrorString(outcome.error)));
    }
}

static void CheckScriptSize(const MaterializedCase& test_case)
{
    if (test_case.script.size() > SCRIPT_BYTES) {
        throw std::runtime_error(test_case.spec->name + " exceeds the script size limit");
    }
}

static void CheckMeasuredOutcome(const MaterializedCase& test_case, const EvalOutcome& expected,
                                 const EvalOutcome& actual, std::string_view stage)
{
    if (actual.error != expected.error || actual.success != expected.success ||
        actual.varops_consumed != expected.varops_consumed) {
        throw std::runtime_error(strprintf("%s changed outcome during %s", test_case.spec->name, stage));
    }
}

static TimingSample MeasurePrepared(const MaterializedCase& test_case, const CryptoFixture& fixture,
                                    PreparedExecution& execution, const EvalOutcome& expected,
                                    TimingStage stage, int round, size_t order)
{
    BenchSignatureChecker checker{fixture, test_case.transaction.get()};
    ankerl::nanobench::Bench bench{SetupBenchmark()};
    EvalOutcome outcome;
    size_t executions{0};
    bench.run(test_case.spec->name, [&] {
        ++executions;
        outcome = ExecutePrepared(test_case, checker, execution);
    });
    if (executions != 1 || bench.results().size() != 1 || bench.results().front().size() != 1) {
        throw std::runtime_error("nanobench did not execute exactly one case sample");
    }
    CheckMeasuredOutcome(test_case, expected, outcome, TimingStageName(stage));
    return {MeasurementMode::REALISTIC, stage, round, order,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed)};
}

static bool ConfigureFullVaropsExtrapolation(const MaterializedCase& test_case,
                                             const EvalOutcome& expected,
                                             FullVaropsResult& result)
{
    if (DomainFor(test_case.spec->role) != ExecutionDomain::GSR_TAPSCRIPT_V2) {
        result.status = "not-v2";
        return false;
    }
    if (!expected.success) {
        result.status = "non-success";
        return false;
    }
    if (test_case.saturation == "transaction-weight") {
        result.status = "transaction-weight-limited";
        return false;
    }
    if (expected.varops_consumed == 0) {
        result.status = "zero-varops";
        return false;
    }
    const uint64_t initial_cost{InitialProducerCost(test_case.initial_stack)};
    if (expected.varops_consumed <= initial_cost ||
        expected.varops_consumed - initial_cost < MIN_FULL_VAROPS_SAMPLE_BUDGET) {
        result.status = "insufficient-sample";
        return false;
    }

    result.status = "extrapolated";
    result.script_bytes = test_case.script.size();
    result.script_executions = 1;
    result.measured_varops = expected.varops_consumed;
    // Initial ownership is funded once, not on every compressed repetition.
    // Keeping interpreter-entry and cleanup-opcode time in the numerator is conservative.
    result.scale = static_cast<double>(TOTAL_VAROPS_BUDGET - initial_cost) /
                   (result.measured_varops - initial_cost);
    return true;
}

static TimingSample ExtrapolateFullVaropsSample(const TimingSample& realistic,
                                                const FullVaropsResult& plan)
{
    if (plan.status != "extrapolated" || plan.measured_varops == 0) {
        throw std::runtime_error("invalid full-varops extrapolation plan");
    }
    return {MeasurementMode::FULL_VAROPS, realistic.stage, realistic.round,
            realistic.order, realistic.wall_sec * plan.scale};
}

static CaseSample RunTimedCaseSample(const MaterializedCase& test_case, const CryptoFixture& fixture,
                                     const std::optional<EvalOutcome>& expected, int round,
                                     size_t order, uint64_t budget_ceiling)
{
    CheckScriptSize(test_case);
    const uint64_t fixture_bytes{StackFixtureBytes(test_case.initial_stack)};
    if (fixture_bytes > MAX_FIXTURE_POOL_BYTES / 2) {
        throw std::runtime_error(strprintf("%s sample fixtures would require %u bytes (limit %u)",
                                           test_case.spec->name, fixture_bytes * 2,
                                           MAX_FIXTURE_POOL_BYTES));
    }

    ReleaseAllocatorCaches();
    PreparedExecution warmup_execution{PrepareExecution(test_case, true, budget_ceiling)};
    PreparedExecution measured_execution{PrepareExecution(test_case, true, budget_ceiling)};
    BenchSignatureChecker checker{fixture, test_case.transaction.get()};
    std::optional<uint64_t> executed_opcodes;
    EvalOutcome warmup_outcome;
    if (budget_ceiling != TOTAL_VAROPS_BUDGET &&
        DomainFor(test_case.spec->role) == ExecutionDomain::GSR_TAPSCRIPT_V2 && !expected) {
        ExecutedOpcodeCounter counter;
        varops::ScopedCostAudit audit_scope{&counter};
        warmup_outcome = ExecutePrepared(test_case, checker, warmup_execution);
        executed_opcodes = counter.count;
    } else {
        warmup_outcome = ExecutePrepared(test_case, checker, warmup_execution);
    }
    CheckDeclaredOutcome(test_case, warmup_outcome, "warmup");
    if (expected) CheckMeasuredOutcome(test_case, *expected, warmup_outcome, "warmup");
    TimingSample sample{MeasurePrepared(test_case, fixture, measured_execution, warmup_outcome,
                                        TimingStage::STABLE, round, order)};
    ReleaseAllocatorCaches();
    return {warmup_outcome, std::move(sample), executed_opcodes};
}

static TimingSample MeasureSchnorrBatch(const CryptoFixture& fixture, TimingStage stage,
                                        int round, size_t order, uint64_t iterations)
{
    ankerl::nanobench::Bench bench{SetupBenchmark()};
    uint64_t valid{0};
    size_t executions{0};
    bench.run("Schnorr signature validation", [&] {
        ++executions;
        for (uint64_t i{0}; i < iterations; ++i) {
            valid += fixture.pubkey.VerifySchnorr(fixture.message, fixture.signature);
        }
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
    if (executions != 1 || valid != iterations || bench.results().size() != 1 ||
        bench.results().front().size() != 1) {
        throw std::runtime_error("raw Schnorr anchor failed");
    }
    const double scale{static_cast<double>(SIGNATURES_PER_BLOCK) / iterations};
    return {MeasurementMode::REALISTIC, stage, round, order,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed) * scale};
}

static BenchResult RunRawSchnorr(const CryptoFixture& fixture)
{
    BenchResult result;
    result.name = "Schnorr signature validation";
    result.domain = ExecutionDomain::RAW_SCHNORR;
    result.role = HeadlineRole::PRE_BASELINE;
    result.opcode_name = "RAW_SCHNORR_80000";
    result.sequence_opcodes = "RAW_SCHNORR_VERIFY";
    result.operand_shape = "64B+32B";
    result.operand_pattern = "valid-fixed-message";
    result.expected_error = SCRIPT_ERR_OK;
    result.actual_error = SCRIPT_ERR_OK;
    result.saturation = "80000-signature-anchor";
    result.full_varops.status = "reference";
    constexpr uint64_t iterations{1000};
    MeasureSchnorrBatch(fixture, TimingStage::SCHNORR_BASELINE, 0, 0, iterations);
    for (int sample{1}; sample <= SCHNORR_BASELINE_SAMPLES; ++sample) {
        result.samples.push_back(MeasureSchnorrBatch(fixture, TimingStage::SCHNORR_BASELINE,
                                                     sample, sample - 1, iterations));
    }
    AggregateSamples(result, TimingStage::SCHNORR_BASELINE, MeasurementMode::REALISTIC);
    result.repetitions = SIGNATURES_PER_BLOCK;
    return result;
}

static double WorstCaseSeconds(const BenchResult& result)
{
    return std::max(result.median_sec, result.full_varops.median_sec);
}

static std::vector<const BenchResult*> TopWorstNewV2Cases(const std::vector<BenchResult>& results)
{
    std::vector<const BenchResult*> ranked;
    for (const BenchResult& result : results) {
        if (result.new_in_v2) ranked.push_back(&result);
    }
    std::sort(ranked.begin(), ranked.end(), [](const BenchResult* left, const BenchResult* right) {
        if (WorstCaseSeconds(*left) != WorstCaseSeconds(*right)) {
            return WorstCaseSeconds(*left) > WorstCaseSeconds(*right);
        }
        return left->name < right->name;
    });
    ranked.resize(std::min<size_t>(5, ranked.size()));
    return ranked;
}

static void RunTimingSelfChecks()
{
    const SampleStats stats{CalculateStats({1, 2, 3, 4})};
    Check(stats.median == 2.5 && stats.minimum == 1 && stats.maximum == 4 &&
              std::abs(stats.mdape - 0.3125) <= 1e-12,
          "internal timing aggregation failed");

    BenchResult lower;
    lower.new_in_v2 = true;
    BenchResult higher;
    higher.new_in_v2 = true;
    lower.name = "measured";
    lower.median_sec = 1;
    higher.name = "projected";
    higher.median_sec = 2;
    higher.full_varops.median_sec = 3;
    BenchResult common;
    common.domain = ExecutionDomain::GSR_TAPSCRIPT_V2;
    common.median_sec = 4;
    common.full_varops.median_sec = 5;
    const std::vector<BenchResult> ranking_results{lower, higher, common};
    const auto top{TopWorstNewV2Cases(ranking_results)};
    Check(top.size() == 2 && top[0]->name == "projected" && top[1]->name == "measured",
          "internal worst-case ranking failed");
}

static const BenchResult* Slowest(const std::vector<BenchResult>& results,
                                  const std::function<bool(const BenchResult&)>& predicate)
{
    const BenchResult* slowest{nullptr};
    for (const BenchResult& result : results) {
        if (predicate(result) && (!slowest || result.median_sec > slowest->median_sec)) slowest = &result;
    }
    return slowest;
}

static const BenchResult* SlowestFullVarops(
    const std::vector<BenchResult>& results,
    const std::function<bool(const BenchResult&)>& predicate)
{
    const BenchResult* slowest{nullptr};
    for (const BenchResult& result : results) {
        if (predicate(result) && result.full_varops.aggregate_stage &&
            (!slowest ||
             result.full_varops.median_sec > slowest->full_varops.median_sec)) {
            slowest = &result;
        }
    }
    return slowest;
}

static std::vector<std::vector<size_t>> BuildRoundSchedules(const std::vector<size_t>& indices,
                                                            int rounds)
{
    std::mt19937_64 generator{ROUND_SEED};
    std::vector<std::vector<size_t>> schedules;
    schedules.reserve(rounds);
    for (int round{0}; round < rounds; ++round) {
        schedules.push_back(indices);
        std::shuffle(schedules.back().begin(), schedules.back().end(), generator);
    }
    return schedules;
}

static std::string CompactResultName(const BenchResult& result)
{
    if (result.operand_shape.empty()) return result.opcode_name;
    return result.opcode_name + " " + result.operand_shape;
}

static void PrintReport(const std::vector<BenchResult>& results, const CorpusCounts& counts,
                        const Options& options)
{
    const BenchResult* denominator{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::PRE_GSR_TAPSCRIPT;
    })};
    const BenchResult* numerator{Slowest(results, [](const BenchResult& result) {
        return result.new_in_v2;
    })};
    const BenchResult* schnorr{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::RAW_SCHNORR;
    })};
    const BenchResult* full_varops{SlowestFullVarops(results, [](const BenchResult& result) {
        return result.new_in_v2;
    })};

    const auto line{[](const std::string& label, const std::string& value) {
        std::cout << "  " << std::left << std::setw(24) << (label + ':') << value << '\n';
    }};

    std::cout << "\n== VAROPS BENCHMARK SUMMARY ==\n";
    line("cases", strprintf("%u/%u completed x %u stable rounds",
                           counts.completed_cases, counts.generated_cases,
                           options.stable_rounds));
    if (options.sample_budget_percent != 100) {
        line("sample mode", strprintf("%u%% budget (%u varops), no fixed/rejection cases",
                                     options.sample_budget_percent, SampleBudget(options)));
    }
    line("schnorr baseline", strprintf("80,000 checks: %.3f s",
                                       schnorr ? schnorr->median_sec : 0.0));
    if (denominator) {
        line("pre-v2 worst", strprintf("%s: %.3f s",
                                       CompactResultName(*denominator), denominator->median_sec));
    }
    if (numerator) {
        const std::string label{options.sample_budget_percent == 100 ?
            "v2 measured worst" : "v2 measured worst (sample)"};
        line(label, strprintf("%s: %.3f s",
                              CompactResultName(*numerator), numerator->median_sec));
    }
    if (full_varops) {
        std::string ratios;
        if (schnorr && schnorr->median_sec > 0) {
            ratios += strprintf("%.2fx schnorr", full_varops->full_varops.median_sec / schnorr->median_sec);
        }
        if (denominator && denominator->median_sec > 0) {
            if (!ratios.empty()) ratios += ", ";
            ratios += strprintf("%.2fx pre-v2",
                                full_varops->full_varops.median_sec / denominator->median_sec);
        }
        if (numerator && numerator->median_sec > 0) {
            if (!ratios.empty()) ratios += ", ";
            ratios += strprintf("%.2fx v2 measured",
                                full_varops->full_varops.median_sec / numerator->median_sec);
        }
        line("v2 projected worst",
             strprintf("%s: %.3f s (%s)", CompactResultName(*full_varops),
                       full_varops->full_varops.median_sec, ratios.empty() ? "no baseline" : ratios));
    }
    std::cout << "\n  top 5 new-v2 cases (measured or projected):\n";
    const auto top{TopWorstNewV2Cases(results)};
    for (size_t i{0}; i < top.size(); ++i) {
        const BenchResult& result{*top[i]};
        const bool projected{result.full_varops.median_sec > result.median_sec};
        const auto stage{projected ? result.full_varops.aggregate_stage : result.aggregate_stage};
        std::cout << strprintf("  %u. %.3f s (%s, %s): %s\n", i + 1,
                               WorstCaseSeconds(result), projected ? "projected" : "measured",
                               stage ? TimingStageName(*stage) : "unmeasured", result.name);
        if (result.executed_opcodes) {
            std::cout << strprintf("     Executed logical opcodes: %u in %u repetitions; varops consumed: %u",
                                   *result.executed_opcodes, result.repetitions, result.varops_consumed);
            if (result.full_varops.status == "extrapolated") {
                std::cout << strprintf("; projected opcodes: %.0f",
                                       *result.executed_opcodes * result.full_varops.scale);
            }
            std::cout << '\n';
        }
    }
}

static std::string GetBenchmarkSystemInfo()
{
    std::ostringstream info;
    std::string cpu_name{"Unknown"};
#if defined(__APPLE__)
    if (FILE * fp{popen("sysctl -n machdep.cpu.brand_string 2>/dev/null", "r")}) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            cpu_name = buffer;
            if (!cpu_name.empty() && cpu_name.back() == '\n') cpu_name.pop_back();
        }
        pclose(fp);
    }
#elif defined(__linux__)
    if (FILE * cpuinfo{fopen("/proc/cpuinfo", "r")}) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "model name", 10) != 0) continue;
            if (const char* separator{strchr(line, ':')}) {
                cpu_name = separator + 2;
                if (!cpu_name.empty() && cpu_name.back() == '\n') cpu_name.pop_back();
                break;
            }
        }
        fclose(cpuinfo);
    }
#endif

    std::string architecture{"Unknown"};
#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    architecture = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    architecture = "ARM64";
#elif defined(__i386__) || defined(_M_IX86)
    architecture = "x86";
#elif defined(__arm__) || defined(_M_ARM)
    architecture = "ARM";
#endif

    std::string compiler{"Unknown"};
#if defined(__clang__)
    compiler = strprintf("Clang %d.%d.%d", __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    compiler = strprintf("GCC %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    compiler = strprintf("MSVC %d", _MSC_VER);
#endif

    info << "# CPU: " << cpu_name << "\n";
    info << "# Architecture: " << architecture << "\n";
    info << "# Compiler: " << compiler << "\n";
    info << "# SHA256 Implementation: " << SHA256AutoDetect() << "\n";
    return info.str();
}

static std::string CsvEscape(std::string_view value)
{
    if (value.find_first_of(",\"\n\r") == std::string_view::npos) return std::string{value};
    std::string escaped{"\""};
    for (char ch : value) {
        if (ch == '"') escaped += '"';
        escaped += ch;
    }
    return escaped + '"';
}

static std::string CsvNumber(double value)
{
    return strprintf("%.17g", value);
}

template <typename T>
static std::string CsvNumber(const T& value)
{
    std::ostringstream output;
    output << value;
    return output.str();
}

enum class CsvColumn : size_t {
    RECORD_TYPE,
    MEASUREMENT_MODE,
    RANK,
    NAME,
    EXECUTION_DOMAIN,
    HEADLINE_ROLE,
    NEW_IN_V2,
    OPCODE,
    SEQUENCE_OPCODES,
    OPERAND_SHAPE,
    OPERAND_PATTERN,
    SCRIPT_BYTES,
    INITIAL_STACK_ITEMS,
    INITIAL_STACK_BYTES,
    VAROPS_CONSUMED,
    EXPECTED_TERMINATION,
    ACTUAL_TERMINATION,
    SATURATION,
    REPETITIONS,
    EXECUTED_OPCODES,
    SEQUENCE_VAROPS,
    STAGE,
    ROUND,
    ORDER,
    SAMPLES,
    WALL_SECONDS,
    WALL_MIN_SECONDS,
    WALL_MAX_SECONDS,
    MDAPE,
    SCHNORR_EQUIVALENTS,
    VAROPS_PERCENTAGE,
    FULL_VAROPS_STATUS,
    FULL_VAROPS_SCRIPT_BYTES,
    FULL_VAROPS_SCRIPT_EXECUTIONS,
    FULL_VAROPS_MEASURED_VAROPS,
    FULL_VAROPS_SCALE,
    FULL_VAROPS_PROJECTED_OPCODES,
    FULL_VAROPS_STAGE,
    FULL_VAROPS_SAMPLES,
    FULL_VAROPS_WALL_SECONDS,
    FULL_VAROPS_WALL_MIN_SECONDS,
    FULL_VAROPS_WALL_MAX_SECONDS,
    FULL_VAROPS_MDAPE,
    FULL_VAROPS_SCHNORR_EQUIVALENTS,
    COUNT,
};

static constexpr size_t CsvIndex(CsvColumn column) { return static_cast<size_t>(column); }

using CsvRow = std::array<std::string, CsvIndex(CsvColumn::COUNT)>;

static constexpr std::string_view CSV_HEADER{
    "Record_Type,Measurement_Mode,Rank,Name,Domain,Headline_Role,New_In_V2,Opcode,Sequence_Opcodes,"
    "Operand_Shape,Operand_Pattern,Script_Bytes,Initial_Stack_Items,Initial_Stack_Bytes,"
    "Varops_Consumed,Expected_Termination,Actual_Termination,Saturation,Repetitions,Executed_Logical_Opcodes,"
    "Sequence_Varops,Stage,Round,Order,Samples,Wall_Seconds,"
    "Wall_Min_Seconds,Wall_Max_Seconds,MdAPE,Schnorr_Equivalents,Varops_Percentage,"
    "Full_Varops_Status,Full_Varops_Script_Bytes,Full_Varops_Script_Executions,Full_Varops_Measured_Varops,"
    "Full_Varops_Scale,Full_Varops_Projected_Logical_Opcodes,Full_Varops_Stage,Full_Varops_Samples,Full_Varops_Wall_Seconds,"
    "Full_Varops_Wall_Min_Seconds,Full_Varops_Wall_Max_Seconds,Full_Varops_MdAPE,"
    "Full_Varops_Schnorr_Equivalents"};
static_assert(std::ranges::count(CSV_HEADER, ',') + 1 == CsvIndex(CsvColumn::COUNT));

static std::string& CsvField(CsvRow& row, CsvColumn column) { return row[CsvIndex(column)]; }

template <typename Fields>
static void WriteCsvRow(std::ostream& output, const Fields& fields)
{
    for (size_t index{0}; index < fields.size(); ++index) {
        if (index != 0) output << ',';
        output << CsvEscape(fields[index]);
    }
    output << '\n';
}

static void SetResultIdentity(CsvRow& row, const BenchResult& result)
{
    CsvField(row, CsvColumn::NAME) = result.name;
    CsvField(row, CsvColumn::EXECUTION_DOMAIN) = DomainName(result.domain);
    CsvField(row, CsvColumn::HEADLINE_ROLE) = RoleName(result.role);
    CsvField(row, CsvColumn::NEW_IN_V2) = result.new_in_v2 ? "true" : "false";
    CsvField(row, CsvColumn::OPCODE) = result.opcode_name;
    CsvField(row, CsvColumn::SEQUENCE_OPCODES) = result.sequence_opcodes;
    CsvField(row, CsvColumn::OPERAND_SHAPE) = result.operand_shape;
    CsvField(row, CsvColumn::OPERAND_PATTERN) = result.operand_pattern;
    CsvField(row, CsvColumn::SCRIPT_BYTES) = CsvNumber(result.script_bytes);
    CsvField(row, CsvColumn::INITIAL_STACK_ITEMS) = CsvNumber(result.initial_stack_items);
    CsvField(row, CsvColumn::INITIAL_STACK_BYTES) = CsvNumber(result.initial_stack_bytes);
    CsvField(row, CsvColumn::VAROPS_CONSUMED) = CsvNumber(result.varops_consumed);
    CsvField(row, CsvColumn::EXPECTED_TERMINATION) = ScriptErrorString(result.expected_error);
    CsvField(row, CsvColumn::ACTUAL_TERMINATION) = ScriptErrorString(result.actual_error);
    CsvField(row, CsvColumn::SATURATION) = result.saturation;
    CsvField(row, CsvColumn::REPETITIONS) = CsvNumber(result.repetitions);
    if (result.executed_opcodes) {
        CsvField(row, CsvColumn::EXECUTED_OPCODES) = CsvNumber(*result.executed_opcodes);
    }
    CsvField(row, CsvColumn::SEQUENCE_VAROPS) = CsvNumber(result.varops_per_repeat);
}

static bool FlushAndClose(std::ofstream& file, const fs::path& path)
{
    file.flush();
    if (!file.good()) {
        std::cerr << "Error: failed while writing " << path << "\n";
        file.close();
        return false;
    }
    file.close();
    if (file.fail()) {
        std::cerr << "Error: failed while closing " << path << "\n";
        return false;
    }
    return true;
}

static bool SaveResultsToFile(const std::vector<BenchResult>& results, const std::string& filepath,
                              const CorpusCounts& counts, const Options& options)
{
    const fs::path output_target{fs::PathFromString(filepath)};
    fs::path output_temporary{output_target};
    output_temporary += ".tmp." + util::ToString(std::chrono::steady_clock::now().time_since_epoch().count());
    std::ofstream output_file(output_temporary.std_path(), std::ios::out | std::ios::trunc);
    if (!output_file.is_open()) {
        std::cerr << "Error: could not open temporary output file " << output_temporary << "\n";
        return false;
    }

    size_t raw_sample_count{0};
    for (const BenchResult& result : results)
        raw_sample_count += result.samples.size();

    output_file << "# Schema: bench_varops-v5\n";
    output_file << GetBenchmarkSystemInfo();
    output_file << "# Record types: summary=aggregated row; sample=normalized wall-clock measurement.\n";
    output_file << "# Wall_Seconds: summary median or sample value; Schnorr samples are normalized to 80,000 validations.\n";
    output_file << "# Full_Varops_Wall_Seconds: natural legal-script runtime extrapolated "
                   "to exactly 40 billion varops.\n";
    output_file << "# Full-varops extrapolation requires at least 1% of the budget in the measured script.\n";
    output_file << "# Measurement_Mode distinguishes realistic measurements and full-varops extrapolations.\n";
    output_file << "# New_In_V2 marks workloads requiring v2 rules or limits, not only new opcode names.\n";
    output_file << strprintf("# Records: summary=%u sample=%u\n", results.size(), raw_sample_count);
    output_file << "# Realistic measurement: scripts stop at their natural script-size or varops limit, "
                   "or at the declared exploratory sample cap; initial stack preparation is untimed.\n";
    output_file << "# Executed_Logical_Opcodes counts candidate-schedule v2 preflight opcode events; "
                   "fragment calls include their executed body instructions.\n";
    output_file << "# Sequence opcodes exclude the final cleanup/result suffix.\n";
    output_file << strprintf("# Corpus: requested_opcodes=%u generated=%u completed=%u profile=%s\n",
                             counts.requested_opcodes, counts.generated_cases, counts.completed_cases,
                             options.sample_budget_percent == 100 ? "full" : "exploratory-sample");
    output_file << strprintf("# Protocol: schnorr_samples=%u sample_budget_percent=%u sample_budget_varops=%u\n",
                             SCHNORR_BASELINE_SAMPLES,
                             options.sample_budget_percent, SampleBudget(options));
    output_file << "#\n";
    output_file << CSV_HEADER << '\n';

    const BenchResult* schnorr{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::RAW_SCHNORR;
    })};
    const double one_schnorr{!schnorr || schnorr->median_sec == 0 ? 0 : schnorr->median_sec / SIGNATURES_PER_BLOCK};
    for (size_t index{0}; index < results.size(); ++index) {
        const BenchResult& result{results[index]};
        CsvRow row;
        SetResultIdentity(row, result);
        CsvField(row, CsvColumn::RECORD_TYPE) = "summary";
        CsvField(row, CsvColumn::MEASUREMENT_MODE) = "combined";
        CsvField(row, CsvColumn::RANK) = CsvNumber(index + 1);
        CsvField(row, CsvColumn::STAGE) =
            result.aggregate_stage ? TimingStageName(*result.aggregate_stage) : "unmeasured";
        CsvField(row, CsvColumn::SAMPLES) = CsvNumber(result.aggregate_stage ? std::ranges::count_if(
                                                                                   result.samples, [&](const TimingSample& sample) {
                                                                                       return sample.stage == *result.aggregate_stage &&
                                                                                              sample.mode == MeasurementMode::REALISTIC;
                                                                                   }) :
                                                                               0);
        CsvField(row, CsvColumn::WALL_SECONDS) = CsvNumber(result.median_sec);
        CsvField(row, CsvColumn::WALL_MIN_SECONDS) = CsvNumber(result.wall_min_sec);
        CsvField(row, CsvColumn::WALL_MAX_SECONDS) = CsvNumber(result.wall_max_sec);
        CsvField(row, CsvColumn::MDAPE) = CsvNumber(result.mdape);
        CsvField(row, CsvColumn::SCHNORR_EQUIVALENTS) =
            CsvNumber(one_schnorr == 0 ? 0 : result.median_sec / one_schnorr);
        CsvField(row, CsvColumn::VAROPS_PERCENTAGE) =
            CsvNumber(100.0 * result.varops_consumed / TOTAL_VAROPS_BUDGET);
        CsvField(row, CsvColumn::FULL_VAROPS_STATUS) = result.full_varops.status;
        if (result.full_varops.aggregate_stage) {
            CsvField(row, CsvColumn::FULL_VAROPS_SCRIPT_BYTES) =
                CsvNumber(result.full_varops.script_bytes);
            CsvField(row, CsvColumn::FULL_VAROPS_SCRIPT_EXECUTIONS) =
                CsvNumber(result.full_varops.script_executions);
            CsvField(row, CsvColumn::FULL_VAROPS_MEASURED_VAROPS) =
                CsvNumber(result.full_varops.measured_varops);
            CsvField(row, CsvColumn::FULL_VAROPS_SCALE) =
                CsvNumber(result.full_varops.scale);
            if (result.executed_opcodes) {
                CsvField(row, CsvColumn::FULL_VAROPS_PROJECTED_OPCODES) =
                    CsvNumber(*result.executed_opcodes * result.full_varops.scale);
            }
            CsvField(row, CsvColumn::FULL_VAROPS_STAGE) =
                TimingStageName(*result.full_varops.aggregate_stage);
            CsvField(row, CsvColumn::FULL_VAROPS_SAMPLES) =
                CsvNumber(std::ranges::count_if(result.samples, [&](const TimingSample& sample) {
                    return sample.stage == *result.full_varops.aggregate_stage &&
                           sample.mode == MeasurementMode::FULL_VAROPS;
                }));
            CsvField(row, CsvColumn::FULL_VAROPS_WALL_SECONDS) =
                CsvNumber(result.full_varops.median_sec);
            CsvField(row, CsvColumn::FULL_VAROPS_WALL_MIN_SECONDS) =
                CsvNumber(result.full_varops.wall_min_sec);
            CsvField(row, CsvColumn::FULL_VAROPS_WALL_MAX_SECONDS) =
                CsvNumber(result.full_varops.wall_max_sec);
            CsvField(row, CsvColumn::FULL_VAROPS_MDAPE) =
                CsvNumber(result.full_varops.mdape);
            CsvField(row, CsvColumn::FULL_VAROPS_SCHNORR_EQUIVALENTS) =
                CsvNumber(one_schnorr == 0 ? 0 :
                                             result.full_varops.median_sec / one_schnorr);
        }
        WriteCsvRow(output_file, row);
    }

    for (const BenchResult& result : results) {
        for (const TimingSample& sample : result.samples) {
            CsvRow row;
            CsvField(row, CsvColumn::RECORD_TYPE) = "sample";
            CsvField(row, CsvColumn::MEASUREMENT_MODE) = MeasurementModeName(sample.mode);
            CsvField(row, CsvColumn::NAME) = result.name;
            CsvField(row, CsvColumn::NEW_IN_V2) = result.new_in_v2 ? "true" : "false";
            CsvField(row, CsvColumn::STAGE) = TimingStageName(sample.stage);
            CsvField(row, CsvColumn::ROUND) = CsvNumber(sample.round);
            CsvField(row, CsvColumn::ORDER) = CsvNumber(sample.order);
            CsvField(row, CsvColumn::WALL_SECONDS) = CsvNumber(sample.wall_sec);
            WriteCsvRow(output_file, row);
        }
    }

    if (!FlushAndClose(output_file, output_temporary)) {
        std::error_code ignored;
        fs::remove(output_temporary, ignored);
        return false;
    }
    std::error_code rename_error;
    fs::rename(output_temporary, output_target, rename_error);
    if (rename_error) {
        std::cerr << "Error: could not atomically replace " << output_target << ": " << rename_error.message() << "\n";
        std::error_code ignored;
        fs::remove(output_temporary, ignored);
        return false;
    }
    return true;
}

static void PrintUsage(const char* program)
{
    std::cout << "Usage: " << program << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --opcodes OP_NAME...    Benchmark only explicitly supported opcodes\n"
              << "  --epochs N              Stable measurement rounds (default: 5)\n"
              << "  --sample-budget-percent N  Sample repeatable v2 cases at N% of the 40B budget (1..100)\n"
              << "                            Omit fixed/rejection cases; extrapolate measured time and opcodes\n"
              << "  --case-filter TEXT      Match case names; retain selected pre-v2 baselines\n"
              << "  --list-opcodes          List the declarative opcode inventory\n"
              << "  --verify-costs         Cost-verification mode: assert static/runtime parity, skip timing\n"
              << "  --coverage-manifest P Export candidate opcode/formula/parity CSV\n"
              << "  --exclude-experimental Skip postponed OP_TX/macro cases (including parity checks)\n"
              << "  --silent                Suppress progress output\n"
              << "  --file PATH             Atomically write a v4 summary-and-sample CSV\n"
              << "  --help, -h              Show this help\n\n"
              << "\n"
              << "Examples:\n"
              << "  " << program << " --opcodes OP_ROLL OP_SHA256\n"
              << "  " << program << " --sample-budget-percent 10 --file results.csv\n";
}

static Options ParseArguments(int argc, char* argv[])
{
    Options options;
    const std::map<std::string, opcodetype> supported{SupportedOpcodeMap()};
    for (int i{1}; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--opcodes") {
            const int first{i + 1};
            while (i + 1 < argc && !std::string_view{argv[i + 1]}.starts_with("--")) {
                const std::string requested{argv[++i]};
                std::string name{ToUpper(requested)};
                if (!name.starts_with("OP_")) name = "OP_" + name;
                const auto found{supported.find(name)};
                if (found == supported.end()) {
                    throw std::runtime_error("unknown or unsupported opcode '" + requested + "'");
                }
                options.selected_opcodes.insert(found->second);
            }
            if (i + 1 == first) throw std::runtime_error("--opcodes requires at least one opcode");
        } else if (arg == "--epochs") {
            if (++i >= argc) throw std::runtime_error("--epochs requires a positive integer");
            const std::optional<int> stable_rounds{ToIntegral<int>(argv[i])};
            if (!stable_rounds || *stable_rounds <= 0) {
                throw std::runtime_error("invalid --epochs value '" + std::string{argv[i]} + "'");
            }
            options.stable_rounds = *stable_rounds;
        } else if (arg == "--sample-budget-percent") {
            if (++i >= argc) throw std::runtime_error("--sample-budget-percent requires an integer from 1 to 100");
            const std::optional<uint32_t> percent{ToIntegral<uint32_t>(argv[i])};
            if (!percent || *percent < 1 || *percent > 100) {
                throw std::runtime_error("invalid --sample-budget-percent value '" + std::string{argv[i]} + "'");
            }
            options.sample_budget_percent = *percent;
        } else if (arg == "--case-filter") {
            if (++i >= argc || std::string_view{argv[i]}.empty()) {
                throw std::runtime_error("--case-filter requires a nonempty substring");
            }
            options.case_filter = argv[i];
        } else if (arg == "--list-opcodes") {
            options.list_opcodes = true;
        } else if (arg == "--verify-costs") {
            options.verify_costs = true;
        } else if (arg == "--exclude-experimental") {
            options.exclude_experimental = true;
        } else if (arg == "--coverage-manifest") {
            if (++i >= argc) throw std::runtime_error("--coverage-manifest requires a path");
            options.coverage_manifest = argv[i];
        } else if (arg == "--silent") {
            options.silent = true;
        } else if (arg == "--file") {
            if (++i >= argc) throw std::runtime_error("--file requires a path");
            options.output_file = argv[i];
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("unknown option '" + arg + "'");
        }
    }
    return options;
}

static std::map<opcodetype, ParityCoverage> VerifyCorpusCosts(
    const std::vector<CaseSpec>& specs, const CryptoFixture& fixture, bool silent)
{
    std::map<opcodetype, ParityCoverage> parity;
    size_t checked{0};
    size_t independent_checked{0};
    size_t boundary_checked{0};
    for (const CaseSpec& spec : specs) {
        if (DomainFor(spec.role) != ExecutionDomain::GSR_TAPSCRIPT_V2) continue;
        const MaterializedCase planned{Materialize(spec, fixture)};
        const size_t cleanup_items{spec.cleanup_items.value_or(planned.initial_stack.size())};
        CScript verification_script;
        const bool one_repeat{!spec.sequence.empty() && spec.expected_error == SCRIPT_ERR_OK};
        if (!one_repeat) {
            verification_script = planned.script;
        } else {
            verification_script.insert(verification_script.end(), spec.sequence.begin(), spec.sequence.end());
            for (size_t i{0}; i < cleanup_items; ++i) {
                verification_script.push_back(static_cast<unsigned char>(OP_DROP));
            }
            verification_script.push_back(static_cast<unsigned char>(OP_1));
        }
        MaterializedCase test_case{
            &spec,
            planned.initial_stack,
            std::move(verification_script),
            one_repeat ? 1 : planned.repetitions,
            planned.varops_per_repeat,
            "cost-verification",
            planned.transaction,
        };
        if (spec.empty_witness_items && one_repeat) {
            test_case.transaction = MakeOpTxContext(*spec.empty_witness_items, test_case.script);
        }
        BenchSignatureChecker checker{fixture, test_case.transaction.get()};
        IndependentCostAudit independent_audit{spec};
        EvalOutcome observed;
        {
            varops::ScopedCostAudit audit_scope{&independent_audit};
            observed = Evaluate(test_case, checker);
        }
        const bool expected_success{spec.expected_error == SCRIPT_ERR_OK};
        if (observed.success != expected_success || observed.error != spec.expected_error) {
            throw std::runtime_error(strprintf(
                "cost verification semantic mismatch for %s: expected %s, got %s (script=%s, consumed=%u)",
                spec.name, ScriptErrorString(spec.expected_error), ScriptErrorString(observed.error),
                HexStr(test_case.script), observed.varops_consumed) +
                strprintf(" script_size=%u ops=%s initial_items=%u cleanup=%u", test_case.script.size(),
                          SequenceOpcodeNames(test_case.script), test_case.initial_stack.size(),
                          spec.cleanup_items.value_or(test_case.initial_stack.size())));
        }
        ++checked;

        // For successful cases, the observed exact cost must be sufficient and
        // one fewer varop must fail. This includes setup, restoration, cleanup
        // suffix instructions, and the separate final success check.
        if (observed.success && observed.varops_consumed > 0) {
            ++parity[spec.opcode].successful_cases;
            if (!independent_audit.Passed()) {
                throw std::runtime_error("independent formula mismatch for " + spec.name +
                                         ": " + independent_audit.Mismatch());
            }
            if (independent_audit.ExpectedTotal() != observed.varops_consumed ||
                independent_audit.ActualTotal() != observed.varops_consumed) {
                throw std::runtime_error(strprintf(
                    "independent total mismatch for %s: expected=%u audited-runtime=%u consumed=%u",
                    spec.name, independent_audit.ExpectedTotal(),
                    independent_audit.ActualTotal(), observed.varops_consumed));
            }
            ++parity[spec.opcode].static_formula_cases;
            ++independent_checked;
            const EvalOutcome exact{Evaluate(test_case, checker, observed.varops_consumed)};
            if (!exact.success || exact.error != SCRIPT_ERR_OK ||
                exact.varops_consumed != observed.varops_consumed) {
                throw std::runtime_error("exact-budget replay mismatch for " + spec.name);
            }
            const EvalOutcome short_budget{Evaluate(test_case, checker, observed.varops_consumed - 1)};
            if (short_budget.success || short_budget.error != SCRIPT_ERR_VAROP_COUNT) {
                throw std::runtime_error("budget-minus-one did not reject for " + spec.name);
            }
            ++boundary_checked;
        }
        if (!silent && checked % CLI_PROGRESS_INTERVAL == 0) {
            std::cout << strprintf("Cost verification: %u cases\n", checked);
        }
    }
    std::cout << strprintf("Outcome verification passed: %u candidate cases.\n", checked);
    std::cout << strprintf(
        "Independent formula parity passed: %u successful cases across %u opcode families.\n",
        independent_checked, parity.size());
    std::cout << strprintf(
        "Exact-budget/budget-minus-one verification passed: %u successful cases.\n",
        boundary_checked);
    return parity;
}

static void RequireIndependentParity(
    const std::vector<CaseSpec>& specs,
    const std::map<opcodetype, ParityCoverage>& parity)
{
    std::set<opcodetype> selected;
    for (const CaseSpec& spec : specs) {
        if (DomainFor(spec.role) == ExecutionDomain::GSR_TAPSCRIPT_V2) {
            selected.insert(spec.opcode);
        }
    }
    for (const opcodetype opcode : selected) {
        const auto found{parity.find(opcode)};
        if (found == parity.end() || found->second.successful_cases == 0 ||
            found->second.static_formula_cases != found->second.successful_cases) {
            throw std::runtime_error("candidate timing refused: independent parity incomplete for " +
                                     OpcodeName(opcode));
        }
    }
}

} // namespace

int main(int argc, char* argv[])
{
    if constexpr (varops::PRODUCER_LIFETIME_EXPERIMENT) {
        std::cerr << "Experimental producer lifetime schedule: PRODUCE=" << varops::CopyCost(0)
                  << "+" << varops::CopyCost(1) - varops::CopyCost(0)
                  << "*n; initial stack prepaid; explicit RELEASE=0.\n";
    }
    try {
        const Options options{ParseArguments(argc, argv)};
        if (options.list_opcodes) {
            for (const auto& [name, opcode] : SupportedOpcodeMap()) {
                std::cout << strprintf("%s (0x%02x)\n", name, static_cast<unsigned int>(opcode));
            }
            return 0;
        }

        RunBoundarySelfChecks();
        RunTimingSelfChecks();
        SHA256AutoDetect();
        const CryptoFixture fixture;
        const std::vector<CaseSpec> specs{GenerateCaseSpecs(options)};
        if (specs.empty()) throw std::runtime_error("the requested opcode set generated no cases");
        if (options.verify_costs) {
            const auto parity{VerifyCorpusCosts(specs, fixture, options.silent)};
            RequireIndependentParity(specs, parity);
            if (!options.coverage_manifest.empty()) {
                WriteCoverageManifest(options.coverage_manifest, parity);
            }
            return 0;
        }
        Options parity_options{options};
        parity_options.case_filter.clear();
        const std::vector<CaseSpec> parity_specs{GenerateCaseSpecs(parity_options)};
        const auto parity{VerifyCorpusCosts(parity_specs, fixture, true)};
        RequireIndependentParity(parity_specs, parity);
        if (!options.coverage_manifest.empty()) WriteCoverageManifest(options.coverage_manifest, parity);
        ReleaseAllocatorCaches();

        const uint64_t sample_budget{SampleBudget(options)};
        std::set<opcodetype> completed_opcodes;
        std::vector<BenchResult> results;
        results.reserve(specs.size() + 1);
        std::vector<std::optional<size_t>> result_indices(specs.size());
        std::vector<bool> skipped(specs.size());
        CorpusCounts counts{
            options.selected_opcodes.empty() ? OpcodeRegistry().size() : options.selected_opcodes.size(),
            specs.size(),
            0,
        };
        RunGlobalWarmup(fixture);
        results.push_back(RunRawSchnorr(fixture));
        std::vector<size_t> all_indices;
        all_indices.reserve(specs.size());
        for (size_t index{0}; index < specs.size(); ++index) all_indices.push_back(index);
        const auto schedules{BuildRoundSchedules(all_indices, options.stable_rounds)};
        if (!options.silent) {
            std::cout << strprintf("Stable measurement: %u cases x %u rounds\n",
                                   all_indices.size(), options.stable_rounds);
        }
        for (size_t round{0}; round < schedules.size(); ++round) {
            for (size_t order{0}; order < schedules[round].size(); ++order) {
                const size_t spec_index{schedules[round][order]};
                if (skipped[spec_index]) continue;
                MaterializedCase test_case{Materialize(specs[spec_index], fixture, sample_budget)};
                if (test_case.repetitions == 0) {
                    skipped[spec_index] = true;
                    if (!options.silent) {
                        std::cout << "Skipped (one sequence exceeds sample budget): " << specs[spec_index].name << '\n';
                    }
                    continue;
                }
                std::optional<EvalOutcome> expected;
                if (result_indices[spec_index]) {
                    const BenchResult& previous{results[*result_indices[spec_index]]};
                    expected = EvalOutcome{previous.actual_error == SCRIPT_ERR_OK,
                                           previous.actual_error, previous.varops_consumed};
                }
                CaseSample sample{RunTimedCaseSample(test_case, fixture, expected,
                                                     round + 1, order, sample_budget)};
                if (!result_indices[spec_index]) {
                    BenchResult result{ResultMetadata(test_case)};
                    result.actual_error = sample.outcome.error;
                    result.varops_consumed = sample.outcome.varops_consumed;
                    result.executed_opcodes = sample.executed_opcodes;
                    ConfigureFullVaropsExtrapolation(test_case, sample.outcome, result.full_varops);
                    result_indices[spec_index] = results.size();
                    results.push_back(std::move(result));
                    completed_opcodes.insert(specs[spec_index].opcode);
                    ++counts.completed_cases;
                }
                BenchResult& result{results[*result_indices[spec_index]]};
                std::optional<TimingSample> full_varops_sample;
                if (result.full_varops.status == "extrapolated") {
                    if (sample.outcome.varops_consumed != result.full_varops.measured_varops) {
                        throw std::runtime_error("full-varops extrapolation plan changed");
                    }
                    full_varops_sample =
                        ExtrapolateFullVaropsSample(sample.timing, result.full_varops);
                }
                const double wall{std::max(sample.timing.wall_sec,
                                           full_varops_sample ? full_varops_sample->wall_sec : 0.0)};
                result.samples.push_back(std::move(sample.timing));
                if (full_varops_sample) {
                    result.samples.push_back(std::move(*full_varops_sample));
                }
                if (!options.silent) {
                    std::cout << strprintf("round %u case %u/%u %s: %.3f s\n", round + 1,
                                           order + 1, schedules[round].size(), result.name,
                                           wall) << std::flush;
                }
            }
            if (!options.silent) {
                std::cout << strprintf("Stable measurement: round %u/%u complete\n",
                                       round + 1, schedules.size());
            }
        }
        for (size_t index{1}; index < results.size(); ++index) {
            AggregateSamples(results[index], TimingStage::STABLE, MeasurementMode::REALISTIC);
            if (results[index].full_varops.status == "extrapolated") {
                AggregateSamples(results[index], TimingStage::STABLE, MeasurementMode::FULL_VAROPS);
            }
        }

        for (opcodetype requested : options.selected_opcodes) {
            if (!completed_opcodes.contains(requested)) {
                throw std::runtime_error("requested opcode produced no completed row: " + OpcodeName(requested));
            }
        }
        std::sort(results.begin(), results.end(), [](const BenchResult& left, const BenchResult& right) {
            return WorstCaseSeconds(left) > WorstCaseSeconds(right);
        });
        PrintReport(results, counts, options);
        if (!options.output_file.empty() &&
            !SaveResultsToFile(results, options.output_file, counts, options)) {
            return 1;
        }
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "bench_varops: " << exception.what() << "\n";
        return 1;
    }
}
