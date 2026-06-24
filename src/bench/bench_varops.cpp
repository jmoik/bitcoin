// Copyright (c) 2025-2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <prevector.h>
#include <script/op_tx.h>
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
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <span.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <bit>
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
#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
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
#include <vector>
#ifndef _WIN32
#include <sys/resource.h>
#else
#include <compat/compat.h>
#include <windows.h>
#include <psapi.h>
#endif

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

bool CastToBool(const std::vector<unsigned char>& vch);

const TranslateFn G_TRANSLATION_FUN{nullptr};
static bool g_diagnose_div17{false};
static bool g_skip_allocator_trim{false};

// Candidate formulas count coefficients separately from primitive composition.
// Derive these views from the single consensus formulas rather than duplicating prices.
namespace varops {
constexpr uint64_t COST_BASE{BaseCost()};
constexpr uint64_t COST_PREPARE_FIXED{PrepareCost(0)};
constexpr uint64_t COST_PREPARE_BYTE{(PrepareCost(8) - PrepareCost(0)) / 8};
constexpr uint64_t COST_OUTPUT_FIXED{OutputCost(0)};
constexpr uint64_t COST_OUTPUT_BYTE{(OutputCost(8) - OutputCost(0)) / 8};
constexpr uint64_t COST_COPY_FIXED{WriteCost(0)};
constexpr uint64_t COST_COPY_BYTE{(WriteCost(8) - WriteCost(0)) / 8};
constexpr uint64_t COST_READ_FIXED{ReadCost(0)};
constexpr uint64_t COST_READ{(ReadCost(8) - ReadCost(0)) / 8};
constexpr uint64_t COST_ARITH_FIXED{ArithCost(0)};
constexpr uint64_t COST_ARITH_BYTE{(ArithCost(8) - ArithCost(0)) / 8};
constexpr uint64_t COST_BIT_FIXED{BitCost(0)};
constexpr uint64_t COST_BIT{(BitCost(8) - BitCost(0)) / 8};
constexpr uint64_t COST_DIV_FIXED{DivCost(0, 0)};
constexpr uint64_t COST_DIV_STEP{DivCost(1, 0) - DivCost(0, 0)};
constexpr uint64_t COST_DIV_CELL{DivCost(1, 1) - DivCost(1, 0)};
// Hash rates are per byte of the padded 64-byte-block span; an empty message is one block.
constexpr uint64_t COST_SHA256_BYTE{(Sha256Cost(64) - Sha256Cost(0)) / 64};
constexpr uint64_t COST_SHA256_FIXED{Sha256Cost(0) - 64 * COST_SHA256_BYTE};
constexpr uint64_t COST_H160_BYTE{(Ripemd160Cost(64) - Ripemd160Cost(0)) / 64};
constexpr uint64_t COST_H160_FIXED{Ripemd160Cost(0) - 64 * COST_H160_BYTE};
constexpr uint64_t COST_H1_BYTE{(Sha1Cost(64) - Sha1Cost(0)) / 64};
constexpr uint64_t COST_H1_FIXED{Sha1Cost(0) - 64 * COST_H1_BYTE};
constexpr uint64_t COST_MACRO_UNROLL{BaseCost()};
constexpr uint64_t COST_SCALAR_OUTPUT{ScalarOutputCost()};
constexpr uint64_t COST_SCALAR_WRITE{WriteCost(8)};
} // namespace varops

namespace {

constexpr size_t SCRIPT_BYTES{MAX_BLOCK_WEIGHT};
// Unrolled bytes reserved for wrappers and the harness cleanup suffix.
constexpr size_t UNROLLED_MARGIN{64};
constexpr uint64_t TOTAL_VAROPS_BUDGET{uint64_t{MAX_BLOCK_WEIGHT} * varops::BUDGET_PER_WEIGHT_UNIT};
// Avoid amplifying fixed harness overhead from semantic one-shot cases.
constexpr uint64_t MIN_FULL_VAROPS_SAMPLE_BUDGET{TOTAL_VAROPS_BUDGET / 100};
constexpr uint64_t MAX_FIXTURE_POOL_BYTES{512U * 1024U * 1024U};
//! Repeated evaluations timed before a cheap case is sampled and extrapolated.
constexpr uint64_t MAX_UNSCALED_EVALUATIONS{1000};
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
    std::string output_file;
    std::string coverage_manifest;
    std::string case_filter;
    bool shape_search{false};
    double reference_seconds{0};
    uint64_t search_budget{TOTAL_VAROPS_BUDGET / 100};
    uint32_t search_samples{32};
    uint32_t search_climbers{2};
    uint32_t search_steps{4};
    uint32_t search_top{20};
    uint64_t search_seed{ROUND_SEED};
    bool program_search{false};
    uint64_t search_seconds{600};
    std::string search_corpus;
    //! Confirmation mode: rerun the cases a screening CSV flagged above the threshold.
    std::string confirm_file;
    double confirm_threshold{1.0};
    std::set<std::string> confirm_names;
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
        : tx{mutable_tx}, spent_outputs(tx.vin.size(), CTxOut{0, CScript{}}), control_block{std::move(control_block_in)} {}
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

//! Transaction around an OP_TX case: input 0 runs the case script; input 1 carries
//! `empty_items` empty witness items; extra inputs and outputs have empty scripts.
//! `units` is the OP_TX_SELECT count k of one execution, derived from the shape.
struct OpTxShape {
    size_t empty_items{0};
    size_t extra_inputs{0};
    size_t extra_outputs{0};
    uint64_t units{0};
};

struct CaseOptions {
    ScriptError expected_error{SCRIPT_ERR_OK};
    RepeatMode repeat_mode{RepeatMode::MAX_SUCCESS};
    uint64_t fixed_repetitions{0}, max_repetitions{std::numeric_limits<uint64_t>::max()};
    std::optional<size_t> cleanup_items;
    std::string saturation_hint;
    std::optional<uint64_t> expected_varops_per_repeat;
    std::optional<SaturationExpectation> expected_saturation;
    std::string sequence_label;
    std::optional<OpTxShape> op_tx_shape;
    //! Evaluate the script repeatedly against one shared budget until the budget is
    //! spent, as inputs of one transaction whose pooled budget funds them. Models
    //! work bounded per script (unrolled size, stack limits) rather than per budget.
    bool repeat_evaluations{false};
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
    std::optional<OpTxShape> op_tx_shape;
    //! Evaluate the script repeatedly against one shared budget until the budget is
    //! spent, as inputs of one transaction whose pooled budget funds them. Models
    //! work bounded per script (unrolled size, stack limits) rather than per budget.
    bool repeat_evaluations{false};
};

struct MaterializedCase {
    const CaseSpec* spec{nullptr};
    std::vector<valtype> initial_stack;
    CScript script;
    uint64_t repetitions{0}, varops_per_repeat{0};
    std::string saturation;
    std::shared_ptr<const TransactionFixture> transaction;
    //! Script evaluations sharing the budget; see CaseOptions::repeat_evaluations.
    uint64_t evaluations{1};
};

struct EvalOutcome {
    bool success{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t varops_consumed{0};
};

static uint64_t InitialProducerCost(const std::vector<valtype>& stack)
{
    uint64_t total{0};
    for (const auto& value : stack) total += varops::COST_COPY_FIXED + varops::COST_COPY_BYTE * varops::WordSpan(value.size());
    return total;
}

// Message plus padding and length, in whole 64-byte hash blocks.
static uint64_t IndependentHashSpan(uint64_t bytes)
{
    const uint64_t blocks{(bytes + 9 + 63) / 64};
    return blocks * 64;
}

// Independent charges accumulate in uint64_t and saturate at its maximum. All
// terms are nonnegative, so the result is min(exact sum, UINT64_MAX).
static void IndependentAdd(uint64_t& q, uint64_t coefficient, uint64_t units = 1)
{
    constexpr uint64_t MAX{std::numeric_limits<uint64_t>::max()};
    const uint64_t term{units != 0 && coefficient > MAX / units ? MAX : coefficient * units};
    q = term > MAX - q ? MAX : q + term;
}

static uint64_t IndependentDivSteps(uint64_t dividend_limbs, uint64_t divisor_limbs)
{
    return std::max<uint64_t>(1, dividend_limbs + 2 - std::min(divisor_limbs, dividend_limbs + 2));
}

/** Process resource usage around one timed sample; -1 marks an unavailable counter. */
struct ResourceCounters {
    double cpu_sec{-1};
    int64_t minor_faults{-1}, major_faults{-1}, involuntary_switches{-1};
};

static ResourceCounters ReadResourceCounters()
{
    ResourceCounters counters;
#ifndef _WIN32
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        const auto seconds = [](const timeval& t) { return double(t.tv_sec) + double(t.tv_usec) / 1e6; };
        counters.cpu_sec = seconds(usage.ru_utime) + seconds(usage.ru_stime);
        counters.minor_faults = usage.ru_minflt;
        counters.major_faults = usage.ru_majflt;
        counters.involuntary_switches = usage.ru_nivcsw;
    }
#else
    FILETIME creation, exit, kernel, user;
    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        const auto ticks = [](const FILETIME& t) { return (uint64_t{t.dwHighDateTime} << 32) | t.dwLowDateTime; };
        counters.cpu_sec = double(ticks(kernel) + ticks(user)) / 1e7;
    }
    // Windows counts soft and hard faults together; report them as minor faults.
    PROCESS_MEMORY_COUNTERS memory{};
    if (K32GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory))) {
        counters.minor_faults = memory.PageFaultCount;
    }
#endif
    return counters;
}

static ResourceCounters CounterDelta(const ResourceCounters& before, const ResourceCounters& after)
{
    const auto delta = [](auto a, auto b) { return a < 0 || b < 0 ? decltype(a){-1} : b - a; };
    return {delta(before.cpu_sec, after.cpu_sec), delta(before.minor_faults, after.minor_faults),
            delta(before.major_faults, after.major_faults),
            delta(before.involuntary_switches, after.involuntary_switches)};
}

struct TimingSample {
    MeasurementMode mode{MeasurementMode::REALISTIC};
    TimingStage stage{TimingStage::STABLE};
    int round{0};
    size_t order{0};
    double wall_sec{0};
    //! Measured realistic samples only; extrapolated samples reuse the measurement.
    std::optional<ResourceCounters> counters{};
};

struct CaseSample {
    EvalOutcome outcome;
    TimingSample timing;
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
    uint64_t q{0};
    IndependentAdd(q, varops::COST_BASE);
    switch (opcode) {
    case OP_SHA1:
        IndependentAdd(q, varops::COST_H1_FIXED);
        IndependentAdd(q, varops::COST_H1_BYTE, IndependentHashSpan(input_size));
        break;
    case OP_RIPEMD160:
        IndependentAdd(q, varops::COST_H160_FIXED);
        IndependentAdd(q, varops::COST_H160_BYTE, IndependentHashSpan(input_size));
        break;
    case OP_SHA256:
        IndependentAdd(q, varops::COST_SHA256_FIXED);
        IndependentAdd(q, varops::COST_SHA256_BYTE, IndependentHashSpan(input_size));
        break;
    case OP_HASH160:
        IndependentAdd(q, varops::COST_SHA256_FIXED);
        IndependentAdd(q, varops::COST_SHA256_BYTE, IndependentHashSpan(input_size));
        IndependentAdd(q, varops::COST_H160_FIXED);
        IndependentAdd(q, varops::COST_H160_BYTE, IndependentHashSpan(32));
        break;
    case OP_HASH256:
        IndependentAdd(q, varops::COST_SHA256_FIXED, 2);
        IndependentAdd(q, varops::COST_SHA256_BYTE, IndependentHashSpan(input_size) + IndependentHashSpan(32));
        break;
    default:
        throw std::runtime_error("not a hash opcode");
    }
    IndependentAdd(q, varops::COST_COPY_FIXED);
    IndependentAdd(q, varops::COST_COPY_BYTE, varops::WordSpan(output_size));
    return q;
}

// The value's producer prepaid its release.
static uint64_t CandidateDropCost(size_t)
{
    return varops::COST_BASE;
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

/**
 * Superseded BIP 441 byte-rate formulas. They only choose sizes for exploratory
 * crossover probes, whose saturation and cost are not asserted (see AddCostCase).
 * They are not charges; candidate costs come from varops.h.
 */
namespace legacy_sizing {
constexpr uint64_t COST_FAST{2};
constexpr uint64_t COST_COPYING{3};
constexpr uint64_t COST_OTHER{4};
constexpr uint64_t COST_ARITH{6};
constexpr uint64_t COST_HASH{50};
constexpr uint64_t LengthConversionCost(size_t size) { return varops::WordSpan(size) * COST_FAST; }
constexpr uint64_t CompareZeroCost(size_t size) { return varops::WordSpan(size) * COST_FAST; }
constexpr uint64_t AddCost(size_t a, size_t b) { return std::max(varops::WordSpan(a), varops::WordSpan(b)) * (COST_ARITH + COST_COPYING); }
constexpr uint64_t SubCost(size_t a, size_t b) { return std::max(varops::WordSpan(a), varops::WordSpan(b)) * COST_ARITH; }
constexpr uint64_t InvertCost(size_t size) { return varops::WordSpan(size) * COST_OTHER; }
constexpr uint64_t TwoMulCost(size_t size) { return varops::WordSpan(size) * (COST_COPYING + COST_OTHER); }
constexpr uint64_t TwoDivCost(size_t size) { return varops::WordSpan(size) * COST_OTHER; }
constexpr uint64_t UnalignedUpShiftCost(size_t size, size_t prepended) { return varops::WordSpan(size + prepended) * COST_OTHER; }
constexpr uint64_t WithinCost(size_t a, size_t b, size_t c)
{
    return (std::max(varops::WordSpan(a), varops::WordSpan(b)) + std::max(varops::WordSpan(a), varops::WordSpan(c))) * COST_FAST;
}
} // namespace legacy_sizing

static uint64_t SequenceExecutionCost(const CScript& sequence)
{
    uint64_t cost{0};
    CScript::const_iterator pc{sequence.begin()};
    while (pc != sequence.end()) {
        opcodetype opcode;
        valtype data;
        if (!sequence.GetOp(pc, opcode, data)) throw std::runtime_error("invalid benchmark sequence");
        cost += varops::BaseCost();
        if (opcode >= OP_RIPEMD160 && opcode <= OP_HASH256) {
            // Hash input size is unknown at static-model time; the candidate
            // hash+insert charge is asserted per-case instead, so skip the
            // flat byte charge here to avoid double-counting.
            continue;
        }
        cost += data.size() * legacy_sizing::COST_COPYING;
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
    if (g_skip_allocator_trim) return;
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
        (cleanup_items + 1) * varops::BaseCost() + legacy_sizing::CompareZeroCost(1)};
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
    Check(rounding_meter.Spend(rounding_budget) && rounding_budget.Remaining() == 9,
          "candidate first deduction failed");
    Check(rounding_meter.Spend(rounding_budget) && rounding_budget.Remaining() == 9,
          "candidate unchanged charge was deducted twice");
    rounding_meter.Add(2);
    Check(rounding_meter.Spend(rounding_budget) && rounding_budget.Remaining() == 7,
          "candidate second deduction was not applied");
}

struct PreparedExecution {
    std::vector<valtype> legacy_stack;
    std::vector<ValtypeStack> v2_stacks;
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
        execution.v2_stacks.reserve(test_case.evaluations);
        for (uint64_t i{0}; i < test_case.evaluations; ++i) execution.v2_stacks.emplace_back(test_case.initial_stack);
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

    bool success{true};
    for (ValtypeStack& stack : execution.v2_stacks) {
        // Each evaluation is a separate input with its own execution data.
        ScriptExecutionData execdata{execution.execdata};
        success = EvalTapscriptV2(stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                  checker, execdata, *execution.budget, &error);
        if (success) success = CheckTapscriptV2ScriptResult(stack, *execution.budget, &error);
        if (!success) break;
    }
    outcome.success = success;
    outcome.error = error;
    outcome.varops_consumed = execution.initial_budget - execution.budget->Remaining();
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

static CMutableTransaction EmptyWitnessTransaction(const OpTxShape& shape, const CScript& script)
{
    CMutableTransaction tx;
    tx.vin.resize(2 + shape.extra_inputs);
    for (size_t i{0}; i < tx.vin.size(); ++i) tx.vin[i].prevout.n = static_cast<uint32_t>(i);
    const valtype control_block{V2ControlBlock()};
    const valtype selector{0, 1, 0, 0x30, 0x80, 0}; // Collate input 1's witness items.
    tx.vin[0].scriptWitness.stack = {valtype{1}, selector,
                                    valtype{script.begin(), script.end()}, control_block};
    auto& source_witness{tx.vin[1].scriptWitness.stack};
    source_witness.assign(shape.empty_items, valtype{});
    // An immediate-success leaf makes the large source witness plausible.
    source_witness.push_back(valtype{static_cast<unsigned char>(OP_1NEGATE)});
    source_witness.push_back(control_block);
    tx.vout.emplace_back(0, CScript{} << OP_RETURN);
    tx.vout.resize(1 + shape.extra_outputs, CTxOut{0, CScript{}});
    return tx;
}

static std::shared_ptr<const TransactionFixture> MakeOpTxContext(const OpTxShape& shape, const CScript& script)
{
    CMutableTransaction tx{EmptyWitnessTransaction(shape, script)};
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
    if (spec.op_tx_shape) {
        calibration.transaction = MakeOpTxContext(*spec.op_tx_shape, calibration.script);
    }
    BenchSignatureChecker checker{fixture, calibration.transaction.get()};
    const EvalOutcome outcome{Evaluate(calibration, checker)};
    if (!outcome.success || outcome.error != SCRIPT_ERR_OK) {
        throw std::runtime_error(strprintf("one-sequence calibration failed for %s: %s",
                                           spec.name, ScriptErrorString(outcome.error)));
    }
    const uint64_t suffix_cost{
        InitialProducerCost(stack) + CandidateCleanupCost(stack, cleanup_items) +
        varops::COST_BASE + varops::COST_SCALAR_WRITE +
        varops::COST_PREPARE_FIXED + varops::COST_PREPARE_BYTE * 8 +
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
                varops::COST_BASE + varops::COST_SCALAR_WRITE +
                varops::COST_PREPARE_FIXED + varops::COST_PREPARE_BYTE * 8 +
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
    if (spec.op_tx_shape) {
        materialized.transaction = MakeOpTxContext(*spec.op_tx_shape, materialized.script);
    }
    if (spec.repeat_evaluations) {
        BenchSignatureChecker checker{fixture, materialized.transaction.get()};
        const EvalOutcome once{Evaluate(materialized, checker, budget_ceiling)};
        if (!once.success || once.varops_consumed == 0) {
            throw std::runtime_error(strprintf("%s: repeated evaluation needs one successful charged evaluation", spec.name));
        }
        // Spend the budget, unless one evaluation is cheap: then time enough
        // evaluations to spend 1% of it, and the full-budget sample extrapolates.
        const uint64_t initial_cost{InitialProducerCost(materialized.initial_stack)};
        const uint64_t full{budget_ceiling / once.varops_consumed};
        const uint64_t charged{std::max<uint64_t>(1, once.varops_consumed - std::min(initial_cost, once.varops_consumed))};
        const uint64_t sampled{std::max<uint64_t>(MAX_UNSCALED_EVALUATIONS,
                                                  (MIN_FULL_VAROPS_SAMPLE_BUDGET + charged - 1) / charged)};
        materialized.evaluations = std::max<uint64_t>(1, std::min(full, sampled));
        materialized.saturation = strprintf("%s/%u-evaluations",
                                            materialized.evaluations == full ? "varops-budget" : "sampled",
                                            materialized.evaluations);
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
                     options.op_tx_shape, options.repeat_evaluations});
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
                             const CScript& sequence, StackFactory factory, CaseOptions options = {})
{
    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            case_label, shape, pattern, sequence, factory, options);
    AddCase(specs, opcode, HeadlineRole::COMMON_V2,
            std::move(case_label), std::move(shape), std::move(pattern), sequence, std::move(factory), std::move(options));
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
    case OP_1ADD: return legacy_sizing::AddCost(size, 1);
    case OP_1SUB: return legacy_sizing::SubCost(size, 1);
    case OP_NOT:
    case OP_0NOTEQUAL: return legacy_sizing::CompareZeroCost(size);
    case OP_INVERT: return legacy_sizing::InvertCost(size);
    case OP_2MUL: return legacy_sizing::TwoMulCost(size);
    case OP_2DIV: return legacy_sizing::TwoDivCost(size);
    case OP_RIPEMD160:
    case OP_SHA1:
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256: return size * legacy_sizing::COST_HASH;
    default: throw std::runtime_error("unsupported one-to-one opcode");
    }
}

static uint64_t OneToOneSequenceCost(opcodetype opcode, size_t size, bool three_way,
                                     std::string_view pattern = {})
{
    const uint64_t transforms{three_way ? 3U : 1U};
    // Independently count complete logical-opcode formulas from whole-varop terms.
    const uint64_t copy_opcode{varops::COST_BASE + transforms *
        (varops::COST_COPY_FIXED + varops::COST_COPY_BYTE * varops::WordSpan(size))};
    switch (opcode) {
    case OP_NOT:
    case OP_0NOTEQUAL: {
        const bool input_nonzero{pattern != "zero"};
        const size_t output_size{(opcode == OP_NOT ? !input_nonzero : input_nonzero) ? 1U : 0U};
        const uint64_t target{varops::COST_BASE + varops::COST_PREPARE_FIXED +
            varops::COST_PREPARE_BYTE * varops::WordSpan(size) +
            varops::COST_READ_FIXED + varops::COST_READ * varops::WordSpan(size) +
            varops::COST_SCALAR_OUTPUT};
        return copy_opcode + transforms * (target + CandidateDropCost(output_size));
    }
    case OP_1ADD:
    case OP_1SUB: {
        const uint64_t words{varops::WordSpan(size)};
        const bool low{pattern == "padded-low" || pattern == "one-low"};
        const size_t output_size{low ? (opcode == OP_1SUB ? 0U : 1U) :
                                      (opcode == OP_1SUB && pattern == "late-nonzero" && size != 0 ? size - 1 : size)};
        const uint64_t output_words{varops::WordSpan(output_size)};
        const uint64_t target{varops::COST_BASE + varops::COST_PREPARE_FIXED +
            varops::COST_PREPARE_BYTE * words + varops::COST_ARITH_FIXED +
            varops::COST_ARITH_BYTE * words + varops::COST_OUTPUT_FIXED +
            varops::COST_OUTPUT_BYTE * output_words};
        return copy_opcode + transforms * (target + CandidateDropCost(output_size));
    }
    case OP_INVERT:
    case OP_2MUL:
    case OP_2DIV: {
        const uint64_t words{varops::WordSpan(size)};
        const bool low{pattern == "padded-low" || pattern == "one-low"};
        const size_t output_size{
            low && opcode == OP_2DIV ? 0U :
            low && opcode == OP_2MUL ? 1U :
            opcode == OP_2DIV && pattern == "late-nonzero" && size != 0 ? size - 1 : size};
        const uint64_t output_words{varops::WordSpan(output_size)};
        const uint64_t target{varops::COST_BASE + varops::COST_PREPARE_FIXED +
            varops::COST_PREPARE_BYTE * words + varops::COST_BIT_FIXED +
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
        uint64_t hash_q{0};
        IndependentAdd(hash_q, varops::COST_BASE);
        if (opcode == OP_SHA1) {
            IndependentAdd(hash_q, varops::COST_H1_FIXED);
            IndependentAdd(hash_q, varops::COST_H1_BYTE, IndependentHashSpan(size));
        } else if (opcode == OP_RIPEMD160) {
            IndependentAdd(hash_q, varops::COST_H160_FIXED);
            IndependentAdd(hash_q, varops::COST_H160_BYTE, IndependentHashSpan(size));
        } else if (opcode == OP_SHA256) {
            IndependentAdd(hash_q, varops::COST_SHA256_FIXED);
            IndependentAdd(hash_q, varops::COST_SHA256_BYTE, IndependentHashSpan(size));
        } else if (opcode == OP_HASH160) {
            IndependentAdd(hash_q, varops::COST_SHA256_FIXED);
            IndependentAdd(hash_q, varops::COST_SHA256_BYTE, IndependentHashSpan(size));
            IndependentAdd(hash_q, varops::COST_H160_FIXED);
            IndependentAdd(hash_q, varops::COST_H160_BYTE, IndependentHashSpan(32));
        } else {
            IndependentAdd(hash_q, varops::COST_SHA256_FIXED, 2);
            IndependentAdd(hash_q, varops::COST_SHA256_BYTE, IndependentHashSpan(size) + IndependentHashSpan(32));
        }
        IndependentAdd(hash_q, varops::COST_COPY_FIXED);
        IndependentAdd(hash_q, varops::COST_COPY_BYTE, varops::WordSpan(output_size));
        const uint64_t hash_opcode{hash_q};
        return copy_opcode + transforms * (hash_opcode + CandidateDropCost(output_size));
    }
    default:
        break;
    }
    return transforms * size * legacy_sizing::COST_COPYING +
           transforms * OneToOneTargetCost(opcode, size);
}

static uint64_t TruthCopyCost(size_t size) { return size * legacy_sizing::COST_COPYING + legacy_sizing::CompareZeroCost(size); }
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
                        legacy_sizing::AddCost(1, size) + (1 + size) * legacy_sizing::COST_COPYING);
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
        // Equal padded operands scan fully in the comparison and again when the
        // result is trimmed; the small sizes are where READ's rate is tightest.
        for (size_t size : {120U, 255U, 511U, 1250U, 4097U}) {
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "binary-preserve", FormatBytes(size) + "x" + FormatBytes(size), "equal-padded-low",
                    sequence, FixedStack({PaddedNumber(1, size), PaddedNumber(1, size)}));
        }
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
    // Grow the stack to its item limit in one execution, then drop the
    // copies. Later repetitions in the same execution would reuse the stack's
    // capacity, so each execution repeats this only once.
    const auto add_growth_case = [&](CScript step, size_t pushed, size_t initial_items) {
        const size_t steps{(MAX_TAPSCRIPT_V2_STACK_SIZE - initial_items) / pushed};
        CScript sequence;
        for (size_t i{0}; i < steps; ++i) sequence.insert(sequence.end(), step.begin(), step.end());
        for (size_t i{0}; i < steps * pushed / 2; ++i) sequence << OP_2DROP;
        if (steps * pushed % 2) sequence << OP_DROP;
        CaseOptions options;
        options.max_repetitions = 1;
        options.sequence_label = strprintf("%ux(%s)+drops", steps, SequenceOpcodeNames(step));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "stack-growth",
                strprintf("%u-items", initial_items + steps * pushed), "1B-items", std::move(sequence),
                FixedStack(std::vector<valtype>(initial_items, PatternBytes(1, "one-low"))), options);
    };
    switch (opcode) {
    case OP_DUP: add_growth_case(Ops({OP_DUP}), 1, 1); break;
    case OP_2DUP: add_growth_case(Ops({OP_2DUP}), 2, 2); break;
    case OP_3DUP: add_growth_case(Ops({OP_3DUP}), 3, 3); break;
    case OP_OVER: add_growth_case(Ops({OP_OVER}), 1, 2); break;
    case OP_2OVER: add_growth_case(Ops({OP_2OVER}), 2, 4); break;
    case OP_TUCK: add_growth_case(Ops({OP_TUCK}), 1, 2); break;
    case OP_PICK: add_growth_case(Ops({OP_0, OP_PICK}), 1, 1); break;
    default: break;
    }
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
        // At MOVE(k) = 180 + 19k a repetition costs about 3,500 + 19k varops, so with
        // 1,500 items the full budget binds before the 4 MB script limit (30,000 per repetition).
        deep_stack_options.expected_saturation = SaturationExpectation::VAROPS_BUDGET;
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "deep-stack", "1500x4B", "dense",
                Ops({OP_DEPTH, OP_1SUB, OP_ROLL}),
                FixedStack(std::vector<valtype>(1500, PatternBytes(4, "dense"))),
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
    if (opcode == OP_DUP) {
        // Each copy is released before the next one is made. Allocators that return
        // freed blocks to the operating system, such as the Windows heap above its
        // decommit and direct-allocation thresholds, then fault in fresh pages for
        // every copy; others reuse the block. The sizes straddle those thresholds.
        for (size_t size : {16384U, 16385U, 32768U, 65536U, 65537U, 131072U, 131073U, 262144U,
                            262145U, 520192U, 524288U, 1048576U, 2097152U}) {
            AddCase(specs, opcode, HeadlineRole::NEW_GSR, "copy-release", FormatBytes(size), "late-nonzero",
                    Ops({OP_DUP, OP_DROP}), FixedStack({PatternBytes(size, "late-nonzero")}));
        }
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
    // Other inputs and outputs supply the selected data, so it does not change
    // when the benchmark script is repeated to reach the varops boundary. Every
    // case collates its result and maximizes one kind of charged unit per weight.
    constexpr int32_t TARGET_WEIGHT{MAX_BLOCK_WEIGHT - 10'000};
    // Weight left for the repeated script when records fill the transaction.
    constexpr int32_t SCRIPT_RESERVE{12'000};
    const auto base_weight = [](const OpTxShape& shape) {
        return GetTransactionWeight(CTransaction{EmptyWitnessTransaction(shape, {})});
    };
    const auto add = [&](std::string label, std::string shape_label, const valtype& selector,
                         bool single_input_scope, OpTxShape shape) {
        const int32_t weight{base_weight(shape)};
        if (weight + 11 >= TARGET_WEIGHT) throw std::runtime_error("OP_TX fixture exceeds weight target");
        // A single-input scope pops its index operand, so the sequence duplicates both.
        const CScript sequence{single_input_scope ? Ops({OP_2DUP, OP_TX, OP_DROP}) : Ops({OP_DUP, OP_TX, OP_DROP})};
        CaseOptions options{};
        options.cleanup_items = single_input_scope ? 2 : 1;
        options.op_tx_shape = shape;
        // Include the script in the transaction's witness weight. Leave eight
        // weight units for the script-length CompactSize growth and rounding.
        options.max_repetitions = (TARGET_WEIGHT - weight - 8 - 3) / sequence.size();
        options.saturation_hint = "transaction-weight";
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, std::move(label), std::move(shape_label), "other-input",
                sequence, FixedStack(single_input_scope ? std::vector<valtype>{valtype{1}, selector} :
                                                          std::vector<valtype>{selector}),
                std::move(options));
    };
    // Records that fill the transaction beside the script's reserve.
    const auto fill = [&](int32_t record_weight, OpTxShape shape) {
        return static_cast<size_t>((TARGET_WEIGHT - SCRIPT_RESERVE - base_weight(shape)) / record_weight);
    };
    // Input 0's witness: witness item, selector, script and control block.
    constexpr size_t SCRIPT_WITNESS_ITEMS{4};
    // Input 1's witness: the empty items, an immediate-success leaf and its control block.
    constexpr size_t SOURCE_EXTRA_ITEMS{2};

    for (size_t empty_items : {256U, 8192U, 30000U}) {
        // Input 1's witness items: a count and every item.
        add("collated-empty-witness", strprintf("%u-empty-items", empty_items),
            valtype{0, 1, 0, 0x30, 0x80, 0}, true,
            {.empty_items = empty_items, .units = 1 + empty_items + SOURCE_EXTRA_ITEMS});
    }
    {
        // TX_WEIGHT: one value; scans every input, every witness item and every output.
        constexpr size_t empty_items{30000};
        add("weight-scan", strprintf("%u-empty-items", empty_items), valtype{0, 1 | 0x08, 0, 0, 0, 0}, false,
            {.empty_items = empty_items,
             .units = 1 + (1 + SCRIPT_WITNESS_ITEMS) + (1 + empty_items + SOURCE_EXTRA_ITEMS) + 1});
    }
    // An empty output serializes to nine bytes.
    const size_t outputs{fill(9 * WITNESS_SCALE_FACTOR, {})};
    // Both total amounts: two values; scans every input and output.
    add("amount-scan", strprintf("%u-outputs", outputs + 1), valtype{0, 1 | 0x20 | 0x80, 0, 0, 0, 0}, false,
        {.extra_outputs = outputs, .units = 2 + 2 + outputs + 1});
    // Every output's amount and scriptPubKey.
    add("outputs", strprintf("%u-outputs", outputs + 1), valtype{0, 1, 0, 0x02, 0, 0x03}, false,
        {.extra_outputs = outputs, .units = 2 * (outputs + 1)});
    // Every input's fields other than its witness items, which would include the
    // growing script: seven values each. An input serializes to 41 bytes plus its
    // empty witness stack.
    const size_t inputs{fill(41 * WITNESS_SCALE_FACTOR + 1, {})};
    add("inputs", strprintf("%u-inputs", inputs + 2), valtype{0, 1, 0, 0x20, 0x7f, 0}, false,
        {.extra_inputs = inputs, .units = 7 * (inputs + 2)});
}

//! The benchmark key (secret 1): its x-only public key and a BIP 340 signature
//! over an arbitrary-length message, for OP_CHECKSIGFROMSTACK.
static std::pair<valtype, valtype> SignedMessage(std::span<const unsigned char> message)
{
    struct ContextDeleter {
        void operator()(secp256k1_context* ctx) const { secp256k1_context_destroy(ctx); }
    };
    const std::unique_ptr<secp256k1_context, ContextDeleter> ctx{secp256k1_context_create(SECP256K1_CONTEXT_NONE)};
    std::array<unsigned char, 32> secret{};
    secret.back() = 1;
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly;
    valtype pubkey(32), signature(64);
    static const unsigned char empty{0};
    if (!ctx || !secp256k1_keypair_create(ctx.get(), &keypair, secret.data()) ||
        !secp256k1_keypair_xonly_pub(ctx.get(), &xonly, nullptr, &keypair) ||
        !secp256k1_xonly_pubkey_serialize(ctx.get(), pubkey.data(), &xonly) ||
        !secp256k1_schnorrsig_sign_custom(ctx.get(), signature.data(), message.empty() ? &empty : message.data(),
                                          message.size(), &keypair, nullptr)) {
        throw std::runtime_error("failed to sign a benchmark message");
    }
    return {std::move(pubkey), std::move(signature)};
}

static void AddExtendedPrimitiveCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    if (opcode == OP_CHECKSIGFROMSTACK) {
        // Valid signatures verify completely. OP_3DUP doubles the stack, which bounds
        // the message below the element limit.
        const size_t max_message{MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE / 2 - 96};
        for (const size_t size : {size_t{0}, size_t{32}, size_t{520}, size_t{4096}, size_t{65536},
                                  size_t{1048576}, max_message}) {
            const valtype message(size, 0x42);
            auto [pubkey, signature]{SignedMessage(message)};
            AddCase(specs, opcode, HeadlineRole::NEW_GSR, "csfs-valid", "64B+" + FormatBytes(size) + "+32B",
                    "valid-signature", Ops({OP_3DUP, OP_CHECKSIGFROMSTACK, OP_DROP}),
                    FixedStack({std::move(signature), message, std::move(pubkey)}));
        }
    } else if (opcode == OP_TWEAKADD) {
        const auto [pubkey, signature]{SignedMessage({})};
        valtype tweak(32, 0);
        tweak.back() = 1;
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "tweakadd-valid", "32B+32B", "tweak-one",
                Ops({OP_2DUP, OP_TWEAKADD, OP_DROP}), FixedStack({tweak, pubkey}));
    } else if (opcode == OP_BYTEREV) {
        // The value is reversed in place, so every repetition does the same work.
        for (const size_t size : {size_t{0}, size_t{1}, size_t{7}, size_t{8}, size_t{9}, size_t{15}, size_t{16},
                                  size_t{17}, size_t{33}, size_t{520}, size_t{4096}, size_t{65536}, size_t{1048576},
                                  size_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE}}) {
            AddCase(specs, opcode, HeadlineRole::NEW_GSR, "byterev-in-place", FormatBytes(size), "alternating",
                    Ops({OP_BYTEREV}), FixedStack({PatternBytes(size, "alternating")}));
        }
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
    const uint64_t left_words{varops::WordSpan(left)};
    const uint64_t right_words{varops::WordSpan(right)};
    const uint64_t rows{std::max(left_words, right_words) / 8};
    const uint64_t row_limbs{std::min(left_words, right_words) / 8};
    const size_t output_size{left + right};
    const uint64_t storage{varops::WriteCost(left_words + right_words) - varops::WriteCost(varops::WordSpan(output_size))};
    return storage + 3 * varops::COST_BASE + 2 * varops::COST_COPY_FIXED +
           varops::COST_COPY_BYTE * (left_words + right_words) +
           2 * varops::COST_PREPARE_FIXED +
           varops::COST_PREPARE_BYTE * (left_words + right_words) +
           varops::MulCost(rows, row_limbs) +
           varops::COST_OUTPUT_FIXED +
           varops::COST_OUTPUT_BYTE * varops::WordSpan(output_size);
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
    const uint64_t dividend_words{varops::WordSpan(dividend)};
    const uint64_t divisor_words{varops::WordSpan(divisor)};
    const uint64_t dividend_limbs{dividend_words / 8};
    const uint64_t divisor_limbs{divisor_words / 8};
    const uint64_t steps{IndependentDivSteps(dividend_limbs, divisor_limbs)};
    // OP_2DUP, target, OP_DROP.  The output is at most the dividend size;
    // the dense benchmark fixtures used here retain that padded width.
    return 3 * varops::COST_BASE + 2 * varops::COST_COPY_FIXED +
           varops::COST_COPY_BYTE * (dividend_words + divisor_words) +
           2 * varops::COST_PREPARE_FIXED +
           varops::COST_PREPARE_BYTE * (dividend_words + divisor_words) +
           2 * varops::COST_READ_FIXED + varops::COST_READ * (dividend_words + divisor_words) +
           varops::COST_DIV_FIXED + varops::COST_DIV_STEP * steps +
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
    // Build a live operand pool in Script, then consume it in reverse creation
    // order. Unlike host-prepared diagnostics, all duplication work is funded.
    for (size_t count : {256U, 4096U, 6000U}) {
        valtype divisor{seeded(64 * 8, 22)};
        divisor.back() = 0x40;
        CScript batched;
        for (size_t i = 0; i < count; ++i) batched << OP_2DUP;
        for (size_t i = 0; i < count; ++i) batched << opcode << OP_DROP;
        CaseOptions options;
        options.sequence_label = strprintf("%uxOP_2DUP+%ux(%s+OP_DROP)", count, count, OpcodeName(opcode));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "divmod-batched-pool",
                strprintf("520Bx512B/%u-pairs", count), "wide-normalization-top-clear-seed17",
                std::move(batched), FixedStack({seeded(65 * 8, 17), std::move(divisor)}), options);
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
    // Zero padding changes encoded lengths but not the trimmed division work.
    for (const size_t size : {16384U, 65536U}) {
        valtype padded_divisor{DivisorTopClear(size / 2)};
        padded_divisor.resize(size, 0);
        add(PatternBytes(size, "dense"), std::move(padded_divisor),
            FormatBytes(size) + "x" + FormatBytes(size), "divisor-half-zero-padded");
        valtype padded_dividend{PatternBytes(size / 2, "dense")};
        padded_dividend.resize(size, 0);
        add(std::move(padded_dividend), DivisorTopClear(size / 4),
            FormatBytes(size) + "x" + FormatBytes(size / 4), "dividend-half-zero-padded");
    }

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

    // Equal-size operands take two DIV rows, so the candidate cost stays far
    // below the budget; the cap keeps two copies within the 8 MB stack limit.
    const size_t largest{LargestAffordable([opcode](size_t size) { return DivModSequenceCost(opcode, size, size); },
                                           1'000'000)};
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
    const uint64_t copy_cost{(size + shift_size) * legacy_sizing::COST_COPYING};
    const uint64_t prebytes{shift / 8};
    if (opcode == OP_RSHIFT) {
        return copy_cost + legacy_sizing::LengthConversionCost(shift_size) +
               (prebytes < size ? size - prebytes : 0) * legacy_sizing::COST_COPYING;
    }
    if (opcode != OP_LSHIFT) throw std::runtime_error("unsupported shift opcode");
    return copy_cost + legacy_sizing::LengthConversionCost(shift_size) + prebytes * legacy_sizing::COST_FAST +
           size * legacy_sizing::COST_COPYING +
           (shift % 8 == 0 ? 0 : legacy_sizing::UnalignedUpShiftCost(size, prebytes));
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

static uint64_t TimelockSequenceCost(size_t size) { return legacy_sizing::LengthConversionCost(size); }

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
        sequence.push_back(static_cast<unsigned char>(body.size()));
    } else if (body.size() <= 0xffff) {
        sequence.push_back(0xfd);
        sequence.push_back(static_cast<unsigned char>(body.size() & 0xff));
        sequence.push_back(static_cast<unsigned char>(body.size() >> 8));
    } else {
        // CScript sizes are 32-bit, so the four-byte CompactSize form always fits.
        sequence.push_back(0xfe);
        for (unsigned int shift : {0U, 8U, 16U, 24U}) {
            sequence.push_back(static_cast<unsigned char>((body.size() >> shift) & 0xff));
        }
    }
    sequence.insert(sequence.end(), body.begin(), body.end());
    for (size_t call{0}; call < calls; ++call) {
        sequence << OP_CALLMACRO;
        sequence.push_back(0);
    }
    return sequence;
}

static void AppendMacroCompactSize(CScript& script, uint64_t value)
{
    if (value < 253) {
        script.push_back(static_cast<unsigned char>(value));
        return;
    }
    const unsigned int width{value <= 0xffff ? 2U : value <= 0xffffffff ? 4U :
                                                                          8U};
    script.push_back(width == 2 ? 0xfd : width == 4 ? 0xfe :
                                                      0xff);
    for (unsigned int i{0}; i < width; ++i)
        script.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xff));
}

static void AppendMacroDefinition(CScript& script, const CScript& body)
{
    script << OP_MACRO;
    AppendMacroCompactSize(script, body.size());
    script.insert(script.end(), body.begin(), body.end());
}

static void AppendMacroReference(CScript& script, uint64_t index)
{
    script << OP_CALLMACRO;
    AppendMacroCompactSize(script, index);
}

static size_t MacroReferenceSize(uint64_t index)
{
    return 1 + (index < 253 ? 1 : index <= 0xffff ? 3 :
                                                    5);
}

/** Number of references to a body that keep the unrolled script within its limit. */
static size_t UnrolledCalls(const CScript& body)
{
    return (MAX_TAPSCRIPT_V2_UNROLLED_SIZE - UNROLLED_MARGIN) / body.size();
}

/** Unrolling charge of one reference to a body without references, including
 *  the WRITE bytes it adds to the unrolled script. */
static uint64_t MacroCallUnrollCost(const CScript& body)
{
    uint64_t instructions{0};
    CScript::const_iterator pc{body.begin()};
    opcodetype opcode;
    while (pc < body.end()) {
        if (!body.GetOp(pc, opcode)) throw std::runtime_error("macro benchmark body does not decode");
        ++instructions;
    }
    return (instructions + 1) * varops::COST_MACRO_UNROLL + varops::COST_COPY_BYTE * varops::WordSpan(body.size());
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
                strprintf("%uB-body/%u-calls/%s", body.size(), calls, shape),
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
        const size_t body_calls{UnrolledCalls(body)};
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
    add(push_body, UnrolledCalls(push_body), 0,
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
            (3 + stack_items + 1) * varops::COST_BASE +
            varops::COST_PREPARE_FIXED + varops::COST_PREPARE_BYTE * 8 +
            varops::COST_READ_FIXED + varops::COST_READ * 8};
        const uint64_t call_cost{MacroCallUnrollCost(body) + body_cost};
        const size_t calls{std::min(UnrolledCalls(body), static_cast<size_t>((TOTAL_VAROPS_BUDGET - fixed_cost) / call_cost))};
        add_with_stack(body, calls,
                       std::vector<valtype>(stack_items, PatternBytes(item_size, "late-nonzero")),
                       "function-slow-" + OpcodeName(target), "3x519B", "late-nonzero",
                       "varops-budget");
    }

    const CScript div_body{RepeatedSequenceBody(Ops({OP_2DUP, OP_DIV, OP_DROP}), 255)};
    add_with_stack(div_body, UnrolledCalls(div_body),
                   {PatternBytes(17, "dense"), DivisorTopClear(9)},
                   "function-slow-OP_DIV", "17Bx9B", "normalization-top-clear", "function-body-bytes");

    // Unrolling calibration. Each script is a declaration prefix followed by
    // references repeated until the script bytes, the unrolled bytes or the
    // varops budget saturate. call_cost is the unrolling charge of one
    // reference plus the execution charge of what it unrolls to.
    const auto add_references = [&](CScript prefix, uint64_t index, size_t unrolled_size, uint64_t call_cost,
                                    bool inactive, std::string case_label, std::string shape, std::string pattern) {
        // Leave room for the wrapper and the harness cleanup suffix.
        const size_t wrapper_size{(inactive ? 3U : 0U) + 16U};
        const size_t script_calls{(SCRIPT_BYTES - prefix.size() - wrapper_size) / MacroReferenceSize(index)};
        const size_t unrolled_calls{unrolled_size == 0 ? script_calls : static_cast<size_t>((MAX_TAPSCRIPT_V2_UNROLLED_SIZE - UNROLLED_MARGIN) / unrolled_size)};
        const size_t budget_calls{static_cast<size_t>(TOTAL_VAROPS_BUDGET / call_cost)};
        const size_t calls{std::min({script_calls, unrolled_calls, budget_calls})};
        CScript sequence{std::move(prefix)};
        if (inactive) sequence << OP_0 << OP_IF;
        for (size_t call{0}; call < calls; ++call)
            AppendMacroReference(sequence, index);
        if (inactive) sequence << OP_ENDIF;
        const std::string saturation{calls == budget_calls ? "varops-budget" :
                                     calls == unrolled_calls ? "unrolled-bytes" :
                                                               "script-bytes"};
        CaseOptions options{FixedCase(SCRIPT_ERR_OK, 1, 1, saturation)};
        options.sequence_label = strprintf("%s+%u_CALLS", shape, calls);
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, std::move(case_label),
                strprintf("%s/%u-calls", shape, calls), std::move(pattern), std::move(sequence),
                FixedStack({PatternBytes(1, "one-low")}), std::move(options));
    };
    for (const size_t body_size : {1U, 16U, 256U}) {
        // Inactive unrolled instructions are paid for only by the unrolling charge.
        const CScript body{RepeatedSequenceBody(Ops({OP_NOP}), body_size)};
        CScript prefix;
        AppendMacroDefinition(prefix, body);
        add_references(std::move(prefix), 0, body.size(), MacroCallUnrollCost(body),
                       /*inactive=*/true, "macro-unroll-nop", strprintf("%uNOP", body_size), "inactive");
    }
    {
        // A push body costs the same to unroll whatever its payload size; this
        // case measures the uncharged payload copy.
        constexpr size_t push_size{1'000'000};
        const CScript body{CScript{} << valtype(push_size, 0x42)};
        CScript prefix;
        AppendMacroDefinition(prefix, body);
        add_references(std::move(prefix), 0, body.size(), MacroCallUnrollCost(body),
                       /*inactive=*/true, "macro-unroll-push", FormatBytes(push_size), "inactive");
    }
    // One script unrolls at most 4 MB, so a single evaluation cannot spend the budget
    // on unrolling. Repeated evaluations share one budget, as inputs of one transaction.
    const auto add_repeated = [&](const CScript& body, std::string case_label, std::string shape) {
        CScript prefix;
        AppendMacroDefinition(prefix, body);
        const size_t script_calls{(SCRIPT_BYTES - prefix.size() - 19) / MacroReferenceSize(0)};
        const size_t calls{std::min(script_calls, static_cast<size_t>((MAX_TAPSCRIPT_V2_UNROLLED_SIZE - UNROLLED_MARGIN) / body.size()))};
        CScript sequence{std::move(prefix)};
        sequence << OP_0 << OP_IF;
        for (size_t call{0}; call < calls; ++call) AppendMacroReference(sequence, 0);
        sequence << OP_ENDIF;
        CaseOptions options{FixedCase(SCRIPT_ERR_OK, 1, 1, "repeated-evaluations")};
        options.sequence_label = strprintf("%s+%u_CALLS", shape, calls);
        options.repeat_evaluations = true;
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, std::move(case_label),
                strprintf("%s/%u-calls", shape, calls), "inactive", std::move(sequence),
                FixedStack({PatternBytes(1, "one-low")}), std::move(options));
    };
    for (const size_t body_size : {1U, 16U, 256U}) {
        add_repeated(RepeatedSequenceBody(Ops({OP_NOP}), body_size), "macro-unroll-nop-repeated",
                     strprintf("%uNOP", body_size));
    }
    for (const size_t push_size : {32U, 520U, 2800U, 65536U, 1'000'000U}) {
        add_repeated(CScript{} << valtype(push_size, 0x42), "macro-unroll-push-repeated", FormatBytes(push_size));
    }
    for (const size_t depth : {256U, 16'384U}) {
        // Body i references body i-1; body 0 is empty. Each call visits depth
        // references and unrolls to nothing.
        CScript prefix;
        AppendMacroDefinition(prefix, CScript{});
        for (size_t i{1}; i < depth; ++i) {
            CScript body;
            AppendMacroReference(body, i - 1);
            AppendMacroDefinition(prefix, body);
        }
        add_references(std::move(prefix), depth - 1, 0, depth * varops::COST_MACRO_UNROLL,
                       /*inactive=*/false, "macro-ref-chain", strprintf("depth-%u", depth), "empty-leaf");
    }
    {
        // Body i references body i-1 twice; each call visits 2^(levels+1)-1 references.
        constexpr size_t levels{20};
        CScript prefix;
        AppendMacroDefinition(prefix, CScript{});
        for (size_t i{1}; i <= levels; ++i) {
            CScript body;
            AppendMacroReference(body, i - 1);
            AppendMacroReference(body, i - 1);
            AppendMacroDefinition(prefix, body);
        }
        add_references(std::move(prefix), levels, 0, ((uint64_t{2} << levels) - 1) * varops::COST_MACRO_UNROLL,
                       /*inactive=*/false, "macro-ref-fanout", strprintf("levels-%u", levels), "empty-leaf");
    }

    // Cheap sustaining sequences found by the per-opcode calibration probes.
    // Preserve the initial values without unnecessary per-iteration copies.
    const auto add_probe = [&](std::string label, const CScript& sequence,
                               std::vector<valtype> stack, std::string shape,
                               opcodetype target = OP_INVALIDOPCODE) {
        const CScript body{RepeatedSequenceBody(sequence, (256 / sequence.size()) * sequence.size())};
        size_t calls{UnrolledCalls(body)};
        if (target == OP_SHA1 || target == OP_RIPEMD160 || target == OP_SHA256 ||
            target == OP_HASH160 || target == OP_HASH256) {
            const size_t digest_size{target == OP_SHA1 || target == OP_RIPEMD160 || target == OP_HASH160 ? 20U : 32U};
            const uint64_t sequence_cost{
                sequence.size() == 1 ? CandidateHashOpcodeCost(target, digest_size) :
                OneToOneSequenceCost(target, digest_size, false, "dense")};
            const uint64_t body_cost{body.size() / sequence.size() * sequence_cost};
            const uint64_t call_cost{MacroCallUnrollCost(body) + body_cost};
            calls = std::min(calls, static_cast<size_t>(TOTAL_VAROPS_BUDGET / call_cost));
        }
        // Every probe preserves its stack, so one extra call adds a fixed charge.
        // Price rises must not push the body-byte call count past the budget.
        const auto consumed = [&](size_t count) {
            CScript script{FunctionCalls(body, count)};
            script.insert(script.end(), stack.size(), static_cast<unsigned char>(OP_DROP));
            script << OP_1;
            ValtypeStack eval_stack{stack};
            ScriptExecutionData execdata;
            BaseSignatureChecker checker;
            varops::Budget budget{TOTAL_VAROPS_BUDGET};
            ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
            if (!EvalTapscriptV2(eval_stack, script, BENCH_SCRIPT_VERIFY_FLAGS, checker, execdata, budget, &error)) {
                throw std::runtime_error("function probe calibration failed for " + label + ": " + ScriptErrorString(error));
            }
            return TOTAL_VAROPS_BUDGET - budget.Remaining();
        };
        const uint64_t one_call{consumed(1)};
        const uint64_t call_cost{consumed(2) - one_call};
        const size_t budget_calls{static_cast<size_t>((TOTAL_VAROPS_BUDGET - (one_call - call_cost)) / call_cost)};
        const bool budget_limited{budget_calls < calls};
        calls = std::min(calls, budget_calls);
        add_with_stack(body, calls,
                       std::move(stack), "function-probe-" + label, std::move(shape),
                       "calibration-worst-pattern", budget_limited ? "varops-budget" : "function-body-bytes");
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
        add_with_stack(body, UnrolledCalls(body), {},
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
            AddPreAndV2Cases(specs, opcode, "upgradable-nops", "no-operands", "executed",
                             Ops({OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10}), FixedStack({}));
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
    case OP_IF: {
        AddPreAndV2Cases(specs, opcode, "executed-if", "1B", "true-branch", Ops({OP_1, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        AddPreAndV2Cases(specs, opcode, "skipped-if", "0B", "false-branch", Ops({OP_0, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        // Maximum-size scripts of control instructions, each paying only BASE, and of
        // skipped instructions, which weight alone funds. One copy fills the script;
        // the final OP_1 takes the last byte.
        const size_t body{SCRIPT_BYTES - 1 - 3};
        const auto wrap = [](opcodetype condition, const CScript& inner) {
            CScript script;
            script << condition << OP_IF;
            script.insert(script.end(), inner.begin(), inner.end());
            script << OP_ENDIF;
            return script;
        };
        const auto repeat = [](const CScript& unit, size_t count) {
            CScript script;
            script.reserve(unit.size() * count);
            for (size_t i{0}; i < count; ++i) script.insert(script.end(), unit.begin(), unit.end());
            return script;
        };
        // Spelled-out names of these scripts would be megabytes long.
        const auto labeled = [](std::string label) {
            CaseOptions options;
            options.sequence_label = std::move(label);
            return options;
        };
        AddPreAndV2Cases(specs, opcode, "else-toggle", FormatBytes(body) + "-script", "alternating-branches",
                         wrap(OP_1, repeat(Ops({OP_ELSE}), body)), FixedStack({}),
                         labeled(strprintf("OP_1+OP_IF+%uxOP_ELSE+OP_ENDIF", body)));
        AddPreAndV2Cases(specs, opcode, "inactive-if-pairs", FormatBytes(body) + "-script", "flat",
                         wrap(OP_0, repeat(Ops({OP_IF, OP_ENDIF}), body / 2)), FixedStack({}),
                         labeled(strprintf("OP_0+OP_IF+%ux(OP_IF+OP_ENDIF)+OP_ENDIF", body / 2)));
        CScript nested{repeat(Ops({OP_IF}), body / 2)};
        const CScript closing{repeat(Ops({OP_ENDIF}), body / 2)};
        nested.insert(nested.end(), closing.begin(), closing.end());
        AddPreAndV2Cases(specs, opcode, "inactive-if-nested", FormatBytes(body) + "-script", strprintf("depth-%u", body / 2),
                         wrap(OP_0, nested), FixedStack({}),
                         labeled(strprintf("OP_0+OP_IF+%uxOP_IF+%uxOP_ENDIF+OP_ENDIF", body / 2, body / 2)));
        AddPreAndV2Cases(specs, opcode, "skipped-nops", FormatBytes(body) + "-script", "uncharged",
                         wrap(OP_0, repeat(Ops({OP_NOP}), body)), FixedStack({}),
                         labeled(strprintf("OP_0+OP_IF+%uxOP_NOP+OP_ENDIF", body)));
        // v1 rejects skipped pushes above 520 bytes, so only v2 can skip one maximal literal.
        CScript literal;
        const size_t literal_size{body - 5};
        literal.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
        for (unsigned int shift : {0U, 8U, 16U, 24U}) literal.push_back(static_cast<unsigned char>((literal_size >> shift) & 0xff));
        literal.insert(literal.end(), literal_size, 0x42);
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "skipped-literal", FormatBytes(literal_size), "uncharged",
                wrap(OP_0, literal), FixedStack({}));
        break;
    }
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

static uint64_t WithinSequenceCost(size_t size) { return 3 * size * legacy_sizing::COST_COPYING + legacy_sizing::WithinCost(size, size, size); }

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
        add(AddExtendedPrimitiveCases, {OP_CHECKSIGFROMSTACK, OP_TWEAKADD, OP_BYTEREV});
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
    if (opcode >= OP_0 && opcode <= OP_PUSHDATA4) return {"BASE + COPY(n)", "BASE,COPY.fixed,COPY.byte"};
    switch (opcode) {
    case OP_NOP: case OP_IF: case OP_CODESEPARATOR:
        return {"BASE", "BASE"};
    case OP_TOALTSTACK: case OP_FROMALTSTACK:
        return {"BASE + MOVE(1)", "BASE,MOVE.fixed,MOVE.entry"};
    case OP_SWAP:
        return {"BASE + MOVE(2)", "BASE,MOVE.fixed,MOVE.entry"};
    case OP_ROT:
        return {"BASE + MOVE(3)", "BASE,MOVE.fixed,MOVE.entry"};
    case OP_2SWAP:
        return {"BASE + MOVE(4)", "BASE,MOVE.fixed,MOVE.entry"};
    case OP_2ROT:
        return {"BASE + MOVE(6)", "BASE,MOVE.fixed,MOVE.entry"};
    case OP_DROP: return {"BASE + RELEASE(W(x))", "BASE,RELEASE.fixed,RELEASE.byte"};
    case OP_2DROP: return {"BASE + RELEASE(W(x1)) + RELEASE(W(x2))", "BASE,RELEASE.fixed,RELEASE.byte"};
    case OP_NIP: return {"BASE + RELEASE(W(x1))", "BASE,RELEASE.fixed,RELEASE.byte"};
    case OP_VERIFY: return {"BASE + PREPARE(n) + READ(W(n))", "BASE,PREPARE.fixed,PREPARE.byte,READ"};
    case OP_DUP: case OP_2DUP: case OP_3DUP: case OP_OVER: case OP_2OVER: case OP_TUCK:
        return {"BASE + sum(COPY(n_i))", "BASE,COPY.fixed,COPY.byte"};
    case OP_IFDUP:
        return {"BASE + PREPARE(n) + READ(W(n)) + OUTPUT(n) + optional COPY(n)",
            "BASE,PREPARE.fixed,PREPARE.byte,READ,OUTPUT.fixed,OUTPUT.byte,COPY.fixed,COPY.byte"};
    case OP_DEPTH: case OP_SIZE: return {"BASE + OUTPUT(8)", "BASE,OUTPUT(8)"};
    case OP_PICK: return {"BASE + PREPARE(depth) + READ(W(depth)) + COPY(n)", "BASE,PREPARE.fixed,PREPARE.byte,READ,COPY.fixed,COPY.byte"};
    case OP_ROLL: return {"BASE + PREPARE(depth) + READ(W(depth)) + MOVE(entries)", "BASE,PREPARE.fixed,PREPARE.byte,READ,MOVE"};
    case OP_EQUAL: case OP_EQUALVERIFY:
        return {"BASE + conditional READ(W(n)) + OUTPUT(8)", "BASE,READ,OUTPUT(8)"};
    case OP_NOT: case OP_0NOTEQUAL:
        return {"BASE + PREPARE(n) + READ(W(n)) + OUTPUT(8)", "BASE,PREPARE.fixed,PREPARE.byte,READ,OUTPUT(8)"};
    case OP_1ADD: case OP_1SUB: case OP_ADD: case OP_SUB:
        return {"BASE + PREPARE(operands) + ARITH(W) + OUTPUT(out)",
            "BASE,PREPARE.fixed,PREPARE.byte,ARITH.fixed,ARITH.byte,OUTPUT.fixed,OUTPUT.byte"};
    case OP_BOOLAND: case OP_BOOLOR: case OP_NUMEQUAL: case OP_NUMEQUALVERIFY:
    case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN:
    case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_WITHIN:
        return {"BASE + PREPARE(operands) + READ(comparisons) + OUTPUT(8)", "BASE,PREPARE.fixed,PREPARE.byte,READ,OUTPUT(8)"};
    case OP_MIN: case OP_MAX:
        return {"BASE + PREPARE(operands) + READ(W) + OUTPUT(out) + RELEASE(max input)",
            "BASE,PREPARE.fixed,PREPARE.byte,READ,OUTPUT.fixed,OUTPUT.byte,RELEASE.fixed,RELEASE.byte"};
    case OP_INVERT: case OP_2MUL: case OP_2DIV: case OP_AND: case OP_OR: case OP_XOR:
    case OP_LSHIFT: case OP_RSHIFT: case OP_BYTEREV:
        return {"BASE + PREPARE(operands) + BIT(bytes) + OUTPUT(out)",
            "BASE,PREPARE.fixed,PREPARE.byte,READ,BIT,OUTPUT.fixed,OUTPUT.byte"};
        case OP_MUL: return {"BASE + PREPARE(a,b) + MUL(u,v) + WRITE(8*(u+v)) + NORMALIZE(out)", "BASE,PREPARE.fixed,PREPARE.byte,MUL.fixed,MUL.row,MUL.cell,WRITE,NORMALIZE"};
        case OP_DIV: case OP_MOD: return {"BASE + PREPARE(a,b) + DIV(s,v) + OUTPUT(out) + RELEASE(max input)", "BASE,PREPARE.fixed,PREPARE.byte,DIV.fixed,DIV.step,DIV.cell,OUTPUT.fixed,OUTPUT.byte,RELEASE.fixed,RELEASE.byte"};
    case OP_CAT: return {"BASE + COPY(a+b)", "BASE,COPY.fixed,COPY.byte"};
    case OP_SUBSTR:
        return {"BASE + PREPARE(indices) + READ(indices) + COPY(out) + RELEASE(W(source), W(indices))",
                "BASE,PREPARE.fixed,PREPARE.byte,READ,COPY.fixed,COPY.byte,RELEASE.fixed,RELEASE.byte"};
    case OP_LEFT: return {"BASE + PREPARE(index) + READ(W(index)) + COPY(out)", "BASE,PREPARE.fixed,PREPARE.byte,READ,COPY.fixed,COPY.byte"};
    case OP_RIGHT: return {"BASE + PREPARE(index) + READ(W(index)) + COPY(out)", "BASE,PREPARE.fixed,PREPARE.byte,READ,COPY.fixed,COPY.byte"};
    case OP_SHA1:
        return {"BASE + SHA1(n) + COPY(digest)", "BASE,SHA1.fixed,SHA1.byte,COPY.fixed,COPY.byte"};
    case OP_RIPEMD160:
        return {"BASE + RIPEMD160(n) + COPY(digest)", "BASE,RIPEMD160.fixed,RIPEMD160.byte,COPY.fixed,COPY.byte"};
    case OP_SHA256:
        return {"BASE + SHA256(n) + COPY(digest)", "BASE,SHA256.fixed,SHA256.byte,COPY.fixed,COPY.byte"};
    case OP_HASH160:
        return {"BASE + SHA256(n) + RIPEMD160(32) + COPY(digest)", "BASE,SHA256.fixed,SHA256.byte,RIPEMD160.fixed,RIPEMD160.byte,COPY.fixed,COPY.byte"};
    case OP_HASH256:
        return {"BASE + SHA256(n) + SHA256(32) + COPY(digest)", "BASE,SHA256.fixed,SHA256.byte (n),SHA256.fixed,SHA256.byte (32),COPY.fixed,COPY.byte"};
    case OP_CHECKSIG: case OP_CHECKSIGVERIFY: case OP_CHECKSIGADD:
        return {"BASE + optional SHA256 + SIG + result work", "BASE,SHA256.fixed,SHA256.byte,SIG,OUTPUT(8),PREPARE.fixed,PREPARE.byte,ARITH.fixed,ARITH.byte,OUTPUT.fixed,OUTPUT.byte,COPY.fixed,COPY.byte"};
    case OP_CHECKLOCKTIMEVERIFY: case OP_CHECKSEQUENCEVERIFY:
        return {"BASE + PREPARE(n) + READ(W(n)) + OUTPUT(n)", "BASE,PREPARE.fixed,PREPARE.byte,READ,OUTPUT.fixed,OUTPUT.byte"};
    case OP_TX:
        return {"BASE + SELECT(selected records/items) + COPY.byte*returned_bytes",
                "BASE,SELECT.fixed,SELECT.item,COPY.byte"};
    case OP_MACRO: return {"BASE * (substituted instructions + visited references) + WRITE(unrolled length), then execution", "BASE,WRITE"};
    default: return {"unwired", ""};
    }
}

static std::pair<std::string, std::string> CandidateFormula(opcodetype opcode)
{
    // NUMERIC_RESULT(n) = WRITE(W(n)) + NORMALIZE. Initial witness
    // production is charged once per script, not again in each opcode formula.
    switch (opcode) {
    case OP_DROP: case OP_2DROP: case OP_NIP: return {"BASE", "BASE"};
    case OP_BYTEREV: return {"BASE + BIT(W(n))", "BASE,BIT"};
    case OP_MIN: case OP_MAX:
        return {"BASE + PREPARE(operands) + READ(W) + NUMERIC_RESULT(out)", "BASE,PREPARE,READ,WRITE,NORMALIZE"};
    case OP_DIV: case OP_MOD:
        return {"BASE + PREPARE(a,b) + READ(a,b) + DIV(s,v) + NUMERIC_RESULT(out)", "BASE,PREPARE,READ,DIV,WRITE,NORMALIZE"};
    case OP_MUL:
        return {"BASE + PREPARE(a,b) + MUL(u,v) + WRITE(8*(u+v)) + NORMALIZE(out)",
                "BASE,PREPARE,MUL,WRITE,NORMALIZE"};
    case OP_SUBSTR:
        return {"BASE + PREPARE(indices) + READ(indices) + WRITE(out)", "BASE,PREPARE,READ,WRITE"};
    case OP_LSHIFT: case OP_RSHIFT:
        return {"BASE + PREPARE(operands) + READ(shift) + BIT(W(input)) + NUMERIC_RESULT(out)", "BASE,PREPARE,READ,BIT,WRITE,NORMALIZE"};
    case OP_CHECKSIGFROMSTACK:
        return {"BASE + WRITE(8) + [nonempty signature: SIG + SHA256(64+n)]", "BASE,SIG,SHA256,WRITE"};
    case OP_TWEAKADD: return {"BASE + TWEAK + WRITE(32)", "BASE,TWEAK,WRITE"};
    case OP_TX:
        return {"BASE + SELECT(k) + WRITE(collated bytes), or WRITE(n) / NUMERIC_RESULT per noncollated value",
                "BASE,SELECT,WRITE,NORMALIZE"};
    case OP_MACRO:
        return {"BASE * (substituted instructions + visited references) + WRITE(unrolled length), then execution", "BASE,WRITE"};
    default: break;
    }
    auto result{BaselineFormula(opcode)};
    for (std::string* text : {&result.first, &result.second}) {
        for (const auto& [from, to] : {std::pair{std::string{"COPY"}, std::string{"WRITE"}},
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

//! Successful cases per opcode whose charge passed the exact-budget checks.
using CostCoverage = std::map<opcodetype, size_t>;

static void WriteCoverageManifest(const std::string& path, const CostCoverage& coverage)
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
    out << "opcode,candidate formula,coefficients used,cost-test status\n";
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        const auto [formula, coefficients]{CandidateFormula(entry.opcode)};
        const auto found{coverage.find(entry.opcode)};
        const size_t cases{found == coverage.end() ? 0 : found->second};
        const std::string status{
            formula == "unwired" ? "unwired" :
            cases != 0 ? strprintf("exact budget verified (%u successful cases)", cases) :
                         "no successful case"};
        out << quote(OpcodeName(entry.opcode)) << ',' << quote(formula) << ',' << quote(coefficients) << ','
            << quote(status) << '\n';
    }
}

static std::vector<CaseSpec> GenerateCaseSpecs(const Options& options)
{
    std::vector<CaseSpec> specs;
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        const opcodetype opcode{entry.opcode};
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
    if (!options.confirm_names.empty()) {
        std::erase_if(specs, [&](const CaseSpec& spec) { return !options.confirm_names.contains(spec.name); });
        for (const std::string& name : options.confirm_names) {
            if (std::ranges::none_of(specs, [&](const CaseSpec& spec) { return spec.name == name; })) {
                throw std::runtime_error("confirmation case is not in this corpus (rerun screening with the same options): " + name);
            }
        }
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
    const bool diagnose{g_diagnose_div17 && test_case.spec->opcode == OP_DIV &&
                        test_case.spec->operand_shape == "17Bx9B"};
    ResourceCounters before, after;
    bench.run(test_case.spec->name, [&] {
        ++executions;
        before = ReadResourceCounters();
        outcome = ExecutePrepared(test_case, checker, execution);
        after = ReadResourceCounters();
    });
    const ResourceCounters counters{CounterDelta(before, after)};
    if (diagnose) {
        std::cerr << strprintf("DIV17_DIAG round=%d order=%u trim=%d wall=%.9f cpu=%.9f"
                               " minor_faults=%d major_faults=%d involuntary=%d\n",
            round, order, !g_skip_allocator_trim,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed), counters.cpu_sec,
            counters.minor_faults, counters.major_faults, counters.involuntary_switches);
    }
    if (executions != 1 || bench.results().size() != 1 || bench.results().front().size() != 1) {
        throw std::runtime_error("nanobench did not execute exactly one case sample");
    }
    CheckMeasuredOutcome(test_case, expected, outcome, TimingStageName(stage));
    return {MeasurementMode::REALISTIC, stage, round, order,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed), counters};
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
    const uint64_t initial_cost{InitialProducerCost(test_case.initial_stack) * test_case.evaluations};
    if (expected.varops_consumed <= initial_cost ||
        expected.varops_consumed - initial_cost < MIN_FULL_VAROPS_SAMPLE_BUDGET) {
        result.status = "insufficient-sample";
        return false;
    }

    result.status = "extrapolated";
    result.script_bytes = test_case.script.size();
    result.script_executions = test_case.evaluations;
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
    const uint64_t fixture_bytes{StackFixtureBytes(test_case.initial_stack) * test_case.evaluations};
    if (fixture_bytes > MAX_FIXTURE_POOL_BYTES / 2) {
        throw std::runtime_error(strprintf("%s sample fixtures would require %u bytes (limit %u)",
                                           test_case.spec->name, fixture_bytes * 2,
                                           MAX_FIXTURE_POOL_BYTES));
    }

    ReleaseAllocatorCaches();
    PreparedExecution warmup_execution{PrepareExecution(test_case, true, budget_ceiling)};
    PreparedExecution measured_execution{PrepareExecution(test_case, true, budget_ceiling)};
    BenchSignatureChecker checker{fixture, test_case.transaction.get()};
    const EvalOutcome warmup_outcome{ExecutePrepared(test_case, checker, warmup_execution)};
    CheckDeclaredOutcome(test_case, warmup_outcome, "warmup");
    if (expected) CheckMeasuredOutcome(test_case, *expected, warmup_outcome, "warmup");
    TimingSample sample{MeasurePrepared(test_case, fixture, measured_execution, warmup_outcome,
                                        TimingStage::STABLE, round, order)};
    ReleaseAllocatorCaches();
    return {warmup_outcome, std::move(sample)};
}

static TimingSample MeasureSchnorrBatch(const CryptoFixture& fixture, TimingStage stage,
                                        int round, size_t order, uint64_t iterations)
{
    ankerl::nanobench::Bench bench{SetupBenchmark()};
    uint64_t valid{0};
    size_t executions{0};
    ResourceCounters before, after;
    bench.run("Schnorr signature validation", [&] {
        ++executions;
        before = ReadResourceCounters();
        for (uint64_t i{0}; i < iterations; ++i) {
            valid += fixture.pubkey.VerifySchnorr(fixture.message, fixture.signature);
        }
        ankerl::nanobench::doNotOptimizeAway(valid);
        after = ReadResourceCounters();
    });
    if (executions != 1 || valid != iterations || bench.results().size() != 1 ||
        bench.results().front().size() != 1) {
        throw std::runtime_error("raw Schnorr anchor failed");
    }
    const double scale{static_cast<double>(SIGNATURES_PER_BLOCK) / iterations};
    return {MeasurementMode::REALISTIC, stage, round, order,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed) * scale,
            CounterDelta(before, after)};
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
    FULL_VAROPS_STAGE,
    FULL_VAROPS_SAMPLES,
    FULL_VAROPS_WALL_SECONDS,
    FULL_VAROPS_WALL_MIN_SECONDS,
    FULL_VAROPS_WALL_MAX_SECONDS,
    FULL_VAROPS_MDAPE,
    FULL_VAROPS_SCHNORR_EQUIVALENTS,
    CPU_SECONDS,
    MINOR_PAGE_FAULTS,
    MAJOR_PAGE_FAULTS,
    INVOLUNTARY_SWITCHES,
    COUNT,
};

static constexpr size_t CsvIndex(CsvColumn column) { return static_cast<size_t>(column); }

using CsvRow = std::array<std::string, CsvIndex(CsvColumn::COUNT)>;

static constexpr std::string_view CSV_HEADER{
    "Record_Type,Measurement_Mode,Rank,Name,Domain,Headline_Role,New_In_V2,Opcode,Sequence_Opcodes,"
    "Operand_Shape,Operand_Pattern,Script_Bytes,Initial_Stack_Items,Initial_Stack_Bytes,"
    "Varops_Consumed,Expected_Termination,Actual_Termination,Saturation,Repetitions,"
    "Sequence_Varops,Stage,Round,Order,Samples,Wall_Seconds,"
    "Wall_Min_Seconds,Wall_Max_Seconds,MdAPE,Schnorr_Equivalents,Varops_Percentage,"
    "Full_Varops_Status,Full_Varops_Script_Bytes,Full_Varops_Script_Executions,Full_Varops_Measured_Varops,"
    "Full_Varops_Scale,Full_Varops_Stage,Full_Varops_Samples,Full_Varops_Wall_Seconds,"
    "Full_Varops_Wall_Min_Seconds,Full_Varops_Wall_Max_Seconds,Full_Varops_MdAPE,"
    "Full_Varops_Schnorr_Equivalents,CPU_Seconds,Minor_Page_Faults,Major_Page_Faults,Involuntary_Context_Switches"};
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
                              const CorpusCounts& counts, const Options& options,
                              const std::vector<std::string>& notes = {})
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

    output_file << "# Schema: bench_varops-v6\n";
    output_file << GetBenchmarkSystemInfo();
    output_file << "# Record types: summary=aggregated row; sample=normalized wall-clock measurement.\n";
    output_file << "# Wall_Seconds: summary median or sample value; Schnorr samples are normalized to 80,000 validations.\n";
    output_file << "# Full_Varops_Wall_Seconds: natural legal-script runtime extrapolated "
                   "to exactly 40 billion varops.\n";
    output_file << "# Full-varops extrapolation requires at least 1% of the budget in the measured script.\n";
    output_file << "# Measurement_Mode distinguishes realistic measurements and full-varops extrapolations.\n";
    output_file << "# Realistic sample rows record process CPU seconds, page faults and involuntary context switches "
                   "during the timed execution (Windows reports all page faults as minor, without switches).\n";
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
    for (const std::string& note : notes) output_file << "# " << note << '\n';
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
            if (sample.counters) {
                const ResourceCounters& c{*sample.counters};
                if (c.cpu_sec >= 0) CsvField(row, CsvColumn::CPU_SECONDS) = CsvNumber(c.cpu_sec);
                if (c.minor_faults >= 0) CsvField(row, CsvColumn::MINOR_PAGE_FAULTS) = CsvNumber(c.minor_faults);
                if (c.major_faults >= 0) CsvField(row, CsvColumn::MAJOR_PAGE_FAULTS) = CsvNumber(c.major_faults);
                if (c.involuntary_switches >= 0) {
                    CsvField(row, CsvColumn::INVOLUNTARY_SWITCHES) = CsvNumber(c.involuntary_switches);
                }
            }
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

/** Cases selected from a screening run, and its same-run reference. */
struct ConfirmationPlan {
    std::set<std::string> names;
    std::set<std::string> references;
    std::map<std::string, double> screening_ratios;
    double screening_reference{0};
};

static std::vector<std::string> ParseCsvLine(const std::string& line)
{
    std::vector<std::string> fields(1);
    bool quoted{false};
    for (size_t i{0}; i < line.size(); ++i) {
        const char ch{line[i]};
        if (quoted) {
            if (ch == '"' && i + 1 < line.size() && line[i + 1] == '"') {
                fields.back() += '"';
                ++i;
            } else if (ch == '"') {
                quoted = false;
            } else {
                fields.back() += ch;
            }
        } else if (ch == '"') {
            quoted = true;
        } else if (ch == ',') {
            fields.emplace_back();
        } else if (ch != '\r') {
            fields.back() += ch;
        }
    }
    return fields;
}

/**
 * Screening flags every v2 case whose measured or projected time exceeds
 * threshold × the screening run's slowest pre-v2 case. Confirmation reruns the
 * flagged cases with the three slowest pre-v2 cases as a same-run reference.
 */
static ConfirmationPlan ReadConfirmationPlan(const std::string& path, double threshold)
{
    std::ifstream input{path};
    if (!input) throw std::runtime_error("cannot read screening CSV " + path);
    std::string line;
    std::map<std::string, size_t> column;
    std::vector<std::pair<double, std::string>> references;
    std::vector<std::pair<std::string, double>> candidates;
    while (std::getline(input, line)) {
        if (line.empty() || line.front() == '#') continue;
        const std::vector<std::string> fields{ParseCsvLine(line)};
        if (column.empty()) {
            for (size_t i{0}; i < fields.size(); ++i) column[fields[i]] = i;
            for (const char* name : {"Record_Type", "Name", "Domain", "Wall_Seconds", "Full_Varops_Wall_Seconds"}) {
                if (!column.contains(name)) throw std::runtime_error(strprintf("screening CSV lacks %s", name));
            }
            continue;
        }
        const auto field = [&](const char* name) -> const std::string& {
            const size_t index{column.at(name)};
            if (index >= fields.size()) throw std::runtime_error("truncated screening CSV row");
            return fields[index];
        };
        if (field("Record_Type") != "summary") continue;
        const auto seconds = [](const std::string& text) {
            if (text.empty()) return 0.0;
            double value{0};
            std::istringstream parser{text};
            parser.imbue(std::locale::classic());
            if (!(parser >> value) || !parser.eof()) {
                throw std::runtime_error("invalid seconds value '" + text + "'");
            }
            return value;
        };
        const double wall{std::max(seconds(field("Wall_Seconds")), seconds(field("Full_Varops_Wall_Seconds")))};
        if (field("Domain") == DomainName(ExecutionDomain::PRE_GSR_TAPSCRIPT)) {
            references.emplace_back(wall, field("Name"));
        } else if (field("Domain") == DomainName(ExecutionDomain::GSR_TAPSCRIPT_V2)) {
            candidates.emplace_back(field("Name"), wall);
        }
    }
    if (references.empty()) throw std::runtime_error("screening CSV has no pre-v2 reference cases");
    std::ranges::sort(references, std::greater{});
    ConfirmationPlan plan;
    plan.screening_reference = references.front().first;
    for (size_t i{0}; i < std::min<size_t>(3, references.size()); ++i) {
        plan.references.insert(references[i].second);
        plan.names.insert(references[i].second);
    }
    for (const auto& [name, wall] : candidates) {
        const double ratio{wall / plan.screening_reference};
        if (ratio > threshold) {
            plan.screening_ratios[name] = ratio;
            plan.names.insert(name);
        }
    }
    return plan;
}

/** Per-round ratios against the same round's slowest reference, with a verdict per case. */
static std::vector<std::string> ReportConfirmation(const std::vector<BenchResult>& results,
                                                   const ConfirmationPlan& plan, double threshold)
{
    std::map<int, double> reference;
    for (const BenchResult& result : results) {
        if (!plan.references.contains(result.name)) continue;
        for (const TimingSample& sample : result.samples) {
            if (sample.mode != MeasurementMode::REALISTIC) continue;
            reference[sample.round] = std::max(reference[sample.round], sample.wall_sec);
        }
    }
    std::vector<std::string> lines;
    lines.push_back(strprintf("Confirmation: threshold %.3fx; screening reference %.3f s; %u flagged cases; "
                              "per-round ratio = max(measured, projected) / slowest same-round reference",
                              threshold, plan.screening_reference, plan.screening_ratios.size()));
    for (const auto& [name, screening] : plan.screening_ratios) {
        const auto found{std::ranges::find_if(results, [&](const BenchResult& result) { return result.name == name; })};
        if (found == results.end()) {
            lines.push_back(strprintf("Confirmation: %s did not complete", name));
            continue;
        }
        std::map<int, double> wall;
        for (const TimingSample& sample : found->samples) wall[sample.round] = std::max(wall[sample.round], sample.wall_sec);
        std::vector<double> ratios;
        for (const auto& [round, seconds] : wall) {
            if (reference.contains(round) && reference.at(round) > 0) ratios.push_back(seconds / reference.at(round));
        }
        if (ratios.empty()) {
            lines.push_back(strprintf("Confirmation: %s has no round with a reference", name));
            continue;
        }
        std::ranges::sort(ratios);
        const double median{ratios.size() % 2 ? ratios[ratios.size() / 2] :
                                                (ratios[ratios.size() / 2 - 1] + ratios[ratios.size() / 2]) / 2};
        const std::string verdict{median > 1.0 ? "above-limit" : ratios.back() > 1.0 ? "straddles-limit" : "below-limit"};
        lines.push_back(strprintf("Confirmation: %s screening=%.3fx rounds=%u median=%.3fx min=%.3fx max=%.3fx verdict=%s",
                                  name, screening, ratios.size(), median, ratios.front(), ratios.back(), verdict));
    }
    return lines;
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
              << "  --verify-costs         Cost-verification mode: check outcomes and exact budgets, skip timing\n"
              << "  --coverage-manifest P Export candidate opcode/formula/cost-test CSV\n"
              << "  --confirm SCREEN.csv    Rerun the v2 cases a screening CSV flagged above the threshold,\n"
              << "                            with its three slowest pre-v2 cases as same-run reference\n"
              << "  --confirm-threshold R   Screening ratio that flags a case (default: 1.0)\n"
              << "  --diagnose-div17       Print CPU/fault/context-switch counters for DIV 17x9B\n"
              << "  --no-allocator-trim    Diagnostic: do not force allocator cache release\n"
              << "  --shape-search          Search operand shapes/sizes for the worst time per varop\n"
              << "  --reference-seconds S   Same-machine T_pre used to report search ratios (required)\n"
              << "  --search-budget N       Varops per screening sample (default: 400000000)\n"
              << "  --search-samples N      Random candidates per opcode; program search: seed programs\n"
              << "                            per opcode for an empty corpus (default: 32)\n"
              << "  --search-climbers N     Best random candidates refined per opcode (default: 2)\n"
              << "  --search-steps N        Maximum hill-climbing steps per refinement (default: 4)\n"
              << "  --search-top N          Global screening leaders to confirm (default: 20)\n"
              << "  --search-seed N         Random seed for candidate generation\n"
              << "  --program-search        Coverage-guided search over multi-opcode programs, stack depth\n"
              << "                            and live size for the worst time per varop (uses --opcodes,\n"
              << "                            --reference-seconds, --search-budget, --search-top, --epochs)\n"
              << "  --search-seconds N      Program search: wall-clock limit before confirmation (default: 600)\n"
              << "  --search-corpus DIR     Program search: load and extend a persistent corpus of programs\n"
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
        } else if (arg == "--confirm") {
            if (++i >= argc) throw std::runtime_error("--confirm requires a screening CSV path");
            options.confirm_file = argv[i];
        } else if (arg == "--confirm-threshold") {
            if (++i >= argc) throw std::runtime_error("--confirm-threshold requires a positive number");
            double threshold{0};
            std::istringstream parser{argv[i]};
            parser.imbue(std::locale::classic());
            if (!(parser >> threshold) || !parser.eof() || !std::isfinite(threshold) || threshold <= 0) {
                throw std::runtime_error("invalid --confirm-threshold value '" + std::string{argv[i]} + "'");
            }
            options.confirm_threshold = threshold;
        } else if (arg == "--list-opcodes") {
            options.list_opcodes = true;
        } else if (arg == "--verify-costs") {
            options.verify_costs = true;
        } else if (arg == "--coverage-manifest") {
            if (++i >= argc) throw std::runtime_error("--coverage-manifest requires a path");
            options.coverage_manifest = argv[i];
        } else if (arg == "--diagnose-div17") {
            g_diagnose_div17 = true;
        } else if (arg == "--no-allocator-trim") {
            g_skip_allocator_trim = true;
        } else if (arg == "--shape-search") {
            options.shape_search = true;
        } else if (arg == "--reference-seconds") {
            if (++i >= argc) throw std::runtime_error("--reference-seconds requires a positive number");
            double seconds{0};
            std::istringstream parser{argv[i]};
            parser.imbue(std::locale::classic());
            if (!(parser >> seconds) || !parser.eof() || !std::isfinite(seconds) || seconds <= 0) {
                throw std::runtime_error("invalid --reference-seconds value '" + std::string{argv[i]} + "'");
            }
            options.reference_seconds = seconds;
        } else if (arg == "--program-search") {
            options.program_search = true;
        } else if (arg == "--search-corpus") {
            if (++i >= argc || std::string_view{argv[i]}.empty()) throw std::runtime_error("--search-corpus requires a directory");
            options.search_corpus = argv[i];
        } else if (arg == "--search-budget" || arg == "--search-samples" || arg == "--search-climbers" ||
                   arg == "--search-steps" || arg == "--search-top" || arg == "--search-seed" ||
                   arg == "--search-seconds") {
            if (++i >= argc) throw std::runtime_error(arg + " requires an integer");
            const std::optional<uint64_t> value{ToIntegral<uint64_t>(argv[i])};
            const bool allow_zero{arg == "--search-seed" || arg == "--search-climbers" ||
                                  arg == "--search-steps" || arg == "--search-top"};
            if (!value || (*value == 0 && !allow_zero) ||
                (arg == "--search-budget" && *value > TOTAL_VAROPS_BUDGET) ||
                (arg != "--search-budget" && arg != "--search-seed" &&
                 *value > std::numeric_limits<uint32_t>::max())) {
                throw std::runtime_error("invalid " + arg + " value '" + std::string{argv[i]} + "'");
            }
            if (arg == "--search-budget") options.search_budget = *value;
            if (arg == "--search-samples") options.search_samples = *value;
            if (arg == "--search-climbers") options.search_climbers = *value;
            if (arg == "--search-steps") options.search_steps = *value;
            if (arg == "--search-top") options.search_top = *value;
            if (arg == "--search-seed") options.search_seed = *value;
            if (arg == "--search-seconds") options.search_seconds = *value;
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
    const bool search{options.shape_search || options.program_search};
    if (options.shape_search && options.program_search) {
        throw std::runtime_error("choose one of --shape-search and --program-search");
    }
    if (search && options.reference_seconds == 0) {
        throw std::runtime_error("--shape-search and --program-search require --reference-seconds");
    }
    if (!options.search_corpus.empty() && !options.program_search) {
        throw std::runtime_error("--search-corpus requires --program-search");
    }
    if (!options.confirm_file.empty() && (search || options.verify_costs ||
                                          !options.case_filter.empty() || !options.selected_opcodes.empty())) {
        throw std::runtime_error("--confirm selects its own cases; do not combine it with --opcodes, --case-filter, "
                                 "--shape-search, --program-search or --verify-costs");
    }
    if (search && (options.verify_costs || !options.case_filter.empty())) {
        throw std::runtime_error("--shape-search and --program-search cannot be combined with --verify-costs or --case-filter");
    }
    return options;
}

static CostCoverage VerifyCorpusCosts(
    const std::vector<CaseSpec>& specs, const CryptoFixture& fixture, bool silent)
{
    CostCoverage coverage;
    size_t checked{0};
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
        if (spec.op_tx_shape && one_repeat) {
            test_case.transaction = MakeOpTxContext(*spec.op_tx_shape, test_case.script);
        }
        BenchSignatureChecker checker{fixture, test_case.transaction.get()};
        const EvalOutcome observed{Evaluate(test_case, checker)};
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
            const EvalOutcome exact{Evaluate(test_case, checker, observed.varops_consumed)};
            if (!exact.success || exact.error != SCRIPT_ERR_OK ||
                exact.varops_consumed != observed.varops_consumed) {
                throw std::runtime_error("exact-budget replay mismatch for " + spec.name);
            }
            const EvalOutcome short_budget{Evaluate(test_case, checker, observed.varops_consumed - 1)};
            if (short_budget.success || short_budget.error != SCRIPT_ERR_VAROP_COUNT) {
                throw std::runtime_error("budget-minus-one did not reject for " + spec.name);
            }
            ++coverage[spec.opcode];
            ++boundary_checked;
        }
        if (!silent && checked % CLI_PROGRESS_INTERVAL == 0) {
            std::cout << strprintf("Cost verification: %u cases\n", checked);
        }
    }
    std::cout << strprintf("Outcome verification passed: %u candidate cases.\n", checked);
    std::cout << strprintf(
        "Exact-budget/budget-minus-one verification passed: %u successful cases across %u opcode families.\n",
        boundary_checked, coverage.size());
    return coverage;
}

static void RequireCostCoverage(const std::vector<CaseSpec>& specs, const CostCoverage& coverage)
{
    std::set<opcodetype> selected;
    for (const CaseSpec& spec : specs) {
        if (DomainFor(spec.role) == ExecutionDomain::GSR_TAPSCRIPT_V2) {
            selected.insert(spec.opcode);
        }
    }
    for (const opcodetype opcode : selected) {
        if (!coverage.contains(opcode)) {
            throw std::runtime_error("candidate timing refused: no successful cost-verification case for " +
                                     OpcodeName(opcode));
        }
    }
}

// The corpus fixes hand-chosen operands. This mode searches operand values and
// sizes for the largest measured time per charged varop of a repeated,
// stack-neutral script. It complements the whole-workload runtime checks.
enum class SearchShape : uint8_t {
    DENSE,
    ZERO,
    ONE_LOW,
    SMALL,
    TOP_ONE,
    TOP_CLEAR,
    LOW_HALF,
    HIGH_HALF,
    ALTERNATING,
    RANDOM,
};

constexpr std::array SEARCH_SHAPES{
    SearchShape::DENSE, SearchShape::ZERO, SearchShape::ONE_LOW, SearchShape::SMALL,
    SearchShape::TOP_ONE, SearchShape::TOP_CLEAR, SearchShape::LOW_HALF, SearchShape::HIGH_HALF,
    SearchShape::ALTERNATING, SearchShape::RANDOM};
// Keep initial operands inside a feasible witness, leaving room for the script.
constexpr size_t MAX_SEARCH_PAYLOAD{3'900'000};
// Screening samples are single timings; ignore improvements within their noise.
constexpr double SEARCH_IMPROVEMENT{0.03};

static std::string SearchShapeName(SearchShape shape)
{
    switch (shape) {
    case SearchShape::DENSE: return "dense";
    case SearchShape::ZERO: return "zero";
    case SearchShape::ONE_LOW: return "one-low";
    case SearchShape::SMALL: return "small";
    case SearchShape::TOP_ONE: return "top-one";
    case SearchShape::TOP_CLEAR: return "top-clear";
    case SearchShape::LOW_HALF: return "low-half";
    case SearchShape::HIGH_HALF: return "high-half";
    case SearchShape::ALTERNATING: return "alternating";
    case SearchShape::RANDOM: return "random";
    }
    return "unknown";
}

struct SearchOperand {
    SearchShape shape{SearchShape::DENSE};
    size_t size{0};
    uint64_t value{0}; // Little-endian value of SMALL, zero-padded to size.
};

struct SearchPoint {
    opcodetype opcode{OP_NOP};
    std::vector<SearchOperand> operands;
};

struct RepeatedMeasurement {
    std::string reason;
    bool valid{false};
    uint64_t repetitions{0};
    uint64_t consumed{0};
    uint64_t initial{0};
    double wall_sec{0};
    double projected_sec{0};
    //! Full-block time of the work a block can actually hold; see MeasureRepeated.
    double reachable_sec{0};
    double ratio{0};
};

struct SearchResult : RepeatedMeasurement {
    SearchPoint point;
    std::string phase;
};

static size_t SearchArity(opcodetype opcode)
{
    switch (opcode) {
    case OP_1ADD: case OP_1SUB: case OP_NOT: case OP_0NOTEQUAL:
    case OP_INVERT: case OP_2MUL: case OP_2DIV:
    case OP_RIPEMD160: case OP_SHA1: case OP_SHA256: case OP_HASH160: case OP_HASH256:
        return 1;
    case OP_EQUAL: case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR:
    case OP_NUMEQUAL: case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN:
    case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX:
    case OP_AND: case OP_OR: case OP_XOR: case OP_MUL: case OP_DIV: case OP_MOD:
    case OP_LSHIFT: case OP_RSHIFT: case OP_CAT: case OP_LEFT: case OP_RIGHT:
        return 2;
    case OP_SUBSTR: case OP_WITHIN:
        return 3;
    default:
        return 0;
    }
}

static void NormalizeOperand(SearchOperand& operand)
{
    operand.size = std::min<size_t>(operand.size, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE);
    if (operand.shape != SearchShape::SMALL) {
        operand.value = 0;
    } else if (operand.size < sizeof(uint64_t)) {
        operand.value &= (uint64_t{1} << (8 * operand.size)) - 1;
    }
}

static valtype SearchBytes(const SearchOperand& operand)
{
    const size_t size{operand.size};
    valtype out(size, 0x00);
    switch (operand.shape) {
    case SearchShape::DENSE: std::ranges::fill(out, 0xff); break;
    case SearchShape::ZERO: break;
    case SearchShape::ONE_LOW: if (size != 0) out.front() = 0x01; break;
    case SearchShape::SMALL:
        for (size_t i{0}; i < std::min(size, sizeof(uint64_t)); ++i) {
            out[i] = static_cast<unsigned char>(operand.value >> (8 * i));
        }
        break;
    case SearchShape::TOP_ONE: if (size != 0) out.back() = 0x01; break;
    case SearchShape::TOP_CLEAR: std::ranges::fill(out, 0x7f); break;
    case SearchShape::LOW_HALF: std::fill(out.begin(), out.begin() + (size + 1) / 2, 0xff); break;
    case SearchShape::HIGH_HALF: std::fill(out.begin() + size / 2, out.end(), 0xff); break;
    case SearchShape::ALTERNATING:
        for (size_t i{0}; i < size; ++i) out[i] = (i & 1) ? 0x55 : 0xaa;
        break;
    case SearchShape::RANDOM: {
        std::mt19937_64 rng{0x5eed ^ size};
        for (unsigned char& byte : out) byte = static_cast<unsigned char>(rng());
        break;
    }
    }
    return out;
}

static std::string SearchOperandsLabel(const SearchPoint& point)
{
    std::string label;
    for (const SearchOperand& operand : point.operands) {
        if (!label.empty()) label += ' ';
        label += operand.shape == SearchShape::SMALL ?
            strprintf("small=%u:%uB", operand.value, operand.size) :
            strprintf("%s:%uB", SearchShapeName(operand.shape), operand.size);
    }
    return label;
}

static std::string SearchKey(const SearchPoint& point)
{
    return OpcodeName(point.opcode) + "(" + SearchOperandsLabel(point) + ")";
}

static CScript SearchSequence(const SearchPoint& point)
{
    const size_t arity{point.operands.size()};
    return Ops({arity == 1 ? OP_DUP : arity == 2 ? OP_2DUP : OP_3DUP, point.opcode, OP_DROP});
}

static uint64_t SearchPayload(const SearchPoint& point)
{
    uint64_t total{0};
    for (const SearchOperand& operand : point.operands) total += operand.size;
    return total;
}

static SearchOperand DrawSearchOperand(std::mt19937_64& rng)
{
    // Word, hash-block and allocation boundaries, then log-uniform sizes.
    static constexpr std::array<size_t, 20> BOUNDARIES{
        0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 520, 521, 4096, 4097, 65536, 1'000'000};
    SearchOperand operand{SEARCH_SHAPES[rng() % SEARCH_SHAPES.size()], 0, 0};
    if (rng() % 10 < 3) {
        operand.size = BOUNDARIES[rng() % BOUNDARIES.size()];
    } else {
        std::uniform_real_distribution<double> exponent{0, std::log2(double(MAX_SEARCH_PAYLOAD))};
        operand.size = static_cast<size_t>(std::exp2(exponent(rng)));
    }
    if (operand.shape == SearchShape::SMALL) {
        std::uniform_real_distribution<double> exponent{0, 32};
        operand.value = static_cast<uint64_t>(std::exp2(exponent(rng)));
    }
    NormalizeOperand(operand);
    return operand;
}

static std::vector<SearchPoint> SearchNeighbors(const SearchPoint& point)
{
    std::vector<SearchPoint> out;
    std::set<std::string> seen{SearchKey(point)};
    for (size_t index{0}; index < point.operands.size(); ++index) {
        const SearchOperand base{point.operands[index]};
        const auto add = [&](SearchOperand operand) {
            NormalizeOperand(operand);
            SearchPoint next{point};
            next.operands[index] = operand;
            if (SearchPayload(next) > MAX_SEARCH_PAYLOAD || !seen.insert(SearchKey(next)).second) return;
            out.push_back(std::move(next));
        };
        for (const size_t size : {base.size * 2, base.size / 2, base.size + 1, base.size + 8,
                                  base.size - std::min<size_t>(base.size, 1),
                                  base.size - std::min<size_t>(base.size, 8)}) {
            SearchOperand operand{base};
            operand.size = size;
            add(operand);
        }
        for (const SearchShape shape : SEARCH_SHAPES) {
            SearchOperand operand{base};
            operand.shape = shape;
            if (shape == SearchShape::SMALL && base.shape != SearchShape::SMALL) operand.value = 0xff;
            add(operand);
        }
        if (base.shape == SearchShape::SMALL) {
            for (const uint64_t value : {base.value * 2, base.value / 2, base.value + 1,
                                         base.value - std::min<uint64_t>(base.value, 1)}) {
                SearchOperand operand{base};
                operand.value = value;
                add(operand);
            }
        }
    }
    return out;
}

// Time a stack-neutral sequence repeated against the screening budget and
// project it to the full budget; initial ownership is funded once.
static RepeatedMeasurement MeasureRepeated(opcodetype opcode, std::string shape, CScript sequence,
                                           std::vector<valtype> stack, const CryptoFixture& fixture,
                                           const Options& options, int samples)
{
    RepeatedMeasurement result;
    const size_t sequence_bytes{sequence.size()};
    uint64_t instructions{0};
    for (CScript::const_iterator pc{sequence.begin()}; pc != sequence.end(); ++instructions) {
        opcodetype decoded;
        if (!sequence.GetOp(pc, decoded)) throw std::runtime_error("invalid search sequence");
    }
    std::vector<CaseSpec> specs;
    AddCase(specs, opcode, HeadlineRole::NEW_GSR, "shape-search", std::move(shape),
            "searched", std::move(sequence), FixedStack(std::move(stack)));
    const CaseSpec& spec{specs.front()};
    try {
        uint64_t ceiling{options.search_budget};
        MaterializedCase test_case{Materialize(spec, fixture, ceiling)};
        if (test_case.repetitions == 0) {
            // One sequence exceeds the screening budget: sample one repetition.
            const uint64_t one_sequence{
                test_case.varops_per_repeat + InitialProducerCost(test_case.initial_stack) +
                CandidateCleanupCost(test_case.initial_stack, test_case.initial_stack.size()) + 10'000};
            ceiling = std::min(TOTAL_VAROPS_BUDGET, std::max(ceiling, one_sequence));
            test_case = Materialize(spec, fixture, ceiling);
        }
        if (test_case.repetitions == 0) {
            result.reason = "one sequence exceeds the budget";
            return result;
        }
        std::vector<double> walls;
        std::optional<EvalOutcome> expected;
        for (int sample{0}; sample < samples; ++sample) {
            CaseSample measured{RunTimedCaseSample(test_case, fixture, expected, sample + 1, 0, ceiling)};
            expected = measured.outcome;
            walls.push_back(measured.timing.wall_sec);
        }
        result.repetitions = test_case.repetitions;
        result.consumed = expected->varops_consumed;
        result.initial = InitialProducerCost(test_case.initial_stack);
        if (result.consumed <= result.initial) {
            result.reason = "no charged work beyond initial ownership";
            return result;
        }
        result.wall_sec = CalculateStats(std::move(walls)).median;
        // Same projection as the corpus: initial ownership is funded once.
        const double budget{double(TOTAL_VAROPS_BUDGET - result.initial)};
        const double charged{double(result.consumed - result.initial)};
        result.projected_sec = result.wall_sec * budget / charged;
        // A block holds the repeated body either in a direct script, bounded by
        // the budget and by its weight, or substituted from a macro, which pays
        // BASE per substituted instruction and writes the unrolled script.
        const double body_bytes{double(result.repetitions) * double(sequence_bytes)};
        const double direct_scale{std::min(budget / charged, double(SCRIPT_BYTES) / body_bytes)};
        const double unroll{double(result.repetitions) * double(instructions) * double(varops::BaseCost()) +
                            double(varops::WriteCost(static_cast<size_t>(body_bytes)))};
        result.reachable_sec = result.wall_sec * std::max(direct_scale, budget / (charged + unroll));
        result.ratio = result.projected_sec / options.reference_seconds;
        result.valid = true;
    } catch (const std::exception& exception) {
        result.reason = exception.what();
    }
    return result;
}

static SearchResult MeasureSearchPoint(const SearchPoint& point, std::string phase,
                                       const CryptoFixture& fixture, const Options& options, int samples)
{
    std::vector<valtype> stack;
    stack.reserve(point.operands.size());
    for (const SearchOperand& operand : point.operands) stack.push_back(SearchBytes(operand));
    return {MeasureRepeated(point.opcode, SearchOperandsLabel(point), SearchSequence(point),
                            std::move(stack), fixture, options, samples),
            point, std::move(phase)};
}

static bool WriteSearchResults(const Options& options, const std::vector<SearchResult>& log)
{
    std::ofstream out{options.output_file};
    out << "# bench_varops shape search\n"
        << strprintf("# reference_seconds=%.9g search_budget=%u seed=%u samples=%u climbers=%u steps=%u top=%u epochs=%d\n",
                     options.reference_seconds, options.search_budget, options.search_seed,
                     options.search_samples, options.search_climbers, options.search_steps,
                     options.search_top, options.stable_rounds)
        << "# ratio = wall * (40e9 - initial) / (consumed - initial) / reference_seconds\n"
        << "phase,opcode,operands,sequence,valid,reason,repetitions,varops_consumed,initial_varops,"
           "wall_seconds,projected_full_budget_seconds,ratio\n";
    for (const SearchResult& result : log) {
        out << strprintf("%s,%s,%s,%s,%d,%s,%u,%u,%u,%.9g,%.9g,%.9g\n",
                         result.phase, OpcodeName(result.point.opcode),
                         CsvEscape(SearchOperandsLabel(result.point)),
                         SequenceOpcodeNames(SearchSequence(result.point)), result.valid,
                         CsvEscape(result.reason), result.repetitions, result.consumed, result.initial,
                         result.wall_sec, result.projected_sec, result.ratio);
    }
    out.close();
    if (!out) std::cerr << "Error: could not write " << options.output_file << "\n";
    return bool(out);
}

static bool RunShapeSearch(const Options& options, const CryptoFixture& fixture)
{
    for (const opcodetype requested : options.selected_opcodes) {
        if (SearchArity(requested) == 0) {
            throw std::runtime_error("--shape-search does not support " + OpcodeName(requested));
        }
    }
    std::vector<opcodetype> opcodes;
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        if (SearchArity(entry.opcode) == 0) continue;
        if (!options.selected_opcodes.empty() && !options.selected_opcodes.contains(entry.opcode)) continue;
        opcodes.push_back(entry.opcode);
    }

    std::mt19937_64 rng{options.search_seed};
    std::vector<SearchResult> log;
    std::map<std::string, SearchResult> screened;
    const auto screen = [&](const SearchPoint& point, std::string phase) {
        const std::string key{SearchKey(point)};
        if (const auto found{screened.find(key)}; found != screened.end()) return found->second;
        SearchResult result{MeasureSearchPoint(point, std::move(phase), fixture, options, 1)};
        log.push_back(result);
        screened.emplace(key, result);
        return result;
    };

    std::vector<SearchResult> climbed;
    for (const opcodetype opcode : opcodes) {
        const size_t arity{SearchArity(opcode)};
        std::vector<SearchResult> candidates;
        for (uint64_t attempt{0};
             candidates.size() < options.search_samples && attempt < 4 * uint64_t{options.search_samples}; ++attempt) {
            SearchPoint point{opcode, {}};
            for (size_t i{0}; i < arity; ++i) point.operands.push_back(DrawSearchOperand(rng));
            if (SearchPayload(point) > MAX_SEARCH_PAYLOAD) continue;
            SearchResult result{screen(point, "random")};
            if (result.valid) candidates.push_back(std::move(result));
        }
        std::ranges::sort(candidates, std::greater{}, &SearchResult::ratio);
        double opcode_best{candidates.empty() ? 0 : candidates.front().ratio};
        for (size_t index{0}; index < std::min<size_t>(options.search_climbers, candidates.size()); ++index) {
            SearchResult current{candidates[index]};
            for (uint32_t step{0}; step < options.search_steps; ++step) {
                SearchResult best{current};
                for (const SearchPoint& neighbor : SearchNeighbors(current.point)) {
                    SearchResult result{screen(neighbor, "climb")};
                    if (result.valid && result.ratio > best.ratio) best = std::move(result);
                }
                if (best.ratio <= current.ratio * (1 + SEARCH_IMPROVEMENT)) break;
                current = std::move(best);
            }
            opcode_best = std::max(opcode_best, current.ratio);
            climbed.push_back(std::move(current));
        }
        if (!options.silent) {
            std::cout << strprintf("shape search %s: %u valid random candidates, best screened ratio %.4f\n",
                                   OpcodeName(opcode), candidates.size(), opcode_best) << std::flush;
        }
    }

    std::vector<SearchPoint> finalists;
    std::set<std::string> finalist_keys;
    const auto add_finalist = [&](const SearchPoint& point) {
        if (finalist_keys.insert(SearchKey(point)).second) finalists.push_back(point);
    };
    for (const SearchResult& result : climbed) add_finalist(result.point);
    std::vector<SearchResult> leaders;
    std::ranges::copy_if(log, std::back_inserter(leaders), &SearchResult::valid);
    std::ranges::sort(leaders, std::greater{}, &SearchResult::ratio);
    for (size_t index{0}; index < std::min<size_t>(options.search_top, leaders.size()); ++index) {
        add_finalist(leaders[index].point);
    }

    std::vector<SearchResult> confirmed;
    for (const SearchPoint& point : finalists) {
        SearchResult result{MeasureSearchPoint(point, "confirm", fixture, options, options.stable_rounds)};
        log.push_back(result);
        if (result.valid) confirmed.push_back(std::move(result));
    }
    std::ranges::sort(confirmed, std::greater{}, &SearchResult::ratio);

    const size_t valid_count{static_cast<size_t>(std::ranges::count_if(log, &SearchResult::valid))};
    std::cout << strprintf("\nShape search: %u measurements (%u valid), T_pre = %.4f s, screening budget %u varops\n",
                           log.size(), valid_count, options.reference_seconds, options.search_budget)
              << "Ratio = projected full-budget time / T_pre (confirmed median of "
              << options.stable_rounds << " samples)\n";
    std::cout << strprintf("%-6s %-10s %-10s %-10s %s\n", "ratio", "proj_s", "ps/varop", "reps", "case");
    // The global top 20, then the leader of every other searched opcode.
    std::set<opcodetype> reported;
    for (size_t index{0}; index < confirmed.size(); ++index) {
        const SearchResult& result{confirmed[index]};
        const bool first_for_opcode{reported.insert(result.point.opcode).second};
        if (index >= 20 && !first_for_opcode) continue;
        std::cout << strprintf("%-6.4f %-10.4f %-10.2f %-10u %s\n", result.ratio, result.projected_sec,
                               result.wall_sec * 1e12 / double(result.consumed - result.initial),
                               result.repetitions, SearchKey(result.point));
    }
    return options.output_file.empty() || WriteSearchResults(options, log);
}

// Program search: a coverage-guided loop over stack-neutral programs, in the
// style of PerfFuzz. A program is an initial witness stack and a body of steps.
// Each step copies operands from the stack (or moves earlier results), applies
// one opcode, and keeps or drops its results; the body drops whatever it kept,
// so every repetition of the body sees the same stack. Fitness is the time of a
// full block of the repeated body over T_pre, where the block holds only as much
// of the body as its budget and weight allow (MeasureRepeated). Inactive
// branches are left to the corpus cases. A program is retained when
// it reaches a feature no retained program has (an opcode, a data dependency
// between two opcodes, an operand size class, a stack depth or live size), or
// when it is slower than that feature's retained program.
struct ProgramItem {
    SearchOperand operand;
    uint32_t copies{1};
};

struct ProgramStep {
    opcodetype opcode{OP_NOP};
    //! Operand positions from the top of the stack before the step, modulo its depth.
    std::vector<uint32_t> args;
    bool keep{false}; //!< Leave the results for later steps.
    bool move{false}; //!< Move earlier results instead of copying them.
};

struct Program {
    std::vector<ProgramItem> stack; //!< Bottom first.
    std::vector<ProgramStep> steps;
};

struct ProgramResult : RepeatedMeasurement {
    Program program;
    std::string phase;
    std::vector<std::string> features;
};

struct StackEffect {
    size_t in{0}, out{0};
};

constexpr size_t MAX_PROGRAM_STEPS{12};
constexpr size_t MAX_PROGRAM_ITEMS{16};
constexpr uint64_t MAX_PROGRAM_DEPTH{16'384};
// A screening sample that would replace a feature's program is first remeasured.
constexpr int PROMOTION_SAMPLES{3};
constexpr int PROGRAM_PROGRESS_SECONDS{30};

static std::optional<StackEffect> ProgramEffect(opcodetype opcode)
{
    if (opcode == OP_SIZE) return StackEffect{1, 2};
    if (opcode == OP_BYTEREV) return StackEffect{1, 1};
    if (const size_t arity{SearchArity(opcode)}; arity != 0) return StackEffect{arity, 1};
    return std::nullopt;
}

static void PushIndex(CScript& script, size_t index)
{
    if (index == 0) {
        script << OP_0;
    } else if (index <= 16) {
        script << static_cast<opcodetype>(OP_1 + index - 1);
    } else {
        // Two little-endian bytes: a one-byte push of 0x81 would have to be OP_1NEGATE.
        script << valtype{static_cast<unsigned char>(index), static_cast<unsigned char>(index >> 8)};
    }
}

struct CompiledProgram {
    CScript sequence;
    std::vector<valtype> stack;
    std::vector<std::string> features;
    opcodetype lead{OP_NOP};
};

static CompiledProgram CompileProgram(const Program& program)
{
    CompiledProgram out;
    struct Slot {
        uint32_t id;
        int producer; //!< Step that produced the value, or -1 for an initial item.
        size_t size;  //!< Size of an initial item.
    };
    std::vector<Slot> slots;
    uint32_t next_id{0};
    uint64_t payload{0};
    for (const ProgramItem& item : program.stack) {
        const valtype bytes{SearchBytes(item.operand)};
        for (uint32_t copy{0}; copy < item.copies; ++copy) {
            out.stack.push_back(bytes);
            slots.push_back({next_id++, -1, item.operand.size});
        }
        payload += uint64_t{item.copies} * item.operand.size;
    }
    const size_t initial{slots.size()};
    std::set<std::string> features{strprintf("depth:%u", std::bit_width(initial)),
                                   strprintf("live:%u", std::bit_width(payload))};
    for (size_t index{0}; index < program.steps.size(); ++index) {
        const ProgramStep& step{program.steps[index]};
        const StackEffect effect{*ProgramEffect(step.opcode)};
        const std::string name{OpcodeName(step.opcode)};
        std::vector<Slot> after{slots};
        CScript code;
        std::vector<uint32_t> operands;
        operands.reserve(step.args.size());
        for (const uint32_t arg : step.args) operands.push_back(slots[slots.size() - 1 - arg % slots.size()].id);
        std::set<uint32_t> staged;
        for (const uint32_t id : operands) {
            const auto found{std::ranges::find(after, id, &Slot::id)};
            const size_t depth{static_cast<size_t>(after.end() - found) - 1};
            const Slot slot{*found};
            if (step.move && slot.producer >= 0 && !staged.contains(id)) {
                if (depth == 1) code << OP_SWAP;
                if (depth == 2) code << OP_ROT;
                if (depth > 2) {
                    PushIndex(code, depth);
                    code << OP_ROLL;
                }
                after.erase(found);
                after.push_back(slot);
            } else {
                if (depth == 0) code << OP_DUP;
                if (depth == 1) code << OP_OVER;
                if (depth > 1) {
                    PushIndex(code, depth);
                    code << OP_PICK;
                }
                after.push_back({next_id++, slot.producer, slot.size});
            }
            staged.insert(after.back().id);
        }
        size_t largest{0};
        bool initial_operand{false};
        for (size_t i{0}; i < effect.in; ++i) {
            const Slot& slot{after[after.size() - effect.in + i]};
            if (slot.producer < 0) {
                initial_operand = true;
                largest = std::max(largest, slot.size);
            } else {
                features.insert("chain:" + OpcodeName(program.steps[slot.producer].opcode) + ">" + name);
            }
        }
        const std::string size_class{initial_operand ? strprintf("%u", std::bit_width(largest)) : "derived"};
        code << step.opcode;
        after.resize(after.size() - effect.in);
        for (size_t i{0}; i < effect.out; ++i) after.push_back({next_id++, static_cast<int>(index), 0});
        if (!step.keep) {
            code << (effect.out == 2 ? OP_2DROP : OP_DROP);
            after.resize(after.size() - effect.out);
        }
        out.sequence.insert(out.sequence.end(), code.begin(), code.end());
        slots = std::move(after);
        if (out.lead == OP_NOP) out.lead = step.opcode;
        features.insert("op:" + name);
        features.insert("op:" + name + "@" + size_class);
    }
    for (size_t kept{slots.size() - initial}; kept != 0; kept -= std::min<size_t>(kept, 2)) {
        out.sequence << (kept >= 2 ? OP_2DROP : OP_DROP);
    }
    out.features.assign(features.begin(), features.end());
    return out;
}

static std::string ProgramFlags(const ProgramStep& step)
{
    std::string flags{std::string{step.keep ? "k" : ""} + (step.move ? "m" : "")};
    return flags.empty() ? "-" : flags;
}

//! One line: the initial stack, then the steps with their operand positions and flags.
static std::string ProgramLabel(const Program& program)
{
    std::string label;
    for (const ProgramItem& item : program.stack) {
        if (!label.empty()) label += ' ';
        label += SearchOperandsLabel({OP_NOP, {item.operand}});
        if (item.copies != 1) label += strprintf("*%u", item.copies);
    }
    label += " |";
    for (const ProgramStep& step : program.steps) {
        label += ' ' + OpcodeName(step.opcode) + "(";
        for (size_t i{0}; i < step.args.size(); ++i) label += strprintf("%s%u", i == 0 ? "" : ",", step.args[i]);
        label += ")" + (ProgramFlags(step) == "-" ? "" : ProgramFlags(step));
    }
    return label;
}

static std::string ProgramText(const Program& program)
{
    std::string text{"# bench_varops program v1\n"};
    for (const ProgramItem& item : program.stack) {
        text += strprintf("item %s %u %u %u\n", SearchShapeName(item.operand.shape), item.operand.size,
                          item.operand.value, item.copies);
    }
    for (const ProgramStep& step : program.steps) {
        text += strprintf("step %s %s", OpcodeName(step.opcode), ProgramFlags(step));
        for (const uint32_t arg : step.args) text += strprintf(" %u", arg);
        text += '\n';
    }
    return text;
}

static uint64_t ProgramDepth(const Program& program)
{
    uint64_t depth{0};
    for (const ProgramItem& item : program.stack) depth += item.copies;
    return depth;
}

static uint64_t ProgramPayload(const Program& program)
{
    uint64_t payload{0};
    for (const ProgramItem& item : program.stack) payload += uint64_t{item.copies} * item.operand.size;
    return payload;
}

static bool ProgramFeasible(Program& program)
{
    if (program.stack.empty() || program.stack.size() > MAX_PROGRAM_ITEMS) return false;
    if (program.steps.empty() || program.steps.size() > MAX_PROGRAM_STEPS) return false;
    for (ProgramItem& item : program.stack) {
        NormalizeOperand(item.operand);
        if (item.copies == 0) return false;
    }
    for (const ProgramStep& step : program.steps) {
        const std::optional<StackEffect> effect{ProgramEffect(step.opcode)};
        if (!effect || step.args.size() != effect->in) return false;
    }
    return ProgramDepth(program) <= MAX_PROGRAM_DEPTH && ProgramPayload(program) <= MAX_SEARCH_PAYLOAD;
}

static std::optional<Program> ParseProgram(const std::string& text)
{
    const std::map<std::string, opcodetype> opcodes{SupportedOpcodeMap()};
    Program program;
    std::istringstream lines{text};
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty() || line.front() == '#') continue;
        std::istringstream fields{line};
        fields.imbue(std::locale::classic());
        std::string kind, name;
        fields >> kind >> name;
        if (kind == "item") {
            ProgramItem item;
            const auto shape{std::ranges::find(SEARCH_SHAPES, name, SearchShapeName)};
            if (shape == SEARCH_SHAPES.end() || !(fields >> item.operand.size >> item.operand.value >> item.copies)) {
                return std::nullopt;
            }
            item.operand.shape = *shape;
            program.stack.push_back(item);
        } else if (kind == "step") {
            ProgramStep step;
            const auto opcode{opcodes.find(name)};
            std::string flags;
            if (opcode == opcodes.end() || !(fields >> flags)) return std::nullopt;
            step.opcode = opcode->second;
            if (flags.find_first_not_of("km-") != std::string::npos) return std::nullopt;
            step.keep = flags.find('k') != std::string::npos;
            step.move = flags.find('m') != std::string::npos;
            for (uint32_t arg; fields >> arg;) step.args.push_back(arg);
            program.steps.push_back(std::move(step));
        } else {
            return std::nullopt;
        }
        if (!fields.eof()) return std::nullopt;
    }
    if (!ProgramFeasible(program)) return std::nullopt;
    return program;
}

static ProgramResult MeasureProgram(const Program& program, std::string phase, const CryptoFixture& fixture,
                                    const Options& options, int samples)
{
    CompiledProgram compiled{CompileProgram(program)};
    ProgramResult result{MeasureRepeated(compiled.lead, "program", std::move(compiled.sequence),
                                         std::move(compiled.stack), fixture, options, samples),
                         program, std::move(phase), std::move(compiled.features)};
    // Search the work a block can hold: cheap bodies cannot spend the budget.
    result.ratio = result.reachable_sec / options.reference_seconds;
    return result;
}

static uint32_t DrawProgramArg(std::mt19937_64& rng)
{
    // Mostly near the top of the stack, where operands and earlier results sit.
    const uint64_t draw{rng() % 10};
    if (draw < 6) return rng() % 4;
    if (draw < 9) return rng() % 16;
    std::uniform_real_distribution<double> exponent{0, std::log2(double(MAX_PROGRAM_DEPTH))};
    return static_cast<uint32_t>(std::exp2(exponent(rng)));
}

static ProgramStep DrawProgramStep(std::mt19937_64& rng, const std::vector<opcodetype>& opcodes)
{
    ProgramStep step;
    step.opcode = opcodes[rng() % opcodes.size()];
    for (size_t i{0}; i < ProgramEffect(step.opcode)->in; ++i) step.args.push_back(DrawProgramArg(rng));
    step.keep = rng() % 3 == 0;
    step.move = rng() % 3 == 0;
    return step;
}

static void MutateOperand(SearchOperand& operand, std::mt19937_64& rng)
{
    switch (rng() % 8) {
    case 0: operand.size *= 2; break;
    case 1: operand.size /= 2; break;
    case 2: operand.size = rng() % 2 ? operand.size + 1 : operand.size - std::min<size_t>(operand.size, 1); break;
    case 3: operand.size = rng() % 2 ? operand.size + 8 : operand.size - std::min<size_t>(operand.size, 8); break;
    case 4: operand.size = DrawSearchOperand(rng).size; break;
    case 5: operand.shape = SEARCH_SHAPES[rng() % SEARCH_SHAPES.size()]; break;
    case 6: operand = DrawSearchOperand(rng); break;
    default:
        if (operand.shape != SearchShape::SMALL) operand = {SearchShape::SMALL, operand.size, 0xff};
        switch (rng() % 4) {
        case 0: operand.value *= 2; break;
        case 1: operand.value /= 2; break;
        case 2: ++operand.value; break;
        default: operand.value -= std::min<uint64_t>(operand.value, 1); break;
        }
    }
    NormalizeOperand(operand);
}

static void MutateProgram(Program& program, const Program& other, std::mt19937_64& rng,
                          const std::vector<opcodetype>& opcodes)
{
    auto& stack{program.stack};
    auto& steps{program.steps};
    ProgramItem& item{stack[rng() % stack.size()]};
    const size_t at{static_cast<size_t>(rng() % steps.size())};
    ProgramStep& step{steps[at]};
    switch (rng() % 14) {
    case 0: case 1: case 2: MutateOperand(item.operand, rng); break;
    case 3: {
        const size_t position{static_cast<size_t>(rng() % (stack.size() + 1))};
        stack.insert(stack.begin() + position, ProgramItem{DrawSearchOperand(rng), 1});
        break;
    }
    case 4: if (stack.size() > 1) stack.erase(stack.begin() + rng() % stack.size()); break;
    case 5:
        switch (rng() % 3) {
        case 0: item.copies *= 2; break;
        case 1: item.copies = std::max<uint32_t>(1, item.copies / 2); break;
        default: item.copies += 1 + rng() % 16; break;
        }
        break;
    case 6: {
        const size_t position{static_cast<size_t>(rng() % (steps.size() + 1))};
        steps.insert(steps.begin() + position, DrawProgramStep(rng, opcodes));
        break;
    }
    case 7: if (steps.size() > 1) steps.erase(steps.begin() + at); break;
    case 8: {
        const opcodetype opcode{opcodes[rng() % opcodes.size()]};
        step.opcode = opcode;
        step.args.resize(ProgramEffect(opcode)->in);
        for (uint32_t& arg : step.args) arg = rng() % 2 ? arg : DrawProgramArg(rng);
        break;
    }
    case 9: {
        uint32_t& arg{step.args[rng() % step.args.size()]};
        switch (rng() % 3) {
        case 0: ++arg; break;
        case 1: arg -= std::min<uint32_t>(arg, 1); break;
        default: arg = DrawProgramArg(rng); break;
        }
        break;
    }
    case 10:
        if (rng() % 2) {
            step.move = !step.move;
        } else {
            step.keep = !step.keep;
        }
        break;
    case 11: steps.insert(steps.begin() + at, step); break;
    case 12: if (steps.size() > 1) std::swap(steps[at], steps[(at + 1) % steps.size()]); break;
    default: {
        // Splice: this program's steps up to a point, then the other's from a point.
        const size_t cut{static_cast<size_t>(rng() % (steps.size() + 1))};
        const size_t from{static_cast<size_t>(rng() % other.steps.size())};
        steps.resize(cut);
        steps.insert(steps.end(), other.steps.begin() + from, other.steps.end());
        if (rng() % 2) {
            stack.insert(stack.end(), other.stack.begin(), other.stack.end());
        }
        break;
    }
    }
    if (steps.size() > MAX_PROGRAM_STEPS) steps.resize(MAX_PROGRAM_STEPS);
    if (stack.size() > MAX_PROGRAM_ITEMS) stack.erase(stack.begin(), stack.end() - MAX_PROGRAM_ITEMS);
}

static bool WriteProgramResults(const Options& options, const std::vector<ProgramResult>& log)
{
    std::ofstream out{options.output_file};
    out << "# bench_varops program search\n"
        << strprintf("# reference_seconds=%.9g search_budget=%u seed=%u samples=%u seconds=%u top=%u epochs=%d\n",
                     options.reference_seconds, options.search_budget, options.search_seed,
                     options.search_samples, options.search_seconds, options.search_top, options.stable_rounds)
        << "# projected = wall * (40e9 - initial) / (consumed - initial); reachable = the same work\n"
        << "# limited by a direct script's weight or by macro unrolling charges; ratio = reachable / reference_seconds\n"
        << "phase,lead_opcode,program,sequence,valid,reason,repetitions,varops_consumed,initial_varops,"
           "wall_seconds,projected_full_budget_seconds,reachable_full_block_seconds,ratio,features\n";
    for (const ProgramResult& result : log) {
        const CompiledProgram compiled{CompileProgram(result.program)};
        std::string features;
        for (const std::string& feature : result.features) features += (features.empty() ? "" : " ") + feature;
        out << strprintf("%s,%s,%s,%s,%d,%s,%u,%u,%u,%.9g,%.9g,%.9g,%.9g,%s\n",
                         result.phase, OpcodeName(compiled.lead), CsvEscape(ProgramLabel(result.program)),
                         SequenceOpcodeNames(compiled.sequence), result.valid, CsvEscape(result.reason),
                         result.repetitions, result.consumed, result.initial, result.wall_sec,
                         result.projected_sec, result.reachable_sec, result.ratio, CsvEscape(features));
    }
    out.close();
    if (!out) std::cerr << "Error: could not write " << options.output_file << "\n";
    return bool(out);
}

static std::string CorpusName(const Program& program)
{
    const std::string text{ProgramText(program)};
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash;
    CSHA256().Write(UCharCast(text.data()), text.size()).Finalize(hash.data());
    return HexStr(std::span{hash}.first(8));
}

static void WriteCorpusProgram(const fs::path& directory, const Program& program)
{
    const fs::path path{directory / fs::u8path(CorpusName(program))};
    if (fs::exists(path)) return;
    std::ofstream out{path.std_path()};
    out << ProgramText(program);
    if (!out) throw std::runtime_error("could not write corpus program " + fs::PathToString(path));
}

//! Keep only the programs that are slowest for some feature, so that reloading
//! the corpus stays bounded by the number of features. Other files are left alone.
static size_t TrimCorpus(const fs::path& directory, const std::vector<const Program*>& programs)
{
    std::set<std::string> keep;
    for (const Program* program : programs) {
        WriteCorpusProgram(directory, *program);
        keep.insert(CorpusName(*program));
    }
    size_t removed{0};
    for (const auto& entry : fs::directory_iterator{directory}) {
        const std::string name{fs::PathToString(entry.path().filename())};
        const bool corpus_file{name.size() == 16 && name.find_first_not_of("0123456789abcdef") == std::string::npos};
        if (entry.is_regular_file() && corpus_file && !keep.contains(name)) {
            fs::remove(entry.path());
            ++removed;
        }
    }
    return removed;
}

static bool RunProgramSearch(const Options& options, const CryptoFixture& fixture)
{
    for (const opcodetype requested : options.selected_opcodes) {
        if (!ProgramEffect(requested)) {
            throw std::runtime_error("--program-search does not support " + OpcodeName(requested));
        }
    }
    std::vector<opcodetype> opcodes;
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        if (!ProgramEffect(entry.opcode)) continue;
        if (!options.selected_opcodes.empty() && !options.selected_opcodes.contains(entry.opcode)) continue;
        opcodes.push_back(entry.opcode);
    }
    std::optional<fs::path> corpus_dir;
    if (!options.search_corpus.empty()) {
        corpus_dir = fs::PathFromString(options.search_corpus);
        fs::create_directories(*corpus_dir);
    }

    using Clock = std::chrono::steady_clock;
    const Clock::time_point start{Clock::now()};
    const Clock::time_point deadline{start + std::chrono::seconds{options.search_seconds}};
    const auto elapsed = [&] { return std::chrono::duration<double>(Clock::now() - start).count(); };
    std::mt19937_64 rng{options.search_seed};
    std::vector<ProgramResult> retained;
    std::map<std::string, size_t> champions; // feature -> index into retained
    std::set<std::string> measured;
    std::vector<ProgramResult> log;
    uint64_t executions{0}, invalid{0};

    // Retain a program that reaches a new feature, or is slower than a feature's
    // program; a slower program is remeasured before it replaces one.
    const auto consider = [&](ProgramResult result) {
        ++executions;
        if (!result.valid) {
            ++invalid;
            return;
        }
        const auto wins = [&](const ProgramResult& candidate, double margin) {
            std::vector<std::string> won;
            bool slower{false};
            for (const std::string& feature : candidate.features) {
                const auto found{champions.find(feature)};
                if (found == champions.end()) {
                    won.push_back(feature);
                } else if (candidate.ratio > retained[found->second].ratio * margin) {
                    won.push_back(feature);
                    slower = true;
                }
            }
            return std::pair{won, slower};
        };
        auto [won, slower]{wins(result, 1 + SEARCH_IMPROVEMENT)};
        if (won.empty()) return;
        if (slower) {
            ProgramResult again{MeasureProgram(result.program, result.phase, fixture, options, PROMOTION_SAMPLES)};
            ++executions;
            if (!again.valid) return;
            std::tie(won, slower) = wins(again, 1);
            if (won.empty()) return;
            result = std::move(again);
        }
        for (const std::string& feature : won) champions[feature] = retained.size();
        if (corpus_dir && result.phase != "corpus") WriteCorpusProgram(*corpus_dir, result.program);
        log.push_back(result);
        retained.push_back(std::move(result));
    };
    const auto try_program = [&](const Program& program, std::string phase) {
        if (!measured.insert(ProgramLabel(program)).second) return;
        consider(MeasureProgram(program, std::move(phase), fixture, options, 1));
    };

    if (corpus_dir) {
        std::vector<fs::path> files;
        for (const auto& entry : fs::directory_iterator{*corpus_dir}) {
            if (entry.is_regular_file()) files.emplace_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        size_t unreadable{0};
        for (const fs::path& path : files) {
            if (Clock::now() >= deadline) break;
            std::ifstream in{path.std_path()};
            std::stringstream text;
            text << in.rdbuf();
            const std::optional<Program> program{ParseProgram(text.str())};
            if (!program) {
                ++unreadable;
                continue;
            }
            try_program(*program, "corpus");
        }
        if (!options.silent) {
            std::cout << strprintf("program search: retained %u of %u corpus programs (%u unreadable) in %.0f s\n",
                                   retained.size(), files.size(), unreadable, elapsed()) << std::flush;
        }
    }
    if (retained.empty()) {
        // Seed with single-opcode programs, one opcode after another, so a short
        // deadline still reaches every opcode.
        for (uint32_t sample{0}; sample < options.search_samples && Clock::now() < deadline; ++sample) {
            for (const opcodetype opcode : opcodes) {
                const size_t in{ProgramEffect(opcode)->in};
                Program program;
                ProgramStep step{opcode, {}, false, false};
                for (size_t i{0}; i < in; ++i) {
                    program.stack.push_back({DrawSearchOperand(rng), 1});
                    step.args.push_back(in - 1 - i);
                }
                program.steps.push_back(std::move(step));
                if (ProgramFeasible(program)) try_program(program, "seed");
            }
        }
    }
    if (retained.empty()) throw std::runtime_error("program search found no valid program to start from");

    double next_progress{double(PROGRAM_PROGRESS_SECONDS)};
    while (Clock::now() < deadline) {
        std::vector<size_t> active;
        active.reserve(champions.size());
        for (const auto& [feature, index] : champions) active.push_back(index);
        std::ranges::sort(active);
        active.erase(std::unique(active.begin(), active.end()), active.end());
        const auto choose = [&] {
            // Half uniform, for diversity; half weighted towards slow programs.
            if (rng() % 2) return active[rng() % active.size()];
            std::vector<double> weights;
            weights.reserve(active.size());
            for (const size_t index : active) weights.push_back(std::pow(retained[index].ratio, 4) + 1e-12);
            return active[std::discrete_distribution<size_t>{weights.begin(), weights.end()}(rng)];
        };
        const ProgramResult& parent{retained[choose()]};
        Program child{parent.program};
        const Program& other{retained[choose()].program};
        for (uint64_t mutations{1 + rng() % 4}; mutations != 0; --mutations) MutateProgram(child, other, rng, opcodes);
        if (ProgramFeasible(child)) try_program(child, "mutate");
        if (!options.silent && elapsed() >= next_progress) {
            next_progress += PROGRAM_PROGRESS_SECONDS;
            double best{0};
            for (const size_t index : active) best = std::max(best, retained[index].ratio);
            std::cout << strprintf("program search: %.0f s, %u executions (%.1f/s, %u invalid), %u programs, "
                                   "%u features, best screened ratio %.4f\n",
                                   elapsed(), executions, executions / elapsed(), invalid, active.size(),
                                   champions.size(), best) << std::flush;
        }
    }
    const double search_seconds{elapsed()};
    if (corpus_dir) {
        std::set<size_t> active;
        for (const auto& [feature, index] : champions) active.insert(index);
        std::vector<const Program*> programs;
        programs.reserve(active.size());
        for (const size_t index : active) programs.push_back(&retained[index].program);
        const size_t removed{TrimCorpus(*corpus_dir, programs)};
        if (!options.silent) {
            std::cout << strprintf("program search: corpus holds %u programs (%u superseded removed)\n",
                                   programs.size(), removed) << std::flush;
        }
    }

    // Confirm the slowest programs and every opcode's slowest program.
    std::vector<size_t> finalists;
    for (const auto& [feature, index] : champions) {
        if (feature.starts_with("op:") && feature.find('@') == std::string::npos) finalists.push_back(index);
    }
    std::vector<size_t> ranked;
    ranked.reserve(champions.size());
    for (const auto& [feature, index] : champions) ranked.push_back(index);
    std::ranges::sort(ranked);
    ranked.erase(std::unique(ranked.begin(), ranked.end()), ranked.end());
    std::ranges::sort(ranked, std::greater{}, [&](size_t index) { return retained[index].ratio; });
    ranked.resize(std::min<size_t>(ranked.size(), options.search_top));
    finalists.insert(finalists.end(), ranked.begin(), ranked.end());
    std::ranges::sort(finalists);
    finalists.erase(std::unique(finalists.begin(), finalists.end()), finalists.end());
    std::vector<ProgramResult> confirmed;
    for (const size_t index : finalists) {
        ProgramResult result{MeasureProgram(retained[index].program, "confirm", fixture, options, options.stable_rounds)};
        log.push_back(result);
        if (result.valid) confirmed.push_back(std::move(result));
    }
    std::ranges::sort(confirmed, std::greater{}, &ProgramResult::ratio);

    std::cout << strprintf("\nProgram search: %u executions (%u invalid) in %.0f s, %u retained, %u features, "
                           "T_pre = %.4f s, screening budget %u varops\n",
                           executions, invalid, search_seconds, retained.size(), champions.size(),
                           options.reference_seconds, options.search_budget)
              << "Ratio = full-block time of the work a block can hold / T_pre (confirmed median of "
              << options.stable_rounds << " samples)\n";
    std::cout << strprintf("%-6s %-10s %-10s %-10s %-10s %s\n", "ratio", "block_s", "budget_s", "ps/varop", "reps", "program");
    // The global top 20, then the leader of every other lead opcode.
    std::set<opcodetype> reported;
    for (size_t index{0}; index < confirmed.size(); ++index) {
        const ProgramResult& result{confirmed[index]};
        const bool first_for_opcode{reported.insert(CompileProgram(result.program).lead).second};
        if (index >= 20 && !first_for_opcode) continue;
        std::cout << strprintf("%-6.4f %-10.4f %-10.4f %-10.2f %-10u %s\n", result.ratio, result.reachable_sec,
                               result.projected_sec,
                               result.wall_sec * 1e12 / double(result.consumed - result.initial),
                               result.repetitions, ProgramLabel(result.program));
    }
    return options.output_file.empty() || WriteProgramResults(options, log);
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        Options options{ParseArguments(argc, argv)};
        std::optional<ConfirmationPlan> confirmation;
        if (!options.confirm_file.empty()) {
            confirmation = ReadConfirmationPlan(options.confirm_file, options.confirm_threshold);
            options.confirm_names = confirmation->names;
            if (confirmation->screening_ratios.empty()) {
                std::cout << strprintf("No v2 case in %s exceeds %.3fx its screening reference; nothing to confirm.\n",
                                       options.confirm_file, options.confirm_threshold);
                return 0;
            }
        }
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
        if (options.shape_search) {
            RunGlobalWarmup(fixture);
            return RunShapeSearch(options, fixture) ? 0 : 1;
        }
        if (options.program_search) {
            RunGlobalWarmup(fixture);
            return RunProgramSearch(options, fixture) ? 0 : 1;
        }
        const std::vector<CaseSpec> specs{GenerateCaseSpecs(options)};
        if (specs.empty()) throw std::runtime_error("the requested opcode set generated no cases");
        if (options.verify_costs) {
            const CostCoverage coverage{VerifyCorpusCosts(specs, fixture, options.silent)};
            RequireCostCoverage(specs, coverage);
            if (!options.coverage_manifest.empty()) {
                WriteCoverageManifest(options.coverage_manifest, coverage);
            }
            return 0;
        }
        Options verify_options{options};
        verify_options.case_filter.clear();
        verify_options.confirm_names.clear();
        const std::vector<CaseSpec> verify_specs{GenerateCaseSpecs(verify_options)};
        const CostCoverage coverage{VerifyCorpusCosts(verify_specs, fixture, true)};
        RequireCostCoverage(verify_specs, coverage);
        if (!options.coverage_manifest.empty()) WriteCoverageManifest(options.coverage_manifest, coverage);
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
        std::vector<std::string> notes;
        if (confirmation) {
            notes = ReportConfirmation(results, *confirmation, options.confirm_threshold);
            std::cout << '\n';
            for (const std::string& note : notes) std::cout << "  " << note << '\n';
        }
        if (!options.output_file.empty() &&
            !SaveResultsToFile(results, options.output_file, counts, options, notes)) {
            return 1;
        }
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "bench_varops: " << exception.what() << "\n";
        return 1;
    }
}
