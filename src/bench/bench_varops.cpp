// Copyright (c) 2025-2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <common/args.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

constexpr size_t SCRIPT_BYTES{MAX_BLOCK_WEIGHT};
constexpr uint64_t TOTAL_VAROPS_BUDGET{uint64_t{MAX_BLOCK_WEIGHT} * varops::BUDGET_PER_WEIGHT_UNIT};
constexpr uint64_t MAX_FIXTURE_POOL_BYTES{512U * 1024U * 1024U};
constexpr size_t MAX_THREE_WAY_ELEMENT_SIZE{(MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - 1) / 6};
constexpr int SIGNATURES_PER_BLOCK{80'000};
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

enum class Profile {
    FULL,
    SMOKE,
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

struct CrossoverPair {
    size_t script_limited;
    size_t varops_limited;
};

struct Options {
    std::set<opcodetype> selected_opcodes;
    int epochs{5};
    bool silent{false};
    bool list_opcodes{false};
    bool validate_only{false};
    Profile profile{Profile::FULL};
    std::string output_file;
};

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

class BenchSignatureChecker final : public BaseSignatureChecker
{
public:
    explicit BenchSignatureChecker(const CryptoFixture& fixture) : m_fixture{fixture} {}

    bool CheckSchnorrSignature(Span<const unsigned char> sig, KeyVersion keyversion,
                               Span<const unsigned char> pubkey, SigVersion,
                               ScriptExecutionData&, ScriptError* error) const override
    {
        const bool valid_key{keyversion == KeyVersion::TAPROOT &&
                             pubkey.size() == m_fixture.pubkey_bytes.size() &&
                             std::equal(pubkey.begin(), pubkey.end(), m_fixture.pubkey_bytes.begin())};
        const bool valid{valid_key && m_fixture.pubkey.VerifySchnorr(m_fixture.message, sig)};
        if (!valid && error) *error = SCRIPT_ERR_SCHNORR_SIG;
        return valid;
    }

    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }

private:
    const CryptoFixture& m_fixture;
};

using StackFactory = std::function<std::vector<valtype>(const CryptoFixture&)>;

struct CaseSpec {
    std::string name;
    opcodetype opcode{OP_INVALIDOPCODE};
    std::string opcode_name;
    std::string motif_name;
    std::string operand_shape;
    std::string operand_pattern;
    HeadlineRole role{HeadlineRole::DIAGNOSTIC};
    ScriptError expected_error{SCRIPT_ERR_OK};
    RepeatMode repeat_mode{RepeatMode::MAX_SUCCESS};
    uint64_t fixed_repetitions{0};
    uint64_t max_repetitions{std::numeric_limits<uint64_t>::max()};
    CScript motif;
    StackFactory stack_factory;
    std::optional<size_t> cleanup_items;
    std::string saturation_hint;
    std::optional<uint64_t> expected_motif_varops;
    std::optional<SaturationExpectation> expected_saturation;
};

struct MaterializedCase {
    const CaseSpec* spec{nullptr};
    std::vector<valtype> initial_stack;
    CScript script;
    uint64_t repetitions{0};
    uint64_t motif_varops{0};
    std::string saturation;
};

struct EvalOutcome {
    bool success{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t varops_consumed{0};
};

struct BenchResult {
    std::string name;
    double median_sec{0};
    double mdape{0};
    uint64_t varops_consumed{0};
    ExecutionDomain domain{ExecutionDomain::GSR_TAPSCRIPT_V2};
    HeadlineRole role{HeadlineRole::DIAGNOSTIC};
    std::string opcode_name;
    std::string motif_name;
    std::string operand_shape;
    std::string operand_pattern;
    uint64_t script_bytes{0};
    uint64_t initial_stack_items{0};
    uint64_t initial_stack_bytes{0};
    ScriptError expected_error{SCRIPT_ERR_OK};
    ScriptError actual_error{SCRIPT_ERR_OK};
    std::string saturation;
    int epochs{0};
    uint64_t repetitions{0};
    uint64_t motif_varops{0};
};

struct CorpusCounts {
    size_t requested_opcodes{0};
    size_t generated_cases{0};
    size_t completed_cases{0};
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

static ExecutionDomain DomainFor(HeadlineRole role)
{
    return role == HeadlineRole::PRE_BASELINE ? ExecutionDomain::PRE_GSR_TAPSCRIPT : ExecutionDomain::GSR_TAPSCRIPT_V2;
}

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

static uint64_t StackFixtureBytes(const std::vector<valtype>& stack)
{
    return StackPayloadBytes(stack) + uint64_t{stack.size()} * sizeof(valtype);
}

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

static CrossoverPair FindCrossoverPair(size_t motif_bytes, size_t cleanup_items, size_t maximum,
                                       const std::function<uint64_t(size_t)>& motif_cost)
{
    if (motif_bytes == 0 || cleanup_items + 1 >= SCRIPT_BYTES || maximum < 2) {
        throw std::runtime_error("invalid crossover search bounds");
    }
    const uint64_t script_limit{(SCRIPT_BYTES - cleanup_items - 1) / motif_bytes};
    const uint64_t available_budget{TOTAL_VAROPS_BUDGET - varops::comparingzero_cost(1)};
    const auto script_limited = [&](size_t size) {
        const uint64_t cost{motif_cost(size)};
        return cost == 0 || available_budget / cost >= script_limit;
    };
    if (!script_limited(1) || script_limited(maximum)) {
        throw std::runtime_error("crossover search does not bracket a transition");
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
    return {low - 1, low};
}

static std::string_view SaturationName(SaturationExpectation expectation)
{
    return expectation == SaturationExpectation::SCRIPT_BYTES ? "script-bytes" : "varops-budget";
}

static bool RunBoundarySelfChecks(std::string& error)
{
    const std::vector<valtype> pre_1000(MAX_STACK_SIZE, valtype{});
    const std::vector<valtype> pre_1001(MAX_STACK_SIZE + 1, valtype{});
    const std::vector<valtype> v2_32768(MAX_TAPSCRIPT_V2_STACK_SIZE, valtype{});
    const std::vector<valtype> v2_32769(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    if (!InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, pre_1000) ||
        InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, pre_1001) ||
        !InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, v2_32768) ||
        InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, v2_32769) ||
        !InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, {valtype(520)}) ||
        InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, {valtype(521)}) ||
        !InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, {valtype(521)})) {
        error = "internal initial-stack boundary classification failed";
        return false;
    }
    if (!NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 4, false) ||
        NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 5, false) ||
        !NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 5, true) ||
        !NumericOperandAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, 521, false)) {
        error = "internal numeric boundary classification failed";
        return false;
    }
    const CrossoverPair crossover{FindCrossoverPair(1, 1, 10'000, [](size_t size) { return 2 * size; })};
    if (crossover.script_limited != 5'000 || crossover.varops_limited != 5'001) {
        error = "internal crossover classification failed";
        return false;
    }
    if (6 * MAX_THREE_WAY_ELEMENT_SIZE + 1 > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE ||
        6 * (MAX_THREE_WAY_ELEMENT_SIZE + 1) + 1 <= MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE) {
        error = "internal three-way stack boundary classification failed";
        return false;
    }
    return true;
}

static EvalOutcome Evaluate(const MaterializedCase& test_case, const BenchSignatureChecker& checker,
                            std::vector<valtype> initial_stack)
{
    EvalOutcome outcome;
    ScriptExecutionData execdata;
    execdata.m_internal_key = XOnlyPubKey::NUMS_H;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};

    if (DomainFor(test_case.spec->role) == ExecutionDomain::PRE_GSR_TAPSCRIPT) {
        execdata.m_validation_weight_left = MAX_BLOCK_WEIGHT;
        execdata.m_validation_weight_left_init = true;
        const bool eval_ok{EvalScript(initial_stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                      checker, SigVersion::TAPSCRIPT, execdata, &error)};
        if (!eval_ok) {
            outcome.error = error;
            return outcome;
        }
        if (initial_stack.size() != 1) {
            outcome.error = SCRIPT_ERR_CLEANSTACK;
            return outcome;
        }
        if (!CastToBool(initial_stack.back())) {
            outcome.error = SCRIPT_ERR_EVAL_FALSE;
            return outcome;
        }
        outcome.success = true;
        outcome.error = SCRIPT_ERR_OK;
        return outcome;
    }

    ValtypeStack stack{initial_stack};
    varops::Budget budget{TOTAL_VAROPS_BUDGET};
    bool eval_ok{EvalTapscriptV2(stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                 checker, execdata, budget, &error)};
    if (eval_ok) eval_ok = CheckTapscriptV2ScriptResult(stack, budget, &error);
    outcome.success = eval_ok;
    outcome.error = error;
    outcome.varops_consumed = TOTAL_VAROPS_BUDGET - budget.Remaining();
    return outcome;
}

static CScript BuildScript(const CScript& motif, uint64_t repetitions, size_t cleanup_items)
{
    if (cleanup_items >= SCRIPT_BYTES) throw std::runtime_error("cleanup suffix exceeds script envelope");
    const size_t suffix_size{cleanup_items + 1};
    if (!motif.empty() && repetitions > (SCRIPT_BYTES - suffix_size) / motif.size()) {
        throw std::runtime_error("motif repetitions exceed script envelope");
    }

    CScript script;
    script.reserve(SCRIPT_BYTES);
    for (uint64_t i{0}; i < repetitions; ++i) {
        script.insert(script.end(), motif.begin(), motif.end());
    }
    const size_t padding{SCRIPT_BYTES - script.size() - suffix_size};
    script.insert(script.end(), padding, static_cast<unsigned char>(OP_NOP));
    script.insert(script.end(), cleanup_items, static_cast<unsigned char>(OP_DROP));
    script << OP_1;
    if (script.size() != SCRIPT_BYTES) throw std::runtime_error("script envelope construction failed");
    return script;
}

static uint64_t MeasureMotifVarops(const CaseSpec& spec, const std::vector<valtype>& stack,
                                   const BenchSignatureChecker& checker)
{
    if (DomainFor(spec.role) != ExecutionDomain::GSR_TAPSCRIPT_V2 || spec.motif.empty()) return 0;
    MaterializedCase calibration;
    calibration.spec = &spec;
    calibration.initial_stack = stack;
    calibration.repetitions = 1;
    calibration.script = spec.motif;
    const size_t cleanup_items{spec.cleanup_items.value_or(stack.size())};
    calibration.script.insert(calibration.script.end(), cleanup_items, static_cast<unsigned char>(OP_DROP));
    calibration.script << OP_1;
    const EvalOutcome outcome{Evaluate(calibration, checker, stack)};
    if (!outcome.success || outcome.error != SCRIPT_ERR_OK) {
        throw std::runtime_error(strprintf("one-motif calibration failed for %s: %s",
                                           spec.name, ScriptErrorString(outcome.error)));
    }
    const uint64_t final_cost{varops::comparingzero_cost(1)};
    if (outcome.varops_consumed < final_cost) {
        throw std::runtime_error("calibration consumed less than the final-result cost");
    }
    return outcome.varops_consumed - final_cost;
}

static MaterializedCase Materialize(const CaseSpec& spec, const CryptoFixture& fixture, Profile profile)
{
    MaterializedCase materialized;
    materialized.spec = &spec;
    materialized.initial_stack = spec.stack_factory(fixture);
    if (!InitialStackAllowed(DomainFor(spec.role), materialized.initial_stack)) {
        throw std::runtime_error(strprintf("%s has an invalid initial stack for %s",
                                           spec.name, DomainName(DomainFor(spec.role))));
    }

    const size_t cleanup_items{spec.cleanup_items.value_or(materialized.initial_stack.size())};
    const uint64_t suffix_size{uint64_t{cleanup_items} + 1};
    const uint64_t script_limit{spec.motif.empty() ? 0 : (SCRIPT_BYTES - suffix_size) / spec.motif.size()};
    BenchSignatureChecker checker{fixture};
    if (spec.expected_error == SCRIPT_ERR_OK || spec.repeat_mode == RepeatMode::VAROP_REJECTION) {
        materialized.motif_varops = MeasureMotifVarops(spec, materialized.initial_stack, checker);
    }
    if (spec.expected_motif_varops && materialized.motif_varops != *spec.expected_motif_varops) {
        throw std::runtime_error(strprintf("motif varops mismatch for %s: expected %u, got %u",
                                           spec.name, *spec.expected_motif_varops,
                                           materialized.motif_varops));
    }

    if (spec.repeat_mode == RepeatMode::FIXED) {
        materialized.repetitions = spec.fixed_repetitions;
        materialized.saturation = spec.saturation_hint;
    } else if (profile == Profile::SMOKE) {
        materialized.repetitions = std::min<uint64_t>({uint64_t{1}, script_limit, spec.max_repetitions});
        materialized.saturation = "smoke-profile";
    } else if (spec.repeat_mode == RepeatMode::VAROP_REJECTION) {
        if (materialized.motif_varops == 0) {
            throw std::runtime_error(strprintf("%s requests varops rejection with a zero-cost motif", spec.name));
        }
        materialized.repetitions = TOTAL_VAROPS_BUDGET / materialized.motif_varops + 1;
        materialized.saturation = "varops-limit";
    } else {
        uint64_t budget_limit{std::numeric_limits<uint64_t>::max()};
        if (DomainFor(spec.role) == ExecutionDomain::GSR_TAPSCRIPT_V2 && materialized.motif_varops != 0) {
            const uint64_t final_cost{varops::comparingzero_cost(1)};
            budget_limit = (TOTAL_VAROPS_BUDGET - final_cost) / materialized.motif_varops;
        }
        materialized.repetitions = std::min({script_limit, budget_limit, spec.max_repetitions});
        if (materialized.repetitions == budget_limit && budget_limit < script_limit) {
            materialized.saturation = "varops-budget";
        } else if (materialized.repetitions == spec.max_repetitions && spec.max_repetitions < script_limit) {
            materialized.saturation = spec.saturation_hint.empty() ? "explicit-limit" : spec.saturation_hint;
        } else {
            materialized.saturation = "script-bytes";
        }
    }

    if (spec.expected_saturation && materialized.saturation != SaturationName(*spec.expected_saturation)) {
        throw std::runtime_error(strprintf("saturation mismatch for %s: expected %s, got %s",
                                           spec.name, SaturationName(*spec.expected_saturation),
                                           materialized.saturation));
    }

    if (!spec.motif.empty() && materialized.repetitions == 0) {
        throw std::runtime_error(strprintf("%s cannot execute its target motif", spec.name));
    }
    if (!spec.motif.empty() && materialized.repetitions > script_limit) {
        throw std::runtime_error(strprintf("%s cannot reach its requested termination inside 4MB", spec.name));
    }
    materialized.script = BuildScript(spec.motif, materialized.repetitions, cleanup_items);
    return materialized;
}

static bool IsResourceError(ScriptError error)
{
    switch (error) {
    case SCRIPT_ERR_STACK_SIZE:
    case SCRIPT_ERR_PUSH_SIZE:
    case SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT:
    case SCRIPT_ERR_VAROP_COUNT:
    case SCRIPT_ERR_TOTAL_STACK_SIZE:
    case SCRIPT_ERR_STACK_ELEMENT_SIZE:
    case SCRIPT_ERR_HASH_OPERAND_SIZE:
        return true;
    default:
        return false;
    }
}

static CScript Ops(std::initializer_list<opcodetype> opcodes)
{
    CScript script;
    for (const opcodetype opcode : opcodes)
        script << opcode;
    return script;
}

static void AddSpec(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                    std::string motif_name, std::string shape,
                    std::string pattern, CScript motif, StackFactory stack_factory,
                    ScriptError expected_error = SCRIPT_ERR_OK,
                    RepeatMode repeat_mode = RepeatMode::MAX_SUCCESS,
                    uint64_t fixed_repetitions = 0,
                    uint64_t max_repetitions = std::numeric_limits<uint64_t>::max(),
                    std::optional<size_t> cleanup_items = std::nullopt,
                    std::string saturation_hint = {},
                    std::optional<uint64_t> expected_motif_varops = std::nullopt,
                    std::optional<SaturationExpectation> expected_saturation = std::nullopt)
{
    const std::string opcode_name{OpcodeName(opcode)};
    const std::string name{strprintf("%s/%s/%s/%s/%s/%s", DomainName(DomainFor(role)), opcode_name,
                                     motif_name, shape, pattern, ScriptErrorString(expected_error))};
    specs.push_back({name, opcode, opcode_name, std::move(motif_name), std::move(shape),
                     std::move(pattern), role, expected_error, repeat_mode,
                     fixed_repetitions, max_repetitions, std::move(motif),
                     std::move(stack_factory), cleanup_items, std::move(saturation_hint),
                     expected_motif_varops, expected_saturation});
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

static void AddCommonNeutral(std::vector<CaseSpec>& specs, opcodetype opcode,
                             std::string motif_name, std::string shape, std::string pattern,
                             const CScript& motif, StackFactory factory)
{
    AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
            motif_name, shape, pattern, motif, factory);
    AddSpec(specs, opcode, HeadlineRole::COMMON_V2,
            std::move(motif_name), std::move(shape), std::move(pattern), motif, std::move(factory));
}

static void AddAuditedSpec(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                           std::string motif_name, std::string shape, std::string pattern,
                           const CScript& motif, StackFactory factory, uint64_t expected_motif_varops,
                           SaturationExpectation expected_saturation)
{
    AddSpec(specs, opcode, role, std::move(motif_name), std::move(shape), std::move(pattern),
            motif, std::move(factory), SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
            std::numeric_limits<uint64_t>::max(), std::nullopt, {}, expected_motif_varops,
            expected_saturation);
}

static CScript OneToOneMotif(opcodetype opcode, bool three_way)
{
    return three_way ? Ops({OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}) : Ops({OP_DUP, opcode, OP_DROP});
}

static uint64_t OneToOneTargetCost(opcodetype opcode, size_t size)
{
    switch (opcode) {
    case OP_1ADD: return varops::add_cost(size, 1);
    case OP_1SUB: return varops::sub_cost(size, 1);
    case OP_NOT:
    case OP_0NOTEQUAL: return varops::comparingzero_cost(size);
    case OP_INVERT: return varops::invert_cost(size);
    case OP_2MUL: return varops::twomul_cost(size);
    case OP_2DIV: return varops::twodiv_cost(size);
    case OP_RIPEMD160:
    case OP_SHA1: return 0;
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256: return size * varops::COST_HASH;
    default: throw std::runtime_error("unsupported one-to-one opcode");
    }
}

static uint64_t OneToOneMotifCost(opcodetype opcode, size_t size, bool three_way)
{
    const uint64_t transforms{three_way ? 3U : 1U};
    return transforms * size * varops::COST_COPYING +
           transforms * OneToOneTargetCost(opcode, size);
}

static uint64_t TruthCopyCost(size_t size)
{
    return size * varops::COST_COPYING + varops::comparingzero_cost(size);
}

static StackFactory OneToOneStack(size_t size, std::string_view pattern, bool three_way)
{
    return FixedStack(std::vector<valtype>(three_way ? 3U : 1U, PatternBytes(size, pattern)));
}

static void AddOneToOneSpec(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                            std::string_view family, size_t size, std::string pattern, bool three_way,
                            std::optional<SaturationExpectation> expected_saturation = std::nullopt)
{
    const CScript motif{OneToOneMotif(opcode, three_way)};
    const std::string motif_name{strprintf("%s-%s", family, three_way ? "3way" : "single")};
    const std::optional<uint64_t> expected_motif_varops{
        DomainFor(role) == ExecutionDomain::GSR_TAPSCRIPT_V2 ? std::optional<uint64_t>{OneToOneMotifCost(opcode, size, three_way)} : std::nullopt};
    StackFactory factory{OneToOneStack(size, pattern, three_way)};
    AddSpec(specs, opcode, role, motif_name, FormatBytes(size), std::move(pattern), motif,
            std::move(factory), SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
            std::numeric_limits<uint64_t>::max(), std::nullopt, {}, expected_motif_varops,
            expected_saturation);
}

static std::vector<size_t> SelectSizes(Profile profile,
                                       std::initializer_list<size_t> smoke,
                                       std::initializer_list<size_t> full,
                                       size_t maximum = std::numeric_limits<size_t>::max())
{
    std::vector<size_t> sizes{profile == Profile::SMOKE ? smoke : full};
    std::erase_if(sizes, [maximum](size_t size) { return size > maximum; });
    std::sort(sizes.begin(), sizes.end());
    sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
    return sizes;
}

static std::vector<size_t> PreDataSizes(Profile profile)
{
    return SelectSizes(profile, {1, 520}, {0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 519, 520});
}

static std::vector<size_t> PreNumericSizes(Profile profile)
{
    return SelectSizes(profile, {1, 4}, {1, 3, 4});
}

static std::vector<size_t> PreCompareSizes(Profile profile)
{
    return SelectSizes(profile, {1, 520}, {0, 1, 3, 4, 5, 7, 8, 9, 16, 17, 519, 520});
}

static std::vector<size_t> V2NumericSizes(Profile profile, size_t maximum)
{
    return SelectSizes(profile, {5, 521},
                       {5, 7, 8, 9, 15, 16, 17, 519, 520, 521, 1024, 4096, 65536, 262144, 1048576, 2000000, maximum},
                       maximum);
}

static std::vector<size_t> V2LargeSizes(Profile profile, size_t maximum)
{
    return SelectSizes(profile, {521}, {521, 1024, 4096, 65536, 262144, 1048576, 2000000, maximum}, maximum);
}

static void AddUnaryDataCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile,
                              bool restored, size_t maximum = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
    if (!restored) {
        for (size_t size : PreNumericSizes(profile)) {
            const std::string pattern{"padded-low"};
            AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                            "unary-preserve", size, pattern, true);
            AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                            "unary-preserve", size, pattern, true);
        }
    }
    for (size_t size : V2NumericSizes(profile, maximum)) {
        const std::string pattern{size == maximum ? "late-nonzero" : "padded-low"};
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-preserve", size,
                        pattern, size <= MAX_THREE_WAY_ELEMENT_SIZE);
    }
    if (profile == Profile::FULL && (opcode == OP_2MUL || opcode == OP_2DIV)) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-preserve", maximum,
                        "padded-low", false);
    }
    if (profile == Profile::FULL) {
        const auto batched_cost{[opcode](size_t size) { return OneToOneMotifCost(opcode, size, true); }};
        const CrossoverPair batched{FindCrossoverPair(OneToOneMotif(opcode, true).size(), 3,
                                                      MAX_THREE_WAY_ELEMENT_SIZE, batched_cost)};
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover", batched.script_limited,
                        "padded-low", true, SaturationExpectation::SCRIPT_BYTES);
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover", batched.varops_limited,
                        "padded-low", true, SaturationExpectation::VAROPS_BUDGET);

        const auto single_cost{[opcode](size_t size) { return OneToOneMotifCost(opcode, size, false); }};
        const CrossoverPair single{FindCrossoverPair(OneToOneMotif(opcode, false).size(), 1,
                                                     MAX_THREE_WAY_ELEMENT_SIZE, single_cost)};
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover-control", single.script_limited,
                        "padded-low", false, SaturationExpectation::SCRIPT_BYTES);
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover-control", single.varops_limited,
                        "padded-low", false, SaturationExpectation::VAROPS_BUDGET);

        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-batch-boundary",
                        MAX_THREE_WAY_ELEMENT_SIZE, "dense", true);
    }
}

static void AddBinaryDataCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile,
                               bool restored, size_t maximum = 2'000'000)
{
    const bool verify_opcode{opcode == OP_EQUALVERIFY || opcode == OP_NUMEQUALVERIFY};
    const bool byte_compare{opcode == OP_EQUAL || opcode == OP_EQUALVERIFY};
    const CScript motif{verify_opcode ? Ops({OP_2DUP, opcode}) : Ops({OP_2DUP, opcode, OP_DROP})};
    if (!restored) {
        for (size_t size : byte_compare ? PreCompareSizes(profile) : PreNumericSizes(profile)) {
            const std::string pattern{opcode == OP_EQUAL || opcode == OP_EQUALVERIFY ? "equal" : "padded-low"};
            valtype first{PatternBytes(size, pattern == "equal" ? "alternating" : "padded-low")};
            valtype second{first};
            if (opcode == OP_SUB) first = PaddedNumber(3, size);
            if (opcode == OP_SUB) second = PaddedNumber(1, size);
            AddCommonNeutral(specs, opcode, "binary-preserve", FormatBytes(size) + "x" + FormatBytes(size),
                             pattern, motif, FixedStack({first, second}));
        }
    }
    for (size_t size : byte_compare ? V2LargeSizes(profile, maximum) : V2NumericSizes(profile, maximum)) {
        valtype first{PatternBytes(size, "alternating")};
        valtype second{first};
        if (opcode == OP_SUB) {
            first = PaddedNumber(3, size);
            second = PaddedNumber(1, size);
        }
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(size) + "x" + FormatBytes(size), "equal-dense",
                motif, FixedStack({first, second}));
    }
    if (profile == Profile::FULL && (opcode == OP_MIN || opcode == OP_MAX)) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(maximum) + "x" + FormatBytes(maximum), "equal-padded-low",
                motif, FixedStack({PaddedNumber(1, maximum), PaddedNumber(1, maximum)}));
    }
    if (profile == Profile::FULL && maximum >= 65536 && opcode != OP_EQUALVERIFY) {
        const bool numeric_verify{opcode == OP_NUMEQUALVERIFY};
        const bool subtraction{opcode == OP_SUB};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", "64KBx1B", "asymmetric-long-short", motif,
                FixedStack({subtraction ? PaddedNumber(3, 65536) : (numeric_verify ? PaddedNumber(1, 65536) : PatternBytes(65536, "alternating")),
                            subtraction ? PaddedNumber(1, 1) : PatternBytes(1, "one-low")}));
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", "1Bx64KB", "asymmetric-short-long", motif,
                FixedStack({subtraction ? PaddedNumber(3, 1) : PatternBytes(1, "one-low"),
                            subtraction ? PaddedNumber(1, 65536) : (numeric_verify ? PaddedNumber(1, 65536) : PatternBytes(65536, "alternating"))}));
    }
}

static void AddStackOpcodeCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const auto common = [&](std::string motif_name, CScript motif, std::vector<valtype> stack) {
        AddCommonNeutral(specs, opcode, std::move(motif_name), "32B", "dense", motif,
                         FixedStack(std::move(stack)));
    };
    switch (opcode) {
    case OP_TOALTSTACK:
    case OP_FROMALTSTACK:
        common("altstack-roundtrip", Ops({OP_TOALTSTACK, OP_FROMALTSTACK}), {PatternBytes(32, "dense")});
        break;
    case OP_DROP: common("dup-drop", Ops({OP_DUP, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_2DROP: common("2dup-2drop", Ops({OP_2DUP, OP_2DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_DUP: common("dup-drop", Ops({OP_DUP, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_2DUP: common("2dup-2drop", Ops({OP_2DUP, OP_2DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_3DUP: common("3dup-cleanup", Ops({OP_3DUP, OP_2DROP, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_OVER: common("over-drop", Ops({OP_OVER, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_2OVER: common("2over-2drop", Ops({OP_2OVER, OP_2DROP}), std::vector<valtype>(4, PatternBytes(32, "dense"))); break;
    case OP_IFDUP: {
        const CScript true_motif{Ops({OP_IFDUP, OP_DROP})};
        AddCommonNeutral(specs, opcode, "ifdup-drop", "1B", "true", true_motif,
                         FixedStack({valtype{1}}));
        if (profile == Profile::FULL) {
            const CScript false_motif{Ops({OP_IFDUP})};
            AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "ifdup-true", "520B", "late-nonzero", true_motif,
                    FixedStack({PatternBytes(520, "late-nonzero")}));
            AddSpec(specs, opcode, HeadlineRole::COMMON_V2,
                    "ifdup-true", "520B", "late-nonzero", true_motif,
                    FixedStack({PatternBytes(520, "late-nonzero")}), SCRIPT_ERR_OK,
                    RepeatMode::MAX_SUCCESS, 0, std::numeric_limits<uint64_t>::max(),
                    std::nullopt, {}, TruthCopyCost(520));
            AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "ifdup-false", "520B", "zero", false_motif,
                    FixedStack({PatternBytes(520, "zero")}));
            AddSpec(specs, opcode, HeadlineRole::COMMON_V2,
                    "ifdup-false", "520B", "zero", false_motif,
                    FixedStack({PatternBytes(520, "zero")}), SCRIPT_ERR_OK,
                    RepeatMode::MAX_SUCCESS, 0, std::numeric_limits<uint64_t>::max(),
                    std::nullopt, {}, TruthCopyCost(520));

            const CrossoverPair true_cross{FindCrossoverPair(true_motif.size(), 1,
                                                             MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE,
                                                             TruthCopyCost)};
            for (const auto& [size, expectation] : std::array{
                     std::pair{true_cross.script_limited, SaturationExpectation::SCRIPT_BYTES},
                     std::pair{true_cross.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
                AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "ifdup-true-crossover",
                               FormatBytes(size), "late-nonzero", true_motif,
                               FixedStack({PatternBytes(size, "late-nonzero")}),
                               TruthCopyCost(size), expectation);
            }

            const CrossoverPair false_cross{FindCrossoverPair(false_motif.size(), 1,
                                                              MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE,
                                                              TruthCopyCost)};
            for (const auto& [size, expectation] : std::array{
                     std::pair{false_cross.script_limited, SaturationExpectation::SCRIPT_BYTES},
                     std::pair{false_cross.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
                AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "ifdup-false-crossover",
                               FormatBytes(size), "zero", false_motif,
                               FixedStack({PatternBytes(size, "zero")}), TruthCopyCost(size),
                               expectation);
            }
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "ifdup-true-scale-tail", "4MB", "late-nonzero", true_motif,
                    FixedStack({PatternBytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero")}),
                    SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                    std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                    TruthCopyCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
        }
        break;
    }
    case OP_NIP: common("2dup-nip-drop", Ops({OP_2DUP, OP_NIP, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_TUCK: common("tuck-drop-swap", Ops({OP_TUCK, OP_DROP, OP_SWAP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_SWAP: common("swap-twice", Ops({OP_SWAP, OP_SWAP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_2SWAP: common("2swap-twice", Ops({OP_2SWAP, OP_2SWAP}), std::vector<valtype>(4, PatternBytes(32, "dense"))); break;
    case OP_ROT: common("rot-thrice", Ops({OP_ROT, OP_ROT, OP_ROT}), std::vector<valtype>(3, PatternBytes(32, "dense"))); break;
    case OP_2ROT: common("2rot-thrice", Ops({OP_2ROT, OP_2ROT, OP_2ROT}), std::vector<valtype>(6, PatternBytes(32, "dense"))); break;
    case OP_DEPTH: common("depth-drop", Ops({OP_DEPTH, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_PICK: {
        common("pick-depth-1", Ops({OP_DUP, OP_PICK, OP_DROP}),
               {PatternBytes(32, "dense"), PatternBytes(32, "alternating"), Val64(1).move_to_valtype()});
        if (profile == Profile::FULL) {
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR, "pick-max-depth-one-shot", "32768-items", "heterogeneous-buried", Ops({OP_PICK}), [](const CryptoFixture&) {
                        std::vector<valtype> stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{0x01});
                        stack.front() = PatternBytes(520, "late-nonzero");
                        stack.push_back(Val64(MAX_TAPSCRIPT_V2_STACK_SIZE - 2).move_to_valtype());
                        return stack; }, SCRIPT_ERR_OK, RepeatMode::FIXED, 1, 1, MAX_TAPSCRIPT_V2_STACK_SIZE, "stack-depth");
        }
        break;
    }
    case OP_ROLL: {
        CScript roll_one;
        roll_one << OP_1 << OP_ROLL << OP_SWAP;
        common("roll-depth-1-neutral", roll_one, {PatternBytes(32, "dense"), PatternBytes(32, "alternating")});
        if (profile == Profile::FULL) {
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR, "roll-max-depth-one-shot", "32768-items", "heterogeneous-buried", Ops({OP_ROLL}), [](const CryptoFixture&) {
                        std::vector<valtype> stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{0x01});
                        stack.front() = PatternBytes(520, "late-nonzero");
                        stack.push_back(Val64(MAX_TAPSCRIPT_V2_STACK_SIZE - 2).move_to_valtype());
                        return stack; }, SCRIPT_ERR_OK, RepeatMode::FIXED, 1, 1, MAX_TAPSCRIPT_V2_STACK_SIZE - 1, "stack-depth");
        }
        break;
    }
    default: throw std::runtime_error("unhandled stack opcode registry entry");
    }

    if (profile == Profile::FULL && (opcode == OP_DUP || opcode == OP_2DUP || opcode == OP_OVER)) {
        const CScript motif{opcode == OP_DUP  ? Ops({OP_DUP, OP_DROP}) :
                            opcode == OP_2DUP ? Ops({OP_2DUP, OP_2DROP}) :
                                                Ops({OP_OVER, OP_DROP})};
        const size_t count{opcode == OP_DUP ? 1U : 2U};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "large-copy", opcode == OP_DUP ? "4MB" : "2MBx2", "late-nonzero", motif,
                [count](const CryptoFixture&) { return std::vector<valtype>(count, PatternBytes(4'000'000 / count, "late-nonzero")); });
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR, "large-copy-varops-reject", opcode == OP_DUP ? "4MB" : "2MBx2", "late-nonzero", motif, [count](const CryptoFixture&) { return std::vector<valtype>(count, PatternBytes(4'000'000 / count, "late-nonzero")); }, SCRIPT_ERR_VAROP_COUNT, RepeatMode::VAROP_REJECTION);
    }
}

static void AddHashCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    for (size_t size : PreDataSizes(profile)) {
        const std::string pattern{size == 0 ? "zero" : "late-nonzero"};
        AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                        "hash-preserve", size, pattern, true);
        AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                        "hash-preserve", size, pattern, true);
    }
    if (opcode == OP_RIPEMD160 || opcode == OP_SHA1) {
        AddSpec(specs, opcode, HeadlineRole::DIAGNOSTIC,
                "hash-legacy-limit", "521B", "dense", Ops({opcode}), FixedStack({PatternBytes(521, "dense")}),
                SCRIPT_ERR_HASH_OPERAND_SIZE, RepeatMode::FIXED, 1, 1, 0, "hash-operand-limit");
        return;
    }
    for (size_t size : V2LargeSizes(profile, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-preserve", size,
                        "late-nonzero", size <= MAX_THREE_WAY_ELEMENT_SIZE);
    }
    if (profile == Profile::FULL) {
        const auto batched_cost{[opcode](size_t size) { return OneToOneMotifCost(opcode, size, true); }};
        const CrossoverPair batched{FindCrossoverPair(OneToOneMotif(opcode, true).size(), 3,
                                                      MAX_SCRIPT_ELEMENT_SIZE, batched_cost)};
        for (const auto& [size, expectation] : std::array{
                 std::pair{batched.script_limited, SaturationExpectation::SCRIPT_BYTES},
                 std::pair{batched.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
            AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                            "hash-crossover", size, "late-nonzero", true,
                            SaturationExpectation::SCRIPT_BYTES);
            AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                            "hash-crossover", size, "late-nonzero", true, expectation);
        }

        const auto single_cost{[opcode](size_t size) { return OneToOneMotifCost(opcode, size, false); }};
        const CrossoverPair single{FindCrossoverPair(OneToOneMotif(opcode, false).size(), 1,
                                                     MAX_THREE_WAY_ELEMENT_SIZE, single_cost)};
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-crossover-control",
                        single.script_limited, "late-nonzero", false,
                        SaturationExpectation::SCRIPT_BYTES);
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-crossover-control",
                        single.varops_limited, "late-nonzero", false,
                        SaturationExpectation::VAROPS_BUDGET);
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-batch-boundary",
                        MAX_THREE_WAY_ELEMENT_SIZE, "dense", true);

        const CScript motif{OneToOneMotif(opcode, false)};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "hash-varops-reject-single", "4MB", "late-nonzero", motif,
                FixedStack({PatternBytes(4'000'000, "late-nonzero")}), SCRIPT_ERR_VAROP_COUNT,
                RepeatMode::VAROP_REJECTION, 0, std::numeric_limits<uint64_t>::max(),
                std::nullopt, {}, OneToOneMotifCost(opcode, 4'000'000, false));
    }
}

static void AddSpliceCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    if (opcode == OP_CAT) {
        const CScript motif{Ops({OP_2DUP, OP_CAT, OP_DROP})};
        const std::vector<std::pair<size_t, size_t>> shapes{profile == Profile::SMOKE ?
                                                                std::vector<std::pair<size_t, size_t>>{{1, 1}, {521, 521}} :
                                                                std::vector<std::pair<size_t, size_t>>{{0, 1}, {1, 1}, {520, 520}, {521, 521}, {65536, 1}, {1, 65536}, {1048576, 1048576}, {2000000, 2000000}}};
        for (const auto& [left, right] : shapes) {
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "cat-preserve", FormatBytes(left) + "+" + FormatBytes(right), "asymmetric-dense", motif,
                    FixedStack({PatternBytes(left, "alternating"), PatternBytes(right, "late-nonzero")}));
        }
        if (profile == Profile::FULL) {
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "cat-element-reject", "2000001B+2000001B", "dense", Ops({OP_CAT}),
                    FixedStack({PatternBytes(2'000'001, "dense"), PatternBytes(2'000'001, "dense")}),
                    SCRIPT_ERR_STACK_ELEMENT_SIZE, RepeatMode::FIXED, 1, 1, 0, "stack-element-limit");
        }
        return;
    }

    // Leave room for duplicated, heavily padded offset/length operands while
    // keeping the data operand as close to the 4MB element limit as possible.
    const size_t data_size{profile == Profile::SMOKE ? 521U : 3'998'900U};
    if (opcode == OP_SUBSTR) {
        const CScript motif{Ops({OP_3DUP, OP_SUBSTR, OP_DROP})};
        const std::vector<std::tuple<uint64_t, uint64_t, std::string>> params{
            {0, 1, "zero-one"},
            {1, data_size / 2, "one-mid"},
            {data_size / 2, data_size, "mid-past-end"},
        };
        for (const auto& [begin, length, pattern] : params) {
            const size_t numeric_size{pattern == "mid-past-end" && profile == Profile::FULL ? 521U : 8U};
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "substr-preserve", FormatBytes(data_size) + ":" + pattern, numeric_size > 8 ? "padded-lengths" : "minimal-lengths",
                    motif, FixedStack({PatternBytes(data_size, "alternating"), PaddedNumber(begin, numeric_size), PaddedNumber(length, numeric_size)}));
        }
        return;
    }

    const CScript motif{Ops({OP_2DUP, opcode, OP_DROP})};
    for (const auto& [offset, label] : std::vector<std::pair<uint64_t, std::string>>{
             {0, "zero"}, {1, "one"}, {data_size / 2, "mid"}, {data_size, "end"}, {data_size + 1, "past-end"}}) {
        const size_t numeric_size{label == "past-end" && profile == Profile::FULL ? 521U : 8U};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "splice-preserve", FormatBytes(data_size) + ":" + label,
                numeric_size > 8 ? "padded-offset" : "minimal-offset", motif,
                FixedStack({PatternBytes(data_size, "alternating"), PaddedNumber(offset, numeric_size)}));
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

static uint64_t MulMotifCost(size_t left, size_t right)
{
    return (left + right) * varops::COST_COPYING + varops::mul_cost(left, right);
}

static void AddMulCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{Ops({OP_2DUP, opcode, OP_DROP})};
    std::vector<std::pair<size_t, size_t>> shapes{{1, 1}, {109, 109}};
    if (profile == Profile::FULL) {
        const size_t largest{LargestAffordable([](size_t size) { return varops::mul_cost(size, size); }, 2'000'000)};
        shapes.insert(shapes.end(), {{108, 108}, {110, 110}, {65536, 1}, {1, 65536}, {largest > 1 ? largest - 1 : largest, largest}, {largest, largest}, {largest + 1, largest + 1}});
    }
    for (const auto& [left, right] : shapes) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-preserve", FormatBytes(left) + "x" + FormatBytes(right), "dense", motif,
                FixedStack({PatternBytes(left, "alternating"), PatternBytes(right, "late-nonzero")}));
    }
    if (profile == Profile::FULL) {
        for (unsigned int ratio : {1U, 4U, 16U, 0U}) {
            const auto right_size{[ratio](size_t left) {
                return ratio == 0 ? size_t{1} : std::max<size_t>(1, left / ratio);
            }};
            const auto motif_cost{[&](size_t left) {
                return MulMotifCost(left, right_size(left));
            }};
            const CrossoverPair crossover{FindCrossoverPair(motif.size(), 2, 2'000'000, motif_cost)};
            for (const auto& [left, expectation] : std::array{
                     std::pair{crossover.script_limited, SaturationExpectation::SCRIPT_BYTES},
                     std::pair{crossover.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
                const size_t right{right_size(left)};
                AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "mul-crossover",
                               FormatBytes(left) + "x" + FormatBytes(right),
                               ratio == 1 ? "balanced-dense" :
                               ratio == 0 ? "asymmetric-one-byte" :
                                            strprintf("asymmetric-%u-to-1", ratio),
                               motif,
                               FixedStack({PatternBytes(left, "alternating"),
                                           PatternBytes(right, "late-nonzero")}),
                               motif_cost(left), expectation);
            }
        }
        constexpr size_t tail_left{2'000'000};
        constexpr size_t tail_right{1};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-scale-tail", FormatBytes(tail_left) + "x1B", "asymmetric-long-short",
                motif, FixedStack({PatternBytes(tail_left, "alternating"), PatternBytes(tail_right, "late-nonzero")}),
                SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                MulMotifCost(tail_left, tail_right));

        const size_t rejected{LargestAffordable([](size_t size) { return varops::mul_cost(size, size); }, 2'000'000)};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-varops-reject", FormatBytes(rejected), "dense", motif,
                FixedStack({PatternBytes(rejected, "alternating"), PatternBytes(rejected, "late-nonzero")}),
                SCRIPT_ERR_VAROP_COUNT, RepeatMode::VAROP_REJECTION);
    }
}

static valtype DivisorTopClear(size_t size)
{
    return valtype(size, 0x7f);
}

static valtype DivisorTopLimbOne(size_t size)
{
    valtype divisor(size, 0);
    if (size == 0) return divisor;
    divisor.front() = 0xff;
    const size_t top_limb_start{(size - 1) / sizeof(uint64_t) * sizeof(uint64_t)};
    divisor[top_limb_start] = 0x01;
    return divisor;
}

static uint64_t DivModMotifCost(opcodetype opcode, size_t dividend, size_t divisor)
{
    const uint64_t operation_cost{opcode == OP_DIV ? varops::div_cost(dividend, divisor) : varops::mod_cost(dividend, divisor)};
    return (dividend + divisor) * varops::COST_COPYING + operation_cost;
}

static void AddDivModCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{Ops({OP_2DUP, opcode, OP_DROP})};
    const auto add = [&](valtype dividend, valtype divisor, std::string shape, std::string pattern) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-preserve", std::move(shape), std::move(pattern), motif,
                FixedStack({std::move(dividend), std::move(divisor)}));
    };
    add(valtype{0x0a}, valtype{0x03}, "1Bx1B", "normalization-short");
    add(PatternBytes(17, "dense"), DivisorTopClear(9), "17Bx9B", "normalization-top-clear");
    add(PatternBytes(8, "one-low"), PatternBytes(16, "late-nonzero"), "8Bx16B", "dividend-smaller");
    if (profile == Profile::FULL) {
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
            const auto motif_cost{[&](size_t dividend) {
                return DivModMotifCost(opcode, dividend, divisor_size(dividend));
            }};
            const CrossoverPair crossover{FindCrossoverPair(motif.size(), 2, 2'000'000, motif_cost)};
            for (const auto& [dividend, expectation] : std::array{
                     std::pair{crossover.script_limited, SaturationExpectation::SCRIPT_BYTES},
                     std::pair{crossover.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
                const size_t size{divisor_size(dividend)};
                valtype divisor{rectangular.pattern == DivisorPattern::TOP_CLEAR ? DivisorTopClear(size) : rectangular.pattern == DivisorPattern::TOP_LIMB_ONE ? DivisorTopLimbOne(size) :
                                                                                                                                                                 PatternBytes(size, "dense")};
                AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "divmod-crossover",
                               FormatBytes(dividend) + "x" + FormatBytes(size),
                               std::string{rectangular.name}, motif,
                               FixedStack({PatternBytes(dividend, "dense"), std::move(divisor)}),
                               motif_cost(dividend), expectation);
            }
        }
        constexpr size_t tail_dividend{65536};
        constexpr size_t tail_divisor{16384};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-scale-tail", "64KBx16KB", "asymmetric-quarter-top-clear", motif,
                FixedStack({PatternBytes(tail_dividend, "dense"), DivisorTopClear(tail_divisor)}),
                SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                DivModMotifCost(opcode, tail_dividend, tail_divisor));

        const size_t largest{LargestAffordable([opcode](size_t size) {
            return opcode == OP_DIV ? varops::div_cost(size, size) : varops::mod_cost(size, size);
        },
                                               2'000'000)};
        for (size_t size : {largest > 1 ? largest - 1 : largest, largest, largest + 1}) {
            add(PatternBytes(size, "dense"), DivisorTopLimbOne(size),
                FormatBytes(size) + "x" + FormatBytes(size), "largest-normalized");
        }
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-varops-reject", FormatBytes(largest), "largest-normalized", motif,
                FixedStack({PatternBytes(largest, "dense"), DivisorTopLimbOne(largest)}),
                SCRIPT_ERR_VAROP_COUNT, RepeatMode::VAROP_REJECTION);
    }
}

static uint64_t ShiftMotifCost(opcodetype opcode, size_t size, uint64_t shift)
{
    const size_t shift_size{Val64(shift).move_to_valtype().size()};
    const uint64_t copy_cost{(size + shift_size) * varops::COST_COPYING};
    const uint64_t prebytes{shift / 8};
    if (opcode == OP_RSHIFT) {
        return copy_cost + varops::lengthconv_cost(shift_size) +
               (prebytes < size ? size - prebytes : 0) * varops::COST_COPYING;
    }
    if (opcode != OP_LSHIFT) throw std::runtime_error("unsupported shift opcode");
    return copy_cost + varops::lengthconv_cost(shift_size) + prebytes * varops::COST_FAST +
           size * varops::COST_COPYING +
           (shift % 8 == 0 ? 0 : varops::upshift_bitshift_cost(size, prebytes));
}

static void AddShiftCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{Ops({OP_2DUP, opcode, OP_DROP})};
    std::vector<std::pair<size_t, uint64_t>> shapes{{1, 1}, {17, 9}, {17, 56}, {17, 65}};
    if (profile == Profile::FULL) {
        shapes.insert(shapes.end(), {{1024, 8}, {1024, 1032}, {1024, 1033}, {65536, 524288}, {1, uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1} * 8}});
    }
    for (const auto& [size, shift] : shapes) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-preserve", FormatBytes(size) + ":" + strprintf("%ubits", shift),
                shift % 8 == 0 ? "byte-aligned" : "unaligned", motif,
                FixedStack({PatternBytes(size, "late-nonzero"), Val64(shift).move_to_valtype()}));
    }
    if (profile == Profile::FULL) {
        for (uint64_t shift : {8U, 65U}) {
            const auto motif_cost{[opcode, shift](size_t size) {
                return ShiftMotifCost(opcode, size, shift);
            }};
            const CrossoverPair crossover{FindCrossoverPair(motif.size(), 2, 2'000'000, motif_cost)};
            for (const auto& [size, expectation] : std::array{
                     std::pair{crossover.script_limited, SaturationExpectation::SCRIPT_BYTES},
                     std::pair{crossover.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
                AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "shift-crossover",
                               FormatBytes(size) + ":" + strprintf("%ubits", shift),
                               shift % 8 == 0 ? "byte-aligned" : "unaligned", motif,
                               FixedStack({PatternBytes(size, "late-nonzero"),
                                           Val64(shift).move_to_valtype()}),
                               motif_cost(size), expectation);
            }
        }
        constexpr size_t tail_size{2'000'000};
        constexpr uint64_t tail_shift{1};
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-scale-tail", FormatBytes(tail_size) + ":1bit", "unaligned", motif,
                FixedStack({PatternBytes(tail_size, "late-nonzero"),
                            Val64(tail_shift).move_to_valtype()}),
                SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                ShiftMotifCost(opcode, tail_size, tail_shift));
    }
    if (profile == Profile::FULL && opcode == OP_LSHIFT) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-element-reject", "1B:past-4MB", "past-end", Ops({OP_LSHIFT}),
                FixedStack({valtype{1}, Val64(uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE} * 8).move_to_valtype()}),
                SCRIPT_ERR_STACK_ELEMENT_SIZE, RepeatMode::FIXED, 1, 1, 0, "stack-element-limit");
    }
}

static void AddSignatureCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{opcode == OP_CHECKSIG       ? Ops({OP_2DUP, OP_CHECKSIG, OP_DROP}) :
                        opcode == OP_CHECKSIGVERIFY ? Ops({OP_2DUP, OP_CHECKSIGVERIFY}) :
                                                      Ops({OP_3DUP, OP_CHECKSIGADD, OP_DROP})};
    const auto valid_factory = [opcode](const CryptoFixture& fixture) {
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{fixture.signature, valtype{}, fixture.pubkey_bytes};
        return std::vector<valtype>{fixture.signature, fixture.pubkey_bytes};
    };
    AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
            "signature-preserve", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", motif, valid_factory, SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
            profile == Profile::SMOKE ? 1 : SIGNATURES_PER_BLOCK, std::nullopt, "validation-weight");
    AddSpec(specs, opcode, HeadlineRole::COMMON_V2,
            "signature-preserve", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", motif, valid_factory);

    if (profile == Profile::FULL) {
        AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                "signature-validation-weight-reject", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
                "valid-fixed-message", motif, valid_factory, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT,
                RepeatMode::FIXED, SIGNATURES_PER_BLOCK + 1, SIGNATURES_PER_BLOCK + 1, std::nullopt,
                "validation-weight-limit");
    }

    const auto empty_factory = [opcode](const CryptoFixture& fixture) {
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{valtype{}, PaddedNumber(1, 521), fixture.pubkey_bytes};
        return std::vector<valtype>{valtype{}, fixture.pubkey_bytes};
    };
    const bool empty_verify_failure{opcode == OP_CHECKSIGVERIFY};
    AddSpec(specs, opcode,
            empty_verify_failure ? HeadlineRole::DIAGNOSTIC : (opcode == OP_CHECKSIGADD ? HeadlineRole::NEW_GSR : HeadlineRole::COMMON_V2),
            "signature-empty", opcode == OP_CHECKSIGADD ? "0B+521B+32B" : "0B+32B",
            "empty-signature", motif, empty_factory,
            empty_verify_failure ? SCRIPT_ERR_CHECKSIGVERIFY : SCRIPT_ERR_OK,
            empty_verify_failure ? RepeatMode::FIXED : RepeatMode::MAX_SUCCESS,
            empty_verify_failure ? 1 : 0, std::numeric_limits<uint64_t>::max(),
            empty_verify_failure ? std::optional<size_t>{0} : std::nullopt,
            empty_verify_failure ? "semantic-failure" : "");

    if (profile == Profile::FULL) {
        const auto invalid_factory = [opcode](const CryptoFixture& fixture) {
            valtype invalid{fixture.signature};
            invalid.front() ^= 1;
            if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{invalid, valtype{}, fixture.pubkey_bytes};
            return std::vector<valtype>{invalid, fixture.pubkey_bytes};
        };
        AddSpec(specs, opcode, HeadlineRole::DIAGNOSTIC,
                "signature-invalid", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
                "invalid-fixed-message", motif, invalid_factory, SCRIPT_ERR_SCHNORR_SIG,
                RepeatMode::FIXED, 1, 1, 0, "semantic-failure");
    }
}

static uint64_t TimelockMotifCost(size_t size)
{
    return varops::lengthconv_cost(size);
}

static void AddTimelockCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{Ops({opcode})};
    for (size_t size : (profile == Profile::SMOKE ? std::vector<size_t>{5} : std::vector<size_t>{4, 5})) {
        AddCommonNeutral(specs, opcode, "timelock-preserve", FormatBytes(size), "padded-one", motif,
                         FixedStack({PaddedNumber(1, size)}));
    }
    for (size_t size : V2LargeSizes(profile, profile == Profile::SMOKE ? 521 : 65536)) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "timelock-preserve", FormatBytes(size), "padded-one", motif,
                FixedStack({PaddedNumber(1, size)}));
    }
    if (profile == Profile::FULL) {
        const CrossoverPair crossover{FindCrossoverPair(motif.size(), 1,
                                                        MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE,
                                                        TimelockMotifCost)};
        for (const auto& [size, expectation] : std::array{
                 std::pair{crossover.script_limited, SaturationExpectation::SCRIPT_BYTES},
                 std::pair{crossover.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
            AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "timelock-crossover",
                           FormatBytes(size), "padded-one", motif,
                           FixedStack({PaddedNumber(1, size)}), TimelockMotifCost(size),
                           expectation);
        }
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "timelock-scale-tail", "4MB", "padded-one", motif,
                FixedStack({PaddedNumber(1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)}),
                SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                TimelockMotifCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
    }
}

static void AddControlAndFloorCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const auto forced_push = [](opcodetype push_opcode, size_t size) {
        CScript motif;
        motif.push_back(static_cast<unsigned char>(push_opcode));
        if (push_opcode == OP_PUSHDATA1) {
            motif.push_back(static_cast<unsigned char>(size));
        } else if (push_opcode == OP_PUSHDATA2) {
            motif.push_back(static_cast<unsigned char>(size & 0xff));
            motif.push_back(static_cast<unsigned char>((size >> 8) & 0xff));
        } else {
            for (unsigned int shift : {0U, 8U, 16U, 24U}) {
                motif.push_back(static_cast<unsigned char>((size >> shift) & 0xff));
            }
        }
        motif.insert(motif.end(), size, 0x42);
        motif << OP_DROP;
        return motif;
    };

    switch (opcode) {
    case OP_NOP:
    case OP_CODESEPARATOR:
        AddCommonNeutral(specs, opcode, "interpreter-floor", "no-operands", "executed", Ops({opcode}), FixedStack({}));
        if (opcode == OP_NOP && profile == Profile::FULL) {
            AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "max-initial-stack", "1000-items", "empty-items", Ops({OP_NOP}),
                    FixedStack(std::vector<valtype>(MAX_STACK_SIZE, valtype{})));
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "max-initial-stack", "32768-items", "empty-items", Ops({OP_NOP}),
                    FixedStack(std::vector<valtype>(MAX_TAPSCRIPT_V2_STACK_SIZE, valtype{})));
        }
        break;
    case OP_0:
        AddCommonNeutral(specs, opcode, "push-drop", "0B", "push-parse", Ops({OP_0, OP_DROP}), FixedStack({}));
        if (profile == Profile::FULL) {
            AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "push-stack-reject", "1001-pushes", "empty-items", Ops({OP_0}), FixedStack({}),
                    SCRIPT_ERR_STACK_SIZE, RepeatMode::FIXED, MAX_STACK_SIZE + 1, MAX_STACK_SIZE + 1, 0,
                    "stack-count-limit");
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "push-stack-reject", "32769-pushes", "empty-items", Ops({OP_0}), FixedStack({}),
                    SCRIPT_ERR_STACK_SIZE, RepeatMode::FIXED, MAX_TAPSCRIPT_V2_STACK_SIZE + 1,
                    MAX_TAPSCRIPT_V2_STACK_SIZE + 1, 0, "stack-count-limit");
        }
        break;
    case OP_PUSHDATA1:
        AddCommonNeutral(specs, opcode, "pushdata1-drop", "76B", "forced-push-encoding",
                         forced_push(OP_PUSHDATA1, 76), FixedStack({}));
        break;
    case OP_PUSHDATA2:
        AddCommonNeutral(specs, opcode, "pushdata2-drop", "520B", "forced-push-encoding",
                         forced_push(OP_PUSHDATA2, 520), FixedStack({}));
        AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                "pushdata2-element-reject", "521B", "forced-push-encoding",
                forced_push(OP_PUSHDATA2, 521), FixedStack({}), SCRIPT_ERR_PUSH_SIZE,
                RepeatMode::FIXED, 1, 1, 0, "push-element-limit");
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata2-drop", "521B", "forced-push-encoding",
                forced_push(OP_PUSHDATA2, 521), FixedStack({}));
        break;
    case OP_PUSHDATA4:
        AddCommonNeutral(specs, opcode, "pushdata4-drop", "1B", "forced-nonminimal-encoding",
                         forced_push(OP_PUSHDATA4, 1), FixedStack({}));
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata4-drop", "64KB", "forced-push-encoding",
                forced_push(OP_PUSHDATA4, 65536), FixedStack({}));
        break;
    case OP_VERIFY: {
        AddCommonNeutral(specs, opcode, "true-verify", "1B", "true", Ops({OP_1, OP_VERIFY}), FixedStack({}));
        if (profile == Profile::FULL) {
            const CScript motif{Ops({OP_DUP, OP_VERIFY})};
            AddSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "verify-preserve", "520B", "late-nonzero", motif,
                    FixedStack({PatternBytes(520, "late-nonzero")}));
            AddSpec(specs, opcode, HeadlineRole::COMMON_V2,
                    "verify-preserve", "520B", "late-nonzero", motif,
                    FixedStack({PatternBytes(520, "late-nonzero")}), SCRIPT_ERR_OK,
                    RepeatMode::MAX_SUCCESS, 0, std::numeric_limits<uint64_t>::max(),
                    std::nullopt, {}, TruthCopyCost(520));
            const CrossoverPair crossover{FindCrossoverPair(motif.size(), 1,
                                                            MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE,
                                                            TruthCopyCost)};
            for (const auto& [size, expectation] : std::array{
                     std::pair{crossover.script_limited, SaturationExpectation::SCRIPT_BYTES},
                     std::pair{crossover.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
                AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "verify-crossover",
                               FormatBytes(size), "late-nonzero", motif,
                               FixedStack({PatternBytes(size, "late-nonzero")}),
                               TruthCopyCost(size), expectation);
            }
            AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                    "verify-scale-tail", "4MB", "late-nonzero", motif,
                    FixedStack({PatternBytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero")}),
                    SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                    std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                    TruthCopyCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
        }
        break;
    }
    case OP_IF:
        AddCommonNeutral(specs, opcode, "executed-if", "1B", "true-branch", Ops({OP_1, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        AddCommonNeutral(specs, opcode, "skipped-if", "0B", "false-branch", Ops({OP_0, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        break;
    default: throw std::runtime_error("unhandled control opcode registry entry");
    }
}

static void AddSizeCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{Ops({OP_SIZE, OP_DROP})};
    for (size_t size : PreDataSizes(profile)) {
        AddCommonNeutral(specs, opcode, "size-preserve", FormatBytes(size), "late-nonzero", motif,
                         FixedStack({PatternBytes(size, "late-nonzero")}));
    }
    for (size_t size : V2LargeSizes(profile, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)) {
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "size-preserve", FormatBytes(size), "late-nonzero", motif,
                FixedStack({PatternBytes(size, "late-nonzero")}));
    }
}

static uint64_t WithinMotifCost(size_t size)
{
    return 3 * size * varops::COST_COPYING + varops::within_cost(size, size, size);
}

static void AddWithinCases(std::vector<CaseSpec>& specs, opcodetype opcode, Profile profile)
{
    const CScript motif{Ops({OP_3DUP, OP_WITHIN, OP_DROP})};
    AddCommonNeutral(specs, opcode, "within-preserve", "4Bx4Bx4B", "inside-range", motif,
                     FixedStack({PaddedNumber(2, 4), PaddedNumber(1, 4), PaddedNumber(3, 4)}));
    AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
            "within-preserve", "521Bx521Bx521B", "inside-range-padded", motif,
            FixedStack({PaddedNumber(2, 521), PaddedNumber(1, 521), PaddedNumber(3, 521)}));
    if (profile == Profile::FULL) {
        const CrossoverPair crossover{FindCrossoverPair(motif.size(), 3,
                                                        MAX_THREE_WAY_ELEMENT_SIZE,
                                                        WithinMotifCost)};
        for (const auto& [size, expectation] : std::array{
                 std::pair{crossover.script_limited, SaturationExpectation::SCRIPT_BYTES},
                 std::pair{crossover.varops_limited, SaturationExpectation::VAROPS_BUDGET}}) {
            AddAuditedSpec(specs, opcode, HeadlineRole::NEW_GSR, "within-crossover",
                           FormatBytes(size) + "x" + FormatBytes(size) + "x" + FormatBytes(size),
                           "inside-range-padded", motif,
                           FixedStack({PaddedNumber(2, size), PaddedNumber(1, size),
                                       PaddedNumber(3, size)}),
                           WithinMotifCost(size), expectation);
        }
        AddSpec(specs, opcode, HeadlineRole::NEW_GSR,
                "within-scale-tail",
                FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE) + "x" +
                    FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE) + "x" +
                    FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE),
                "inside-range-padded", motif,
                FixedStack({PaddedNumber(2, MAX_THREE_WAY_ELEMENT_SIZE),
                            PaddedNumber(1, MAX_THREE_WAY_ELEMENT_SIZE),
                            PaddedNumber(3, MAX_THREE_WAY_ELEMENT_SIZE)}),
                SCRIPT_ERR_OK, RepeatMode::MAX_SUCCESS, 0,
                std::numeric_limits<uint64_t>::max(), std::nullopt, {},
                WithinMotifCost(MAX_THREE_WAY_ELEMENT_SIZE));
    }
}

using CaseGenerator = void (*)(std::vector<CaseSpec>&, opcodetype, Profile);

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
        const CaseGenerator unary_common{[](auto& out, auto op, auto profile) { AddUnaryDataCases(out, op, profile, false); }};
        const CaseGenerator unary_restored{[](auto& out, auto op, auto profile) { AddUnaryDataCases(out, op, profile, true); }};
        const CaseGenerator binary_common{[](auto& out, auto op, auto profile) { AddBinaryDataCases(out, op, profile, false); }};
        const CaseGenerator binary_restored{[](auto& out, auto op, auto profile) { AddBinaryDataCases(out, op, profile, true); }};

        add(AddControlAndFloorCases, {OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_IF, OP_VERIFY, OP_NOP, OP_CODESEPARATOR});
        add(AddStackOpcodeCases, {OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP,
                                  OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK});
        add(unary_common, {OP_1ADD, OP_1SUB, OP_NOT, OP_0NOTEQUAL});
        add(unary_restored, {OP_INVERT, OP_2MUL, OP_2DIV});
        add(binary_common, {OP_EQUAL, OP_EQUALVERIFY, OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
                            OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
                            OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX});
        add(binary_restored, {OP_AND, OP_OR, OP_XOR});
        add(AddHashCases, {OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256});
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

static std::vector<CaseSpec> GenerateCaseSpecs(const Options& options)
{
    std::vector<CaseSpec> specs;
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        const opcodetype opcode{entry.opcode};
        if (!options.selected_opcodes.empty() && !options.selected_opcodes.contains(opcode)) continue;
        entry.generate(specs, opcode, options.profile);
    }

    if (options.profile == Profile::FULL &&
        (options.selected_opcodes.empty() || options.selected_opcodes.contains(OP_DUP))) {
        AddSpec(specs, OP_DUP, HeadlineRole::PRE_BASELINE,
                "empty-dup-stack-reject", "1001-items", "empty-items", Ops({OP_DUP}),
                FixedStack({valtype{}}), SCRIPT_ERR_STACK_SIZE, RepeatMode::FIXED,
                MAX_STACK_SIZE, MAX_STACK_SIZE, 0, "stack-count-limit");
        AddSpec(specs, OP_DUP, HeadlineRole::NEW_GSR,
                "empty-dup-stack-reject", "32769-items", "empty-items", Ops({OP_DUP}),
                FixedStack({valtype{}}), SCRIPT_ERR_STACK_SIZE, RepeatMode::FIXED,
                MAX_TAPSCRIPT_V2_STACK_SIZE, MAX_TAPSCRIPT_V2_STACK_SIZE, 0, "stack-count-limit");
        AddSpec(specs, OP_DUP, HeadlineRole::NEW_GSR,
                "total-stack-reject", "4MB-item", "dense", Ops({OP_DUP, OP_DUP}),
                FixedStack({PatternBytes(4'000'000, "dense")}), SCRIPT_ERR_TOTAL_STACK_SIZE,
                RepeatMode::FIXED, 1, 1, 0, "total-stack-limit");
    }

    std::sort(specs.begin(), specs.end(), [](const CaseSpec& left, const CaseSpec& right) { return left.name < right.name; });
    const std::vector<CaseSpec>::iterator duplicate{std::adjacent_find(specs.begin(), specs.end(), [](const CaseSpec& left, const CaseSpec& right) {
        return left.name == right.name;
    })};
    if (duplicate != specs.end()) throw std::runtime_error("duplicate generated case name: " + duplicate->name);
    return specs;
}

static ankerl::nanobench::Bench SetupBenchmark(int epochs, uint64_t epoch_iterations = 1)
{
    ankerl::nanobench::Bench bench;
    bench.output(nullptr).epochs(epochs).epochIterations(epoch_iterations);
    return bench;
}

static void RunGlobalWarmup(const CryptoFixture& fixture)
{
    const CScript warmup_script{BuildScript(Ops({OP_NOP}), 1, 0)};
    ValtypeStack warmup_stack;
    BenchSignatureChecker checker{fixture};
    ScriptExecutionData execdata;
    execdata.m_internal_key = XOnlyPubKey::NUMS_H;
    varops::Budget budget{TOTAL_VAROPS_BUDGET};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    if (!EvalTapscriptV2(warmup_stack, warmup_script, BENCH_SCRIPT_VERIFY_FLAGS,
                         checker, execdata, budget, &error)) {
        throw std::runtime_error("global benchmark warmup failed: " + ScriptErrorString(error));
    }
}

static BenchResult ResultMetadata(const MaterializedCase& test_case, int epochs)
{
    const CaseSpec& spec{*test_case.spec};
    return {spec.name, 0, 0, 0, DomainFor(spec.role), spec.role, spec.opcode_name,
            spec.motif_name, spec.operand_shape, spec.operand_pattern, test_case.script.size(),
            test_case.initial_stack.size(), StackPayloadBytes(test_case.initial_stack),
            spec.expected_error, SCRIPT_ERR_UNKNOWN_ERROR, test_case.saturation, epochs,
            test_case.repetitions, test_case.motif_varops};
}

static EvalOutcome Preflight(const MaterializedCase& test_case, const CryptoFixture& fixture)
{
    if (test_case.script.size() != SCRIPT_BYTES) {
        throw std::runtime_error(test_case.spec->name + " is not exactly 4,000,000 script bytes");
    }
    BenchSignatureChecker checker{fixture};
    const EvalOutcome outcome{Evaluate(test_case, checker, test_case.initial_stack)};
    if (outcome.error != test_case.spec->expected_error || outcome.success != (test_case.spec->expected_error == SCRIPT_ERR_OK)) {
        throw std::runtime_error(strprintf("preflight mismatch for %s: expected %s, got %s",
                                           test_case.spec->name,
                                           ScriptErrorString(test_case.spec->expected_error),
                                           ScriptErrorString(outcome.error)));
    }
    return outcome;
}

static BenchResult RunCase(const MaterializedCase& test_case, const CryptoFixture& fixture,
                           const Options& options, const EvalOutcome& preflight)
{
    BenchResult result{ResultMetadata(test_case, options.epochs)};
    result.actual_error = preflight.error;
    result.varops_consumed = preflight.varops_consumed;
    if (options.validate_only) return result;

    const uint64_t fixture_bytes{StackFixtureBytes(test_case.initial_stack)};
    if (fixture_bytes > MAX_FIXTURE_POOL_BYTES / static_cast<uint64_t>(options.epochs)) {
        throw std::runtime_error(strprintf("%s epoch fixture pool would require %u bytes (limit %u)",
                                           test_case.spec->name, fixture_bytes * options.epochs,
                                           MAX_FIXTURE_POOL_BYTES));
    }

    BenchSignatureChecker checker{fixture};
    ankerl::nanobench::Bench bench{SetupBenchmark(options.epochs)};
    std::vector<ScriptExecutionData> execdata_pool(options.epochs);
    std::vector<ScriptError> error_pool(options.epochs, SCRIPT_ERR_UNKNOWN_ERROR);
    std::vector<unsigned char> success_pool(options.epochs, 0);
    std::vector<uint64_t> consumed_pool(options.epochs, 0);
    for (ScriptExecutionData& execdata : execdata_pool) {
        execdata.m_internal_key = XOnlyPubKey::NUMS_H;
        execdata.m_validation_weight_left = MAX_BLOCK_WEIGHT;
        execdata.m_validation_weight_left_init = true;
    }

    size_t stack_index{0};
    if (DomainFor(test_case.spec->role) == ExecutionDomain::PRE_GSR_TAPSCRIPT) {
        std::vector<std::vector<valtype>> stack_pool;
        stack_pool.reserve(options.epochs);
        for (int i{0}; i < options.epochs; ++i)
            stack_pool.push_back(test_case.initial_stack);
        bench.run(test_case.spec->name, [&] {
            const size_t index{stack_index++};
            std::vector<valtype>& stack{stack_pool[index]};
            ScriptError& error{error_pool[index]};
            bool success{EvalScript(stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                    checker, SigVersion::TAPSCRIPT, execdata_pool[index], &error)};
            if (success && stack.size() != 1) {
                success = false;
                error = SCRIPT_ERR_CLEANSTACK;
            } else if (success && !CastToBool(stack.back())) {
                success = false;
                error = SCRIPT_ERR_EVAL_FALSE;
            }
            success_pool[index] = success;
        });
    } else {
        std::vector<ValtypeStack> stack_pool;
        stack_pool.reserve(options.epochs);
        std::vector<std::unique_ptr<varops::Budget>> budget_pool;
        budget_pool.reserve(options.epochs);
        for (int i{0}; i < options.epochs; ++i) {
            stack_pool.emplace_back(test_case.initial_stack);
            budget_pool.push_back(std::make_unique<varops::Budget>(TOTAL_VAROPS_BUDGET));
        }
        bench.run(test_case.spec->name, [&] {
            const size_t index{stack_index++};
            ValtypeStack& stack{stack_pool[index]};
            ScriptError& error{error_pool[index]};
            varops::Budget& budget{*budget_pool[index]};
            bool success{EvalTapscriptV2(stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                         checker, execdata_pool[index], budget, &error)};
            if (success) success = CheckTapscriptV2ScriptResult(stack, budget, &error);
            success_pool[index] = success;
        });
        for (size_t index{0}; index < budget_pool.size(); ++index) {
            consumed_pool[index] = TOTAL_VAROPS_BUDGET - budget_pool[index]->Remaining();
        }
    }

    bool mismatch{stack_index != static_cast<size_t>(options.epochs)};
    for (size_t index{0}; index < static_cast<size_t>(options.epochs); ++index) {
        if (error_pool[index] != preflight.error || success_pool[index] != preflight.success ||
            consumed_pool[index] != preflight.varops_consumed) {
            mismatch = true;
        }
    }
    if (mismatch) {
        throw std::runtime_error(test_case.spec->name + " changed outcome during timed epochs");
    }
    if (bench.results().size() != 1) throw std::runtime_error("nanobench produced no result");
    const ankerl::nanobench::Result& measured{bench.results().front()};
    result.median_sec = measured.median(ankerl::nanobench::Result::Measure::elapsed);
    result.mdape = measured.medianAbsolutePercentError(ankerl::nanobench::Result::Measure::elapsed);
    return result;
}

static BenchResult RunRawSchnorr(const CryptoFixture& fixture, const Options& options)
{
    BenchResult result;
    result.name = "Schnorr signature validation";
    result.domain = ExecutionDomain::RAW_SCHNORR;
    result.role = HeadlineRole::PRE_BASELINE;
    result.opcode_name = "RAW_SCHNORR_80000";
    result.motif_name = "fixed-message-verify";
    result.operand_shape = "64B+32B";
    result.operand_pattern = "valid-fixed-message";
    result.expected_error = SCRIPT_ERR_OK;
    result.actual_error = SCRIPT_ERR_OK;
    result.saturation = "80000-signature-anchor";
    result.epochs = options.epochs;
    if (options.validate_only) return result;

    const uint64_t iterations{options.profile == Profile::SMOKE ? 10U : 1000U};
    ankerl::nanobench::Bench bench{SetupBenchmark(options.epochs, iterations)};
    bool valid{false};
    bench.run(result.name, [&] {
        valid = fixture.pubkey.VerifySchnorr(fixture.message, fixture.signature);
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
    if (!valid || bench.results().size() != 1) throw std::runtime_error("raw Schnorr anchor failed");
    const ankerl::nanobench::Result& measured{bench.results().front()};
    result.median_sec = measured.median(ankerl::nanobench::Result::Measure::elapsed) * SIGNATURES_PER_BLOCK;
    result.mdape = measured.medianAbsolutePercentError(ankerl::nanobench::Result::Measure::elapsed);
    result.repetitions = SIGNATURES_PER_BLOCK;
    return result;
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

static void PrintTop(const std::vector<BenchResult>& results, std::string_view title,
                     const std::function<bool(const BenchResult&)>& predicate, size_t limit)
{
    std::cout << "\n"
              << title << ":\n";
    size_t count{0};
    for (const BenchResult& result : results) {
        if (!predicate(result)) continue;
        std::cout << strprintf("%2u. %-66s %8.3f sec  (%5.1f%% varops, %s)\n",
                               ++count, result.name, result.median_sec,
                               100.0 * result.varops_consumed / TOTAL_VAROPS_BUDGET,
                               ScriptErrorString(result.actual_error));
        if (count == limit) break;
    }
    if (count == 0) std::cout << "  (none)\n";
}

static void PrintReport(std::vector<BenchResult> results, const CorpusCounts& counts, bool validate_only)
{
    std::sort(results.begin(), results.end(), [](const BenchResult& left, const BenchResult& right) {
        return left.median_sec > right.median_sec;
    });
    const BenchResult* denominator{Slowest(results, [](const BenchResult& result) {
        return result.role == HeadlineRole::PRE_BASELINE;
    })};
    const BenchResult* numerator{Slowest(results, [](const BenchResult& result) {
        return result.role == HeadlineRole::NEW_GSR;
    })};
    const BenchResult* valid_new{Slowest(results, [](const BenchResult& result) {
        return result.role == HeadlineRole::NEW_GSR && result.actual_error == SCRIPT_ERR_OK;
    })};
    const BenchResult* rejected_new{Slowest(results, [](const BenchResult& result) {
        return result.role == HeadlineRole::NEW_GSR && IsResourceError(result.actual_error);
    })};
    const BenchResult* overall_v2{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::GSR_TAPSCRIPT_V2;
    })};
    const BenchResult* strict_post{Slowest(results, [](const BenchResult& result) {
        return result.role == HeadlineRole::PRE_BASELINE || result.domain == ExecutionDomain::GSR_TAPSCRIPT_V2;
    })};
    const BenchResult* schnorr{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::RAW_SCHNORR;
    })};

    std::cout << "\n================================================================================\n";
    std::cout << "MAXIMUM OBSERVED IN THE GENERATED CORPUS\n";
    std::cout << "================================================================================\n";
    std::cout << strprintf("Corpus: %u requested opcodes, %u generated rows, %u completed rows\n",
                           counts.requested_opcodes, counts.generated_cases, counts.completed_cases);
    if (validate_only) {
        std::cout << "Validation-only mode: all rows matched their declared execution outcome.\n";
        return;
    }
    if (denominator) std::cout << strprintf("Headline denominator (pre-GSR): %s  %.3f sec\n", denominator->name, denominator->median_sec);
    if (numerator) std::cout << strprintf("Headline numerator (new/GSR):    %s  %.3f sec\n", numerator->name, numerator->median_sec);
    if (denominator && numerator && denominator->median_sec > 0) {
        std::cout << strprintf("Headline quotient (new / pre):    %.3f\n", numerator->median_sec / denominator->median_sec);
    }
    if (schnorr) std::cout << strprintf("Raw Schnorr validations (80,000): %.3f sec\n", schnorr->median_sec);
    if (valid_new) std::cout << strprintf("New-GSR valid-only maximum:       %s  %.3f sec\n", valid_new->name, valid_new->median_sec);
    if (rejected_new) std::cout << strprintf("New-GSR rejected-only maximum:    %s  %.3f sec\n", rejected_new->name, rejected_new->median_sec);
    if (overall_v2) std::cout << strprintf("Overall tapscript-v2 maximum:     %s  %.3f sec\n", overall_v2->name, overall_v2->median_sec);
    if (strict_post) std::cout << strprintf("Strict post-activation maximum:   %s  %.3f sec\n", strict_post->name, strict_post->median_sec);

    PrintTop(results, "TOP PRE-GSR ROWS", [](const BenchResult& result) { return result.role == HeadlineRole::PRE_BASELINE; }, 5);
    PrintTop(results, "TOP NEW-GSR ROWS", [](const BenchResult& result) { return result.role == HeadlineRole::NEW_GSR; }, 10);
    PrintTop(results, "TOP COMMON-V2 ROWS", [](const BenchResult& result) { return result.role == HeadlineRole::COMMON_V2; }, 5);
    std::cout << "================================================================================\n";
}

static std::string GetSystemInfo()
{
    std::ostringstream info;
    std::string cpu_name{"Unknown"};
#if defined(__APPLE__)
    if (FILE * fp{popen("sysctl -n machdep.cpu.brand_string", "r")}) {
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
        if (ch == '\"') escaped += '\"';
        escaped += ch;
    }
    escaped += '\"';
    return escaped;
}

static bool SaveResultsToFile(std::vector<BenchResult> results, const std::string& filepath,
                              const CorpusCounts& counts, const Options& options)
{
    std::sort(results.begin(), results.end(), [](const BenchResult& left, const BenchResult& right) {
        return left.median_sec > right.median_sec;
    });
    const fs::path target{fs::PathFromString(filepath)};
    fs::path temporary{target};
    temporary += strprintf(".tmp.%u", std::chrono::steady_clock::now().time_since_epoch().count());
    std::ofstream file(temporary, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "Error: could not open temporary output file " << temporary << "\n";
        return false;
    }

    file << GetSystemInfo();
    file << "# Synthetic envelope: every script is exactly 4,000,000 bytes; initial stack items are pre-pushed, excluded from script weight, and prepared outside timing.\n";
    file << "# GSR budget: 40,000,000,000 varops units. Pre-GSR domain: BIP342 SigVersion::TAPSCRIPT.\n";
    file << "# Metric: maximum observed new/GSR-dependent tapscript-v2 time divided by maximum observed genuine pre-GSR tapscript-v1 time.\n";
    file << strprintf("# Corpus: requested_opcodes=%u generated=%u completed=%u profile=%s validate_only=%s\n",
                      counts.requested_opcodes, counts.generated_cases, counts.completed_cases,
                      options.profile == Profile::FULL ? "full" : "smoke", options.validate_only ? "true" : "false");

    const BenchResult* denominator{Slowest(results, [](const BenchResult& result) { return result.role == HeadlineRole::PRE_BASELINE; })};
    const BenchResult* numerator{Slowest(results, [](const BenchResult& result) { return result.role == HeadlineRole::NEW_GSR; })};
    const BenchResult* schnorr{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::RAW_SCHNORR;
    })};
    if (denominator) file << strprintf("# Headline denominator: %s %.9f sec\n", denominator->name, denominator->median_sec);
    if (numerator) file << strprintf("# Headline numerator: %s %.9f sec\n", numerator->name, numerator->median_sec);
    if (denominator && numerator && denominator->median_sec > 0) {
        file << strprintf("# Headline quotient: %.9f\n", numerator->median_sec / denominator->median_sec);
    }
    if (schnorr) file << strprintf("# Raw Schnorr validations (80,000): %.9f sec\n", schnorr->median_sec);
    file << "#\n";
    file << "Rank,Name,Seconds,Schnorr_Equivalents,Varops_Percentage,Is_GSR_Only,Domain,Headline_Role,Opcode,Motif,Operand_Shape,Operand_Pattern,Script_Bytes,Initial_Stack_Items,Initial_Stack_Bytes,Varops_Consumed,Expected_Termination,Actual_Termination,Saturation,Epochs,MdAPE,Repetitions,Motif_Varops\n";

    const double one_schnorr{!schnorr || schnorr->median_sec == 0 ? 0 : schnorr->median_sec / SIGNATURES_PER_BLOCK};
    for (size_t index{0}; index < results.size(); ++index) {
        const BenchResult& result{results[index]};
        const double equivalents{one_schnorr == 0 ? 0 : result.median_sec / one_schnorr};
        const double percentage{100.0 * result.varops_consumed / TOTAL_VAROPS_BUDGET};
        file << index + 1 << ',' << CsvEscape(result.name) << ',' << result.median_sec << ','
             << equivalents << ',' << percentage << ',' << (result.role == HeadlineRole::NEW_GSR ? "true" : "false") << ','
             << CsvEscape(DomainName(result.domain)) << ',' << CsvEscape(RoleName(result.role)) << ','
             << CsvEscape(result.opcode_name) << ',' << CsvEscape(result.motif_name) << ','
             << CsvEscape(result.operand_shape) << ',' << CsvEscape(result.operand_pattern) << ','
             << result.script_bytes << ',' << result.initial_stack_items << ',' << result.initial_stack_bytes << ','
             << result.varops_consumed << ',' << CsvEscape(ScriptErrorString(result.expected_error)) << ','
             << CsvEscape(ScriptErrorString(result.actual_error)) << ',' << CsvEscape(result.saturation) << ','
             << result.epochs << ',' << result.mdape << ',' << result.repetitions << ','
             << result.motif_varops << '\n';
    }

    file.flush();
    if (!file.good()) {
        std::cerr << "Error: failed while writing " << temporary << "\n";
        file.close();
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
    file.close();
    if (file.fail()) {
        std::cerr << "Error: failed while closing " << temporary << "\n";
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }

    std::error_code rename_error;
    fs::rename(temporary, target, rename_error);
    if (rename_error) {
        std::cerr << "Error: could not atomically replace " << target << ": " << rename_error.message() << "\n";
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
    return true;
}

static void PrintUsage(const char* program)
{
    std::cout << "Usage: " << program << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --opcodes OP_NAME...    Benchmark only explicitly supported opcodes\n"
              << "  --epochs N              Nanobench epochs per row (default: 5)\n"
              << "  --profile full|smoke    Corpus profile (default: full)\n"
              << "  --validate-only         Materialize and preflight without timing\n"
              << "  --list-opcodes          List the declarative opcode inventory\n"
              << "  --silent                Suppress per-row progress\n"
              << "  --file PATH             Atomically write CSV results\n"
              << "  --help, -h              Show this help\n\n"
              << "Examples:\n"
              << "  " << program << " --opcodes OP_ROLL OP_SHA256\n"
              << "  " << program << " --profile smoke --epochs 1 --file results.csv\n";
}

static Options ParseArguments(int argc, char* argv[])
{
    Options options;
    const std::map<std::string, opcodetype> supported{SupportedOpcodeMap()};
    for (int i{1}; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--opcodes") {
            const int first{i + 1};
            while (i + 1 < argc && std::string_view{argv[i + 1]}.substr(0, 2) != "--") {
                const std::string requested{argv[++i]};
                std::string name{ToUpper(requested)};
                if (!name.starts_with("OP_")) name = "OP_" + name;
                const std::map<std::string, opcodetype>::const_iterator found{supported.find(name)};
                if (found == supported.end()) throw std::runtime_error("unknown or unsupported opcode '" + requested + "'");
                options.selected_opcodes.insert(found->second);
            }
            if (i + 1 == first) throw std::runtime_error("--opcodes requires at least one opcode");
        } else if (arg == "--epochs") {
            if (++i >= argc) throw std::runtime_error("--epochs requires a positive integer");
            const std::optional<int> epochs{ToIntegral<int>(argv[i])};
            if (!epochs || *epochs <= 0) throw std::runtime_error("invalid --epochs value '" + std::string{argv[i]} + "'");
            options.epochs = *epochs;
        } else if (arg == "--profile") {
            if (++i >= argc) throw std::runtime_error("--profile requires full or smoke");
            const std::string profile{argv[i]};
            if (profile == "full")
                options.profile = Profile::FULL;
            else if (profile == "smoke")
                options.profile = Profile::SMOKE;
            else
                throw std::runtime_error("invalid --profile value '" + profile + "'");
        } else if (arg == "--validate-only") {
            options.validate_only = true;
        } else if (arg == "--list-opcodes") {
            options.list_opcodes = true;
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

} // namespace

int main(int argc, char* argv[])
{
    try {
        const Options options{ParseArguments(argc, argv)};
        if (options.list_opcodes) {
            for (const auto& [name, opcode] : SupportedOpcodeMap()) {
                std::cout << strprintf("%s (0x%02x)\n", name, static_cast<unsigned int>(opcode));
            }
            return 0;
        }

        std::string boundary_error;
        if (!RunBoundarySelfChecks(boundary_error)) throw std::runtime_error(boundary_error);
        SHA256AutoDetect();
        const CryptoFixture fixture;
        const std::vector<CaseSpec> specs{GenerateCaseSpecs(options)};
        if (specs.empty()) throw std::runtime_error("the requested opcode set generated no cases");
        ReleaseAllocatorCaches();

        std::set<opcodetype> completed_opcodes;
        std::vector<BenchResult> results;
        results.reserve(specs.size() + 1);
        CorpusCounts counts{
            options.selected_opcodes.empty() ? OpcodeRegistry().size() : options.selected_opcodes.size(),
            specs.size(),
            0,
        };

        if (!options.validate_only) RunGlobalWarmup(fixture);
        results.push_back(RunRawSchnorr(fixture, options));
        for (size_t index{0}; index < specs.size(); ++index) {
            {
                MaterializedCase test_case{Materialize(specs[index], fixture, options.profile)};
                const EvalOutcome preflight{Preflight(test_case, fixture)};
                BenchResult result{RunCase(test_case, fixture, options, preflight)};
                completed_opcodes.insert(specs[index].opcode);
                results.push_back(std::move(result));
                ++counts.completed_cases;
                if (!options.silent) {
                    std::cout << strprintf("%4u/%u %-72s %8.3f sec  %5.1f%% varops  %s\n",
                                           index + 1, specs.size(), specs[index].name,
                                           results.back().median_sec,
                                           100.0 * results.back().varops_consumed / TOTAL_VAROPS_BUDGET,
                                           ScriptErrorString(results.back().actual_error));
                }
            }
            ReleaseAllocatorCaches();
        }

        for (opcodetype requested : options.selected_opcodes) {
            if (!completed_opcodes.contains(requested)) {
                throw std::runtime_error("requested opcode produced no completed row: " + OpcodeName(requested));
            }
        }
        PrintReport(results, counts, options.validate_only);
        if (!options.output_file.empty() && !SaveResultsToFile(results, options.output_file, counts, options)) return 1;
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "bench_varops: " << exception.what() << "\n";
        return 1;
    }
}
