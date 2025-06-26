// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <pubkey.h>
#include <span.h>
#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/val64.h>
#include <util/translation.h>
#include <common/args.h>
#include <crypto/sha256.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <key.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <map>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cassert>
#include <string>
#include <limits>
#include <sstream>

namespace Timing {
    constexpr int EPOCHS = 1;
    constexpr int MIN_EPOCH_ITERATIONS = 1;
    constexpr int MIN_EPOCH_TIME_MS = 10;
    constexpr int WARMUP = 0;
}

enum class ValuePattern {
    STANDARD,   // First operand 1, others 2
    IDENTICAL,  // All operands with same value (1)
    ZEROS,      // All operands filled with zeros
    MAX_VALUE   // All operands filled with 0xFF
};

struct StackTemplate {
    std::string name;
    uint64_t size;
    int count;
    ValuePattern pattern;
};

std::vector<StackTemplate> getStackTemplates() {
    return {
        {"1Bx2", 1, 2, ValuePattern::IDENTICAL},
        {"10Bx2", 10, 2, ValuePattern::IDENTICAL},
        {"100Bx2", 100, 2, ValuePattern::IDENTICAL},
        {"1KBx2", 1000, 2, ValuePattern::IDENTICAL},
        {"10KBx2", 10000, 2, ValuePattern::IDENTICAL},
        {"100KBx2", 100000, 2, ValuePattern::IDENTICAL},
        {"1MBx2", 1000000, 2, ValuePattern::IDENTICAL},
        {"2MBx2", 2000000, 2, ValuePattern::IDENTICAL},
        {"4MBx2", 4000000, 2, ValuePattern::IDENTICAL},
    };
}

namespace ScriptConfig {
    
    // Operations that should skip large inputs due to size limits
    inline std::map<std::string, std::vector<std::string>> getSizeLimitedOperations() {
        return {
            {"OP_MUL", {"1MBx2", "2MBx2", "4MBx2"}},  // Quadratic cost - only skip very large inputs
            {"OP_DIV", {"1MBx2", "2MBx2", "4MBx2"}},  // Quadratic cost - only skip very large inputs
            {"OP_RIPEMD160", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},  // 520-byte limit
            {"OP_SHA1", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}}       // 520-byte limit
        };
    }
    
    // Helper function to check if operation should skip large inputs
    inline bool shouldSkipLargeInput(const std::string& opname, const std::string& stack_name) {
        auto size_limited = getSizeLimitedOperations();
        auto it = size_limited.find(opname);
        if (it != size_limited.end()) {
            for (const auto& limited_stack : it->second) {
                if (stack_name == limited_stack) return true;
            }
        }
        return false;
    }
}

namespace SchnorrConfig {
    constexpr int SIGNATURES_PER_BLOCK = 80000;
    
    // Test key: 32 bytes, all zeros except last byte = 1
    inline std::vector<unsigned char> getTestKey() {
        std::vector<unsigned char> key(32, 0);
        key[31] = 1;
        return key;
    }
}

static const ankerl::nanobench::Result* find_result(const ankerl::nanobench::Bench& benches,
                                                   const std::string& name)
{
    for (auto& r : benches.results()) {
        if (r.config().mBenchmarkName == name)
            return &r;
    }
    return nullptr;
}

struct BenchTestCase {
    std::string name;
    std::vector<std::vector<unsigned char>> stack;
    CScript script;
    uint64_t varops_consumed{0};
    
    BenchTestCase(const std::string& n,
                 const std::vector<std::vector<unsigned char>>& s,
                 const CScript& sc) 
        : name(n), stack(s), script(sc) {}
};

static std::vector<std::vector<unsigned char>> init_stack(
    uint64_t size = 1000000,
    int count = 2,
    ValuePattern pattern = ValuePattern::STANDARD
) {
    std::vector<std::vector<unsigned char>> stack;
    
    uint8_t value1, value2;
    
    switch (pattern) {
    case ValuePattern::STANDARD:
        value1 = 1;
        value2 = 2;
        break;
    case ValuePattern::IDENTICAL:
        value1 = value2 = 1;
        break;
    case ValuePattern::ZEROS:
        value1 = value2 = 0;
        break;
    case ValuePattern::MAX_VALUE:
        value1 = value2 = 0xFF;
        break;
    }
    
    // First operand 
    stack.push_back(std::vector<unsigned char>(size, value1));
    
    // Add additional operands
    for (int i = 1; i < count; i++) {
        stack.push_back(std::vector<unsigned char>(size, 
            pattern == ValuePattern::STANDARD ? value2 : value1));
    }
    
    return stack;
}

static CScript create_script(const std::vector<opcodetype>& opcodes) {
    CScript script;
    while (script.size() < MAX_BLOCK_WEIGHT) {
        for (const auto& opcode : opcodes) {
            script << opcode;
            if (script.size() >= MAX_BLOCK_WEIGHT) break;
        }
    }
    return script;
}

static void run_benchmark(ankerl::nanobench::Bench& bench, 
                         BenchTestCase& test_case) {
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;

    uint64_t varops_budget_per_byte = VAROPS_BUDGET_PER_BYTE;
    uint64_t block_size = MAX_BLOCK_WEIGHT;

    uint64_t* varops_budget = new uint64_t(block_size * varops_budget_per_byte);
    uint64_t initial_budget = *varops_budget;
    bool result = false;

    bench.run(test_case.name, [&] {
        std::vector<std::vector<unsigned char> > stack = test_case.stack;
        result = EvalScript(stack, test_case.script, 0, checker,
                        SigVersion::TAPSCRIPT_V2, sdata, &serror, varops_budget);
    });
    // if (!result) {
    //     printf(" (%s) \n", ScriptErrorString(serror).c_str());
    // }
    if (*varops_budget != initial_budget && test_case.varops_consumed == 0) {
        test_case.varops_consumed = initial_budget - *varops_budget;
    }
    // print if no varops_consumed
    if (test_case.varops_consumed == 0) {
        printf(" (No varops consumed for %s) \n", test_case.name.c_str());
    }
}

static void run_schnorr_benchmark(ankerl::nanobench::Bench &bench, const std::string& name) {
    KeyPair::ECC_Start();

    // Create key pair
    CKey key;
    auto test_key = SchnorrConfig::getTestKey();
    key.Set(test_key.begin(), test_key.end(), false);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> vchSig(64);
    const uint256 hash = uint256::ONE;
    key.SignSchnorr(hash, vchSig, NULL, hash);

    XOnlyPubKey xpub{pubkey};
    Span<const unsigned char> sigbytes{vchSig.data(), vchSig.size()};
    assert(sigbytes.size() == 64);

    // Run benchmark
    bench.run(name, [&] {
        bool res = xpub.VerifySchnorr(hash, sigbytes);
        assert(res);
    });

    KeyPair::ECC_Stop();
}


enum class RestorationType {
    DROP,
    DUP,
    DROP_AND_DUP,
    DUP_OP_DROP_DUP,
    DUP_DUP_OP_DROP_DUP,
    DUP_OP_DUP,
    DROP_DROP,
    NONE,
    UNSUPPORTED
};

struct ScriptTemplate {
    std::string name;
    std::vector<opcodetype> opcodes;
};

RestorationType getRestorationType(opcodetype opcode) {
    switch (opcode) {
        // Hash operations (1 in -> 1 out)
        case OP_RIPEMD160:
        case OP_SHA1:
        case OP_SHA256:
        case OP_HASH160:
        case OP_HASH256:
            return RestorationType::DROP_AND_DUP;

        // Bit operations (2 in -> 1 out)
        case OP_AND:
        case OP_OR:
        case OP_XOR:
        case OP_EQUAL:
        case OP_ADD:
        case OP_SUB:
        case OP_MUL:
        case OP_DIV:
        case OP_MOD:
        case OP_BOOLAND:
        case OP_BOOLOR:
        case OP_NUMEQUAL:
        case OP_NUMNOTEQUAL:
        case OP_LESSTHAN:
        case OP_GREATERTHAN:
        case OP_LESSTHANOREQUAL:
        case OP_GREATERTHANOREQUAL:
        case OP_MIN:
        case OP_MAX:
        case OP_CAT:
        case OP_LSHIFT:
        case OP_RSHIFT:
            return RestorationType::DUP_OP_DROP_DUP;

        // Single input operations (1 in -> 1 out)
        case OP_NOT:
        case OP_1ADD:
        case OP_1SUB:
        case OP_ABS:
        case OP_NEGATE:
        case OP_0NOTEQUAL:
            return RestorationType::DROP_AND_DUP;

        case OP_SIZE:
        case OP_OVER:
        case OP_TUCK:
            return RestorationType::DROP;

        case OP_ROLL:
            return RestorationType::DUP;

        // Verify operations (2 in -> 0 out)
        case OP_EQUALVERIFY:
        case OP_NUMEQUALVERIFY:
            return RestorationType::DUP_OP_DUP;

        // Stack manipulation
        case OP_SWAP:
            return RestorationType::NONE;

        case OP_2DUP:
            return RestorationType::DROP_DROP;
        // Special cases
        case OP_WITHIN:
        case OP_SUBSTR:
            return RestorationType::DUP_DUP_OP_DROP_DUP;

        // 2-input operations
        case OP_2MUL:
        case OP_2DIV:
            return RestorationType::DROP_AND_DUP;
        default:
            return RestorationType::UNSUPPORTED;
    }
}

std::vector<opcodetype> createOpcodes(opcodetype opcode, RestorationType type) {
    switch (type) {
        case RestorationType::DROP:
            return {opcode, OP_DROP};
        case RestorationType::DUP:
            return {opcode, OP_DUP};
        case RestorationType::DROP_AND_DUP:
            return {opcode, OP_DROP, OP_DUP};
        case RestorationType::DUP_OP_DROP_DUP:
            return {OP_DUP, opcode, OP_DROP, OP_DUP};
        case RestorationType::DUP_DUP_OP_DROP_DUP:
            return {OP_DUP, OP_DUP, opcode, OP_DROP, OP_DUP};
        case RestorationType::DUP_OP_DUP:
            return {OP_DUP, opcode, OP_DUP};
        case RestorationType::DROP_DROP:
            return {opcode, OP_DROP, OP_DROP};
        case RestorationType::NONE:
            return {opcode};
        case RestorationType::UNSUPPORTED:
            return {};
    }
    return {opcode}; // Default case
}

static ankerl::nanobench::Bench setup_benchmark() {
    ankerl::nanobench::Bench bench;
        bench.output(nullptr)
            .epochs(Timing::EPOCHS)
            .minEpochIterations(Timing::MIN_EPOCH_ITERATIONS)
            .minEpochTime(std::chrono::milliseconds(Timing::MIN_EPOCH_TIME_MS))
            .warmup(Timing::WARMUP);
    
    SHA256AutoDetect();
    return bench;
}

static std::vector<ScriptTemplate> create_script_templates() {
    std::vector<ScriptTemplate> script_templates;
    
    // Loop through all opcodes
    for (unsigned int op = 0x4c; op <= 0xba; op++) {
        opcodetype opcode = static_cast<opcodetype>(op);
        std::string opname = GetOpName(opcode);
        RestorationType type = getRestorationType(opcode);
        if (type == RestorationType::UNSUPPORTED) {
            printf("Warning: Skipping unsupported opcode 0x%02x (%s)\n", op, opname.c_str());
            continue;
        }
        
        ScriptTemplate template_;
        template_.name = opname;
        template_.opcodes = createOpcodes(opcode, type);
        
        script_templates.push_back(template_);
    }
    
    return script_templates;
}

static std::vector<BenchTestCase> create_test_cases(const std::vector<ScriptTemplate>& script_templates) {
    // Get stack templates from configuration
    std::vector<StackTemplate> config_stack_templates = getStackTemplates();
    
    // Create test cases by combining script and stack templates
    std::vector<BenchTestCase> test_cases;
    test_cases.reserve(script_templates.size() * config_stack_templates.size());
    
    for (const auto& script_template : script_templates) {
        for (auto& stack_config : config_stack_templates) {
            // Use configuration to check if operation should skip large inputs
            if (ScriptConfig::shouldSkipLargeInput(script_template.name, stack_config.name)) {
                continue;
            }
            
            // Create special minimal stack for shift operations to avoid size explosion
            if (script_template.name == "OP_LSHIFT" || script_template.name == "OP_RSHIFT") {
                if (stack_config.name == "1MB") {
                    auto stack = init_stack(stack_config.size, stack_config.count, stack_config.pattern);
                    stack[1] = {1}; // Minimal shift
                    test_cases.emplace_back(
                        script_template.name + "_" + stack_config.name,
                        stack,
                        create_script(script_template.opcodes)
                    );
                }
                continue;
            }
            if (script_template.name == "OP_ROLL") {
                // Create a stack with maximum size minus 1 and push the roll index
                int maximum_size = MAX_STACK_SIZE;
                std::vector<std::vector<unsigned char>> stack;

                int roll_index = maximum_size - 3;
                for (int i = 0; i < maximum_size - 1; i++) {
                    std::vector<unsigned char> number = CScriptNum::serialize(roll_index);
                    stack.push_back(number);
                }

                test_cases.emplace_back(
                    script_template.name + "_MAX_STACK_SIZE",
                    stack,
                    create_script(script_template.opcodes)
                );
                continue;
            }

            test_cases.emplace_back(
                script_template.name + "_" + stack_config.name,
                init_stack(stack_config.size, stack_config.count, stack_config.pattern),
                create_script(script_template.opcodes)
            );
        }
    }

    // remove duplicates
    std::sort(test_cases.begin(), test_cases.end(), [](const BenchTestCase& a, const BenchTestCase& b) {
        return a.name < b.name;
    });
    test_cases.erase(std::unique(test_cases.begin(), test_cases.end(), 
        [](const BenchTestCase& a, const BenchTestCase& b) {
            return a.name == b.name;
        }), test_cases.end());
    
    return test_cases;
}

static void run_all_benchmarks(ankerl::nanobench::Bench& bench, std::vector<BenchTestCase>& test_cases) {
    std::cout << "Running Schnorr signature benchmark..." << std::endl;
    run_schnorr_benchmark(bench, "Schnorr signature validation");
    
    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = find_result(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    double schnorr_block_time = schnorr_median_time * SchnorrConfig::SIGNATURES_PER_BLOCK;
    printf("Schnorr block time: %f seconds\n", schnorr_block_time);
    int bench_count = 0;
    
    for (auto& test_case : test_cases) {

        
        run_benchmark(bench, test_case);
        
        // Get median time and calculate Schnorr validations
        if (const auto* result = find_result(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double schnorr_times = median_sec / schnorr_median_time;
            
            printf("Benchmark %d/%zu: %s\t%.3f seconds (%.0f Schnorr sigs)\n", 
                   ++bench_count, test_cases.size(), test_case.name.c_str(), median_sec, schnorr_times);
        }
    }
}

struct BenchResult {
    std::string name;
    double median_sec;
    uint64_t varops_consumed;
    double per_varop_ns;
};

static std::vector<BenchResult> collect_results(const ankerl::nanobench::Bench& bench, const std::vector<BenchTestCase>& test_cases) {
    std::vector<BenchResult> results;
    results.reserve(test_cases.size());
    
    for (const auto& test_case : test_cases) {
        if (const auto* result = find_result(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double per_varop_ns = test_case.varops_consumed > 0 
                ? (median_sec * 1e9) / test_case.varops_consumed 
                : 0;
            
            results.emplace_back(
                test_case.name, 
                median_sec, 
                test_case.varops_consumed,
                per_varop_ns
            );
        }
    }
    
    // Sort by block time
    std::sort(results.begin(), results.end(), 
        [](const auto& a, const auto& b) { return a.median_sec > b.median_sec; });
    
    return results;
}

static void print_worst_cases(std::vector<BenchResult>& results, double schnorr_median_time) {
    // print 20 worst cases sorted by median_sec
    std::sort(results.begin(), results.end(), 
        [](const BenchResult& a, const BenchResult& b) { return a.median_sec > b.median_sec; });

    std::cout << "\n================================================================================\n";
    std::cout << "SLOWEST 20 OPERATIONS\n";
    std::cout << "================================================================================\n";
    
    for (int i = 0; i < std::min(20, (int)results.size()); i++) {
        double schnorr_times = schnorr_median_time > 0 ? results[i].median_sec / schnorr_median_time : 0;
        
        printf("%d. %s %.3f seconds (%.0f Schnorr sigs", 
               (i+1), results[i].name.c_str(), results[i].median_sec, schnorr_times);
        
        if (results[i].varops_consumed > 0) {
            printf(", %llu varops", results[i].varops_consumed);
        }
        printf(")\n");
    }
    std::cout << "================================================================================\n";
}

int main() {
    auto bench = setup_benchmark();
    auto script_templates = create_script_templates();
    auto test_cases = create_test_cases(script_templates);
    
    run_all_benchmarks(bench, test_cases);
    
    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = find_result(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }
    auto results = collect_results(bench, test_cases);
    
    print_worst_cases(results, schnorr_median_time);
} 