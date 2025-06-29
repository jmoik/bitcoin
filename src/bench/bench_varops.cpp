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

// Global variables that can be modified by CLI flags
std::set<opcodetype> SELECTED_OPCODES;  // Empty set means run all opcodes
constexpr uint64_t MAX_BLOCK_WEIGHT_UINT64 = MAX_BLOCK_WEIGHT;
constexpr uint64_t VAROPS_BUDGET_PER_BYTE_UINT64 = VAROPS_BUDGET_PER_BYTE;
constexpr uint64_t TOTAL_VAROPS_BUDGET = MAX_BLOCK_WEIGHT_UINT64 * VAROPS_BUDGET_PER_BYTE_UINT64;

namespace Timing {
    int EPOCHS = 1;
    constexpr int EPOCH_ITERATIONS = 1;
    constexpr int SCHNORR_EPOCHS = 5;
    constexpr int SCHNORR_EPOCH_ITERATIONS = 1000;
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

std::vector<StackTemplate> GetStackTemplates() {
    return {
        {"1Bx2", 1, 2, ValuePattern::IDENTICAL},
        {"10Bx2", 10, 2, ValuePattern::IDENTICAL},
        {"100Bx2", 100, 2, ValuePattern::IDENTICAL},
        {"1KBx2", 1000, 2, ValuePattern::IDENTICAL},
        {"10KBx2", 10000, 2, ValuePattern::IDENTICAL},
        {"100KBx2", 100000, 2, ValuePattern::IDENTICAL},
        {"1MBx2", 1000000, 2, ValuePattern::IDENTICAL},
        {"2MBx2", 2000000, 2, ValuePattern::IDENTICAL},
    };
}

namespace ScriptConfig {
    inline bool ShouldSkipCase(const std::string& opname, const std::string& stack_name) {
        static const std::map<std::string, std::vector<std::string>> size_limited_operations = {
            {"OP_MUL", {"1MBx2", "2MBx2", "4MBx2"}},  // Quadratic cost - only skip very large inputs
            {"OP_DIV", {"1MBx2", "2MBx2", "4MBx2"}},  // Quadratic cost - only skip very large inputs
            {"OP_RIPEMD160", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},  // 520-byte limit
            {"OP_SHA1", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},       // 520-byte limit
            {"OP_OVER", {"2MBx2", "4MBx2"}},
            {"OP_ROT", {"2MBx2", "4MBx2"}},
            {"OP_2ROT", {"2MBx2", "4MBx2"}},
            {"OP_2OVER", {"2MBx2", "4MBx2"}},
            {"OP_2SWAP", {"2MBx2", "4MBx2"}},
        };
        
        auto it = size_limited_operations.find(opname);
        if (it != size_limited_operations.end()) {
            for (const auto& limited_stack : it->second) {
                if (stack_name == limited_stack) return true;
            }
        }
        return false;
    }
}

namespace SchnorrConfig {
    constexpr int SIGNATURES_PER_BLOCK = 80000;
    
    inline std::vector<unsigned char> GetTestKey() {
        std::vector<unsigned char> key(32, 0);
        key[31] = 1;
        return key;
    }
}

static const ankerl::nanobench::Result* FindResult(const ankerl::nanobench::Bench& benches,
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
};

static std::vector<std::vector<unsigned char>> InitStack(
    uint64_t size,
    int count,
    ValuePattern pattern) {
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
    
    stack.emplace_back(size, value1);
    for (int i = 1; i < count; i++) {
        stack.emplace_back(size, value2);
    }
    
    return stack;
}

static CScript CreateScript(const std::vector<opcodetype>& opcodes) {
    CScript script;
    while (script.size() < MAX_BLOCK_WEIGHT) {
        for (const auto& opcode : opcodes) {
            script << opcode;
        }
    }
    return script;
}

static void RunBenchmark(ankerl::nanobench::Bench& bench, 
                         BenchTestCase& test_case) {
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;

    const uint64_t varops_block_budget = TOTAL_VAROPS_BUDGET;
    assert(varops_block_budget > 2e10);  // make sure budget is correct, assigning int to uint64_t would result in a lower budget
    uint64_t working_budget = varops_block_budget;
    bool result = false;

    // Pre-create a pool of stack copies to eliminate copy overhead from benchmark timing
    const size_t stack_pool_size = Timing::EPOCHS * 1;
    size_t stack_index = 0;
    std::vector<std::vector<std::vector<unsigned char>>> stack_pool;
    stack_pool.reserve(stack_pool_size);
    
    for (size_t i = 0; i < stack_pool_size; ++i) {
        stack_pool.push_back(test_case.stack);
    }

    bench.run(test_case.name, [&] {
        assert(stack_index < stack_pool_size);
        std::vector<std::vector<unsigned char>>& working_stack = stack_pool[stack_index];
        working_budget = varops_block_budget;
        result = EvalScript(working_stack, test_case.script, 0, checker,
                        SigVersion::TAPSCRIPT_V2, sdata, &serror, &working_budget);

        ++stack_index;
    });
    if (!result) {
        std::string error_msg = ScriptErrorString(serror);
        if (error_msg.find("Varops count exceeded") == std::string::npos) {
            printf("Script error: %s\n", error_msg.c_str());
            exit(1);
        }
    }
    if (working_budget != varops_block_budget && test_case.varops_consumed == 0) {
        test_case.varops_consumed = varops_block_budget - working_budget;
    }
    serror = SCRIPT_ERR_OK;
}

static void RunSchnorrBenchmark(ankerl::nanobench::Bench &bench, const std::string& name) {
    bench.epochIterations(Timing::SCHNORR_EPOCH_ITERATIONS);
    bench.epochs(Timing::SCHNORR_EPOCHS);
    
    KeyPair::ECC_Start();

    // Create key pair
    CKey key;
    auto test_key = SchnorrConfig::GetTestKey();
    key.Set(test_key.begin(), test_key.end(), false);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> vchSig(64);
    const uint256 hash = uint256::ONE;
    key.SignSchnorr(hash, vchSig, NULL, hash);

    XOnlyPubKey xpub(pubkey);
    Span<const unsigned char> sigbytes{vchSig.data(), vchSig.size()};
    assert(sigbytes.size() == 64);

    bench.run(name, [&] {
        bool res = xpub.VerifySchnorr(hash, sigbytes);
        assert(res);
    });

    KeyPair::ECC_Stop();

    bench.epochs(Timing::EPOCHS);
    bench.epochIterations(Timing::EPOCH_ITERATIONS);
}


struct ScriptTemplate {
    std::string name;
    std::vector<opcodetype> opcodes;
};

std::vector<opcodetype> GetOpcodes(opcodetype opcode) {
    switch (opcode) {
        // Hash operations (1 in -> 1 out)
        case OP_RIPEMD160:
        case OP_SHA1:
        case OP_SHA256:
        case OP_HASH160:
        case OP_HASH256:
        case OP_NOT:
        case OP_1ADD:
        case OP_1SUB:
        case OP_ABS:
        case OP_NEGATE:
        case OP_0NOTEQUAL:
        case OP_2MUL:
        case OP_2DIV:
            return {opcode, OP_DROP, OP_DUP};

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
            return {OP_DUP, opcode, OP_DROP, OP_DUP};

        // Stack manipulation (0 in -> 1 out)
        case OP_SIZE:
        case OP_OVER:
        case OP_TUCK:
        case OP_DEPTH:
        case OP_DUP:
            return {opcode, OP_DROP};

        case OP_2DROP:
            return {OP_DUP, OP_DUP, opcode};

        case OP_2OVER:
            return {opcode, OP_DROP, OP_DROP};

        // Stack manipulation (1 in -> 0 out)
        case OP_ROLL:
        case OP_VERIFY:
        case OP_NIP:
            return {opcode, OP_DUP};

        // Verify operations (2 in -> 0 out)
        case OP_EQUALVERIFY:
        case OP_NUMEQUALVERIFY:
            return {OP_DUP, opcode, OP_DUP};

        // Stack manipulation (0 in -> 0 out)
        case OP_NOP:
        case OP_SWAP:
        case OP_2SWAP:
        case OP_ROT:
        case OP_2ROT:
        case OP_INVERT:
        // case OP_PICK: 
            return {opcode};

        // Stack manipulation (0 in -> 2 out)
        case OP_2DUP:
            return {opcode, OP_DROP, OP_DROP};

        // Special cases (3 in -> 1 out)
        case OP_WITHIN:
        case OP_SUBSTR:
            return {OP_DUP, OP_DUP, opcode, OP_DROP, OP_DUP};

        case OP_TOALTSTACK:
            return {opcode, OP_FROMALTSTACK};

        case OP_DROP:
            return {opcode, OP_DUP};

        default:
            return {}; // Unsupported
    }
}

static ankerl::nanobench::Bench SetupBenchmark() {
    ankerl::nanobench::Bench bench;
        bench.output(nullptr)
            .epochs(Timing::EPOCHS)
            .epochIterations(Timing::EPOCH_ITERATIONS)
            .warmup(Timing::WARMUP);
    SHA256AutoDetect();
    return bench;
}

static std::vector<ScriptTemplate> CreateScriptTemplates() {
    std::vector<ScriptTemplate> script_templates;
    
    // Loop through all opcodes
    for (unsigned int op = 0x4c; op <= 0xba; op++) {
        opcodetype opcode = static_cast<opcodetype>(op);
        
        if (!SELECTED_OPCODES.empty() && SELECTED_OPCODES.find(opcode) == SELECTED_OPCODES.end()) {
            continue;
        }
        
        std::string opname = GetOpName(opcode);
        auto opcodes = GetOpcodes(opcode);
        if (opcodes.empty()) {
            printf("Warning: Skipping unsupported opcode 0x%02x (%s)\n", op, opname.c_str());
            continue;
        }
        script_templates.emplace_back(opname, opcodes);
    }
    
    return script_templates;
}

static std::vector<BenchTestCase> CreateTestCases() {
    std::vector<StackTemplate> config_stack_templates = GetStackTemplates();
    std::vector<ScriptTemplate> script_templates = CreateScriptTemplates();
    
    std::vector<BenchTestCase> test_cases;
    test_cases.reserve(script_templates.size() * config_stack_templates.size());
    
    for (const auto& script_template : script_templates) {
        for (auto& stack_config : config_stack_templates) {
            // Use configuration to check if operation should skip large inputs
            if (ScriptConfig::ShouldSkipCase(script_template.name, stack_config.name)) {
                continue;
            }
            
            // Create special minimal stack for shift operations to avoid size explosion
            if (script_template.name == "OP_LSHIFT" || script_template.name == "OP_RSHIFT") {
                if (stack_config.name == "1MB") {
                    auto stack = InitStack(stack_config.size, stack_config.count, stack_config.pattern);
                    stack[1] = {1}; // Minimal shift
                    test_cases.emplace_back(
                        script_template.name + "_" + stack_config.name,
                        stack,
                        CreateScript(script_template.opcodes)
                    );
                }
                continue;
            }
            if (script_template.name == "OP_ROLL") {
                // Create a stack with maximum size minus 1 and push the roll index
                int maximum_size = MAX_TAPSCRIPT_V2_STACK_SIZE;
                std::vector<std::vector<unsigned char>> stack;

                int roll_index = MAX_TAPSCRIPT_V2_STACK_SIZE - 5;
                for (int i = 0; i < maximum_size - 1; i++) {
                    std::vector<unsigned char> number = Val64(roll_index).move_to_valtype();
                    stack.push_back(number);
                }

                test_cases.emplace_back(
                    script_template.name + "_MAX_STACK_SIZE",
                    stack,
                    CreateScript(script_template.opcodes)
                );
                continue;
            }
            if (script_template.name == "OP_ROT" || script_template.name == "OP_OVER" || script_template.name == "OP_2OVER" || script_template.name == "OP_2ROT" || script_template.name == "OP_2SWAP") {
                auto stack = InitStack(stack_config.size, 6, stack_config.pattern);
                test_cases.emplace_back(
                    script_template.name + "_" + stack_config.name,
                    stack,
                    CreateScript(script_template.opcodes));

                test_cases.emplace_back(
                    script_template.name + "_" + stack_config.name,
                    stack,
                    CreateScript(script_template.opcodes));
                continue;
            }
            test_cases.emplace_back(
                script_template.name + "_" + stack_config.name,
                InitStack(stack_config.size, stack_config.count, stack_config.pattern),
                CreateScript(script_template.opcodes)
            );
            continue;
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

static void PrintBenchmarkResult(int index, size_t total_count, const std::string& name, 
                                double median_sec, double schnorr_times, uint64_t varops_consumed, 
                                bool show_total_count = false) {
    if (show_total_count) {
        printf("Benchmark %3d/%zu: %-30s %.3f seconds (%6.0f Schnorr sigs", 
               index, total_count, name.c_str(), median_sec, schnorr_times);
    } else {
        printf("%d. %-30s %.3f seconds (%6.0f Schnorr sigs", 
               index, name.c_str(), median_sec, schnorr_times);
    }
    
    double varops_percentage = (double(varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0;
    printf(", %6.1f%% of varops budget consumed)\n", varops_percentage);
}

static void RunAllBenchmarks(ankerl::nanobench::Bench& bench, std::vector<BenchTestCase>& test_cases) {
    printf("Running Schnorr signature benchmark...\n");
    RunSchnorrBenchmark(bench, "Schnorr signature validation");
    
    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = FindResult(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    double schnorr_block_time = schnorr_median_time * SchnorrConfig::SIGNATURES_PER_BLOCK;
    printf("Schnorr block time: %.3f seconds\n", schnorr_block_time);
    int bench_count = 0;
    
    for (BenchTestCase& test_case : test_cases) {
        RunBenchmark(bench, test_case);
        
        // Get median time and calculate Schnorr validations
        if (const auto* result = FindResult(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double schnorr_times = median_sec / schnorr_median_time;
            
            PrintBenchmarkResult(++bench_count, test_cases.size(), test_case.name, 
                               median_sec, schnorr_times, test_case.varops_consumed, true);
        }
    }
}

struct BenchResult {
    std::string name;
    double median_sec;
    uint64_t varops_consumed;
    double per_varop_ns;
};

static std::vector<BenchResult> CollectResults(const ankerl::nanobench::Bench& bench, const std::vector<BenchTestCase>& test_cases) {
    std::vector<BenchResult> results;
    results.reserve(test_cases.size());
    
    for (const auto& test_case : test_cases) {
        if (const auto* result = FindResult(bench, test_case.name)) {
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

    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = FindResult(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    // add schnorr median time to result vector
    results.push_back(BenchResult{
        "Schnorr signature validation",
        schnorr_median_time * SchnorrConfig::SIGNATURES_PER_BLOCK,
        0,
        0
    });

    // Sort by block time
    std::sort(results.begin(), results.end(), 
        [](const auto& a, const auto& b) { return a.median_sec > b.median_sec; });
    
    return results;
}

static void PrintWorstCases(std::vector<BenchResult>& results) {
    // print 20 worst cases sorted by median_sec
    std::sort(results.begin(), results.end(), 
        [](const BenchResult& a, const BenchResult& b) { return a.median_sec > b.median_sec; });

    std::cout << "\n================================================================================\n";
    std::cout << "SLOWEST 20 OPERATIONS\n";
    std::cout << "================================================================================\n";
    

    double schnorr_median_time = 0.0;
    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") {
            schnorr_median_time = result.median_sec;
            break;
        }
    }
    for (int i = 0; i < std::min(20, static_cast<int>(results.size())); i++) {
        double schnorr_times = schnorr_median_time > 0 ? results[i].median_sec / schnorr_median_time * SchnorrConfig::SIGNATURES_PER_BLOCK : 0;
        
        PrintBenchmarkResult(i + 1, 0, results[i].name, results[i].median_sec, 
                           schnorr_times, results[i].varops_consumed, false);
    }
    std::cout << "================================================================================\n";
}

static opcodetype GetOpcodeFromName(const std::string& name) {
    // Build reverse mapping from GetOpName
    static std::map<std::string, opcodetype> opcode_map;
    static bool initialized = false;
    
    if (!initialized) {
        for (unsigned int op = 0; op <= 0xff; ++op) {
            opcodetype opcode = static_cast<opcodetype>(op);
            std::string opname = GetOpName(opcode);
            if (opname != "OP_UNKNOWN") {
                opcode_map[opname] = opcode;
            }
        }
        initialized = true;
    }
    
    // Convert input to uppercase
    std::string upper_name = name;
    std::transform(upper_name.begin(), upper_name.end(), upper_name.begin(), ::toupper);
    
    // Try exact match first
    if (opcode_map.find(upper_name) != opcode_map.end()) {
        return opcode_map[upper_name];
    }
    
    // Try with OP_ prefix
    std::string prefixed_name = "OP_" + upper_name;
    if (opcode_map.find(prefixed_name) != opcode_map.end()) {
        return opcode_map[prefixed_name];
    }
    
    throw std::invalid_argument("Unknown opcode name: " + name);
}

static void ParseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--opcodes") {
            // Collect all following arguments until we hit another flag or end of args
            i++; // Move to first opcode argument
            std::vector<std::string> opcode_names;
            
            while (i < argc && argv[i][0] != '-') {
                opcode_names.push_back(argv[i]);
                i++;
            }
            i--; // Back up one since the loop will increment
            
            if (opcode_names.empty()) {
                std::cerr << "Error: --opcodes requires at least one opcode name" << std::endl;
                exit(1);
            }
            
            try {
                std::vector<std::string> resolved_names;
                for (const auto& opcode_name : opcode_names) {
                    opcodetype opcode = GetOpcodeFromName(opcode_name);
                    SELECTED_OPCODES.insert(opcode);
                    resolved_names.push_back(GetOpName(opcode));
                }
                std::cout << "Running benchmarks for opcodes: ";
                for (const auto& name : resolved_names) {
                    std::cout << name << " ";
                }
                std::cout << std::endl;
            } catch (const std::invalid_argument& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                std::cerr << "Available opcodes: OP_ROLL, OP_SHA256, OP_ADD, OP_MUL, etc." << std::endl;
                exit(1);
            }
        } else if (arg == "--epochs" && i + 1 < argc) {
            try {
                Timing::EPOCHS = std::stoi(argv[i + 1]);
                if (Timing::EPOCHS <= 0) {
                    throw std::invalid_argument("Epochs must be positive");
                }
                std::cout << "Setting epochs to: " << Timing::EPOCHS << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error parsing epochs: " << e.what() << std::endl;
                exit(1);
            }
            i++; // Skip next argument as it's the epoch count
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --opcodes <opcode1> [opcode2] ...  Run benchmarks for specific opcodes only" << std::endl;
            std::cout << "  --epochs <number>                  Set number of benchmark epochs" << std::endl;
            std::cout << "  --help, -h                         Show this help message" << std::endl;
            std::cout << std::endl;
            std::cout << "Example opcodes: OP_ROLL, OP_SHA256, OP_ADD, OP_MUL, OP_CAT" << std::endl;
            std::cout << "Example usage:" << std::endl;
            std::cout << "  " << argv[0] << " --opcodes OP_ROLL OP_SHA256" << std::endl;
            std::cout << "  " << argv[0] << " --opcodes OP_ADD OP_MUL --epochs 10" << std::endl;
            exit(0);
        }
    }
}

int main(int argc, char* argv[]) {
    ParseArguments(argc, argv);
    
    ankerl::nanobench::Bench bench = SetupBenchmark();
    std::vector<BenchTestCase> test_cases = CreateTestCases();

    RunAllBenchmarks(bench, test_cases);

    std::vector<BenchResult> results = CollectResults(bench, test_cases);
    PrintWorstCases(results);
}
