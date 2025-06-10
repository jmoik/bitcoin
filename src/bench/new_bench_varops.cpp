// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench_varops_helpers.h>
#include <bench/bench_config.h>
#include <pubkey.h>
#include <span.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <map>
#include <fstream>
#include <vector>
#include <cstdint>

using namespace std;
using namespace BenchConfig;

static void run_schnorr_benchmark(ankerl::nanobench::Bench &bench, const string& name) {
    KeyPair::ECC_Start();

    // Create key pair
    CKey key;
    auto test_key = SchnorrConfig::getTestKey();
    key.Set(test_key.begin(), test_key.end(), false);
    CPubKey pubkey = key.GetPubKey();

    vector<unsigned char> vchSig(64);
    const uint256 hash = uint256::ONE;
    key.SignSchnorr(hash, vchSig, NULL, hash);

    XOnlyPubKey xpub(pubkey);
    Span<const unsigned char> sigbytes(vchSig.data(), vchSig.size());
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
    int repetitions{1000};
};

struct StackTemplate {
    std::string name;
    uint64_t size;
    int count;
    ValuePattern pattern;
    
    auto get_stack() const { return init_stack(size, count, pattern); }
};

// Helper function to get restoration type for an opcode
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
        case OP_NEGATE:
        case OP_ABS:
        case OP_0NOTEQUAL:
            return RestorationType::DROP_AND_DUP;

        case OP_SIZE:
        case OP_OVER:
        case OP_TUCK:
            return RestorationType::DROP;

        // Verify operations (2 in -> 0 out)
        case OP_EQUALVERIFY:
            return RestorationType::DUP_OP_DUP;

        // Verify operations (2 in -> 1 out), this is a varop change, why?
        case OP_NUMEQUALVERIFY:
            return RestorationType::DUP_OP_DROP_DUP;

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
    
    // Use configuration values instead of hardcoded constants
    if (BenchConfig::TESTING) {
        bench.output(nullptr)
            .epochs(Timing::EPOCHS)
            .minEpochIterations(Timing::MIN_EPOCH_ITERATIONS)
            .minEpochTime(std::chrono::milliseconds(Timing::MIN_EPOCH_TIME_MS))
            .warmup(Timing::WARMUP);
    } else {
        bench.output(nullptr)
            .epochs(Timing::EPOCHS)
            .minEpochIterations(Timing::MIN_EPOCH_ITERATIONS)
            .minEpochTime(std::chrono::milliseconds(Timing::MIN_EPOCH_TIME_MS))
            .warmup(Timing::WARMUP);
    }
    
    SHA256AutoDetect();
    return bench;
}

static std::vector<ScriptTemplate> create_script_templates() {
    std::vector<ScriptTemplate> script_templates;
    
    // Loop through all opcodes
    for (unsigned int op = 0; op <= 0xB2; op++) {
        opcodetype opcode = static_cast<opcodetype>(op);
        
        std::string opname = GetOpName(opcode);

        // only include Op_mul
        // if (opname != "OP_MUL") {
        //     continue;
        // }
        
        // Use configuration to check if operation should be skipped
        if (ScriptConfig::shouldSkipOperation(opname)) {
            continue;
        }

        RestorationType type = getRestorationType(opcode);
        if (type == RestorationType::UNSUPPORTED) {
            printf("Warning: Skipping unsupported opcode 0x%02x (%s)\n", op, opname.c_str());
            continue;
        }
        
        // Create template
        ScriptTemplate template_;
        template_.name = GetOpName(opcode);
        template_.opcodes = createOpcodes(opcode, type);
        
        // Use configuration to get repetitions
        template_.repetitions = ScriptConfig::getRepetitions(opname);
        
        script_templates.push_back(template_);
    }
    
    return script_templates;
}

static std::vector<BenchTestCase> create_test_cases(const std::vector<ScriptTemplate>& script_templates) {
    // Get stack templates from configuration
    auto config_stack_templates = StackTemplates::getTemplates();
    
    // Create test cases by combining script and stack templates
    std::vector<BenchTestCase> test_cases;
    test_cases.reserve(script_templates.size() * config_stack_templates.size());
    
    for (const auto& script : script_templates) {
        for (const auto& stack_config : config_stack_templates) {
            // Use configuration to check if operation should skip large inputs
            if (ScriptConfig::shouldSkipLargeInput(script.name, stack_config.name)) {
                continue;
            }
            
            // Create special minimal stack for shift operations to avoid size explosion
            std::vector<std::vector<unsigned char>> test_stack;
            if (script.name == "OP_LSHIFT" || script.name == "OP_RSHIFT") {
                // For shift ops: use very simple small values to avoid size explosion
                test_stack.clear();
                test_stack.push_back(std::vector<unsigned char>(1, 1)); // Small data value (1 byte = 1)  
                test_stack.push_back(std::vector<unsigned char>(1, 0)); // Shift by 0 bits (no change)
            } else if (script.name == "OP_SUBSTR") {
                // For substr ops: use simple small values to avoid size explosion
                test_stack.clear();
                test_stack.push_back(std::vector<unsigned char>(1, 5)); // Small data value (1 byte = 5)  
                test_stack.push_back(std::vector<unsigned char>(1, 0)); // Start index 0
                test_stack.push_back(std::vector<unsigned char>(1, 1)); // Length 1
            } else {
                test_stack = init_stack(stack_config.size, stack_config.count, stack_config.pattern);
            }
            
            test_cases.emplace_back(
                script.name + "_" + stack_config.name,
                test_stack,
                create_script(script.opcodes, script.repetitions)
            );
        }
    }
    
    return test_cases;
}

static void run_all_benchmarks(ankerl::nanobench::Bench& bench, std::vector<BenchTestCase>& test_cases) {
    // Run Schnorr benchmark first
    cout << "Running Schnorr signature benchmark..." << endl;
    run_schnorr_benchmark(bench, "Schnorr signature validation");
    int bench_count = 0;
    
    for (auto& test_case : test_cases) {
        cout << "Benchmark " << ++bench_count << "/" << test_cases.size() 
                  << ": " << test_case.name << endl;
        
        run_benchmark(bench, test_case);
    }
}

struct BenchResult {
    std::string name;
    double median_sec;
    uint64_t varops_consumed;
    double block_time_varops_sec;
    double per_varop_ns;
    uint64_t weight;
    double time_per_weight_ns;
    double block_weight_time_sec;
    double block_time_sec;
};

static std::vector<BenchResult> collect_results(const ankerl::nanobench::Bench& bench, const std::vector<BenchTestCase>& test_cases) {
    std::vector<BenchResult> results;
    results.reserve(test_cases.size());
    
    for (const auto& test_case : test_cases) {
        if (const auto* result = find_result(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double block_time_varops_sec_val = test_case.varops_consumed > 0 
                ? (BLOCK_VAROPS * median_sec) / test_case.varops_consumed 
                : 0;
            double per_varop_ns = test_case.varops_consumed > 0 
                ? (median_sec * 1e9) / test_case.varops_consumed 
                : 0;
            
            uint64_t script_weight = test_case.script.size();
            // uint64_t stack_weight = 0;
            // for (const auto& item : test_case.stack) {
            //     stack_weight += item.size(); // Size in bytes of each stack item
            // }
            // uint64_t total_weight = script_weight + stack_weight;
            uint64_t total_weight = script_weight;
            
            // Calculate time for 4M weight units (full block)
            double block_weight_time_sec_val = total_weight > 0 
                ? (4000000 * median_sec) / total_weight 
                : 0;
            
            // Calculate time per weight unit in nanoseconds
            double time_per_weight_ns = total_weight > 0
                ? (median_sec * 1e9) / total_weight
                : 0;

            // Calculate the new overall block_time_sec
            double block_time_sec_val = 0;
            if (block_time_varops_sec_val > 0 && block_weight_time_sec_val > 0) {
                block_time_sec_val = std::min(block_time_varops_sec_val, block_weight_time_sec_val);
            } else if (block_time_varops_sec_val > 0) {
                block_time_sec_val = block_time_varops_sec_val;
            } else {
                block_time_sec_val = block_weight_time_sec_val;
            }
            
            results.push_back({
                test_case.name, 
                median_sec, 
                test_case.varops_consumed,
                block_time_varops_sec_val,
                per_varop_ns, 
                total_weight, 
                time_per_weight_ns,
                block_weight_time_sec_val,
                block_time_sec_val
            });
        }
    }
    
    // Sort by block time
    std::sort(results.begin(), results.end(), 
        [](const auto& a, const auto& b) { return a.block_time_sec < b.block_time_sec; });
    
    return results;
}

static void print_results(const std::vector<BenchResult>& results) {
    // Print results table
    std::string separator(OutputConfig::TABLE_WIDTH, '-');
    cout << separator << endl;
    cout << left << setw(OutputConfig::ColumnWidths::NAME) << "Test Name"
              << " | " << right << setw(OutputConfig::ColumnWidths::TIME) << "Time (sec)"
              << " | " << setw(OutputConfig::ColumnWidths::VAROPS) << "VarOps Consumed"
              << " | " << setw(OutputConfig::ColumnWidths::BLOCK_TIME_VAROPS) << "Block Time (VarOps) (s)"
              << " | " << setw(OutputConfig::ColumnWidths::TIME_PER_VAROP) << "Time/VarOp (ns)"
              << " | " << setw(OutputConfig::ColumnWidths::WEIGHT)  << "Weight"
              << " | " << setw(OutputConfig::ColumnWidths::TIME_PER_WEIGHT) << "Time/Weight (ns)"
              << " | " << setw(OutputConfig::ColumnWidths::BLOCK_WEIGHT_TIME) << "Block Weight Time (s)"
              << " | " << setw(OutputConfig::ColumnWidths::BLOCK_TIME) << "Block Time (s)" << endl;
    cout << separator << endl;
    
    for (const auto& res : results) {
        cout << left << setw(OutputConfig::ColumnWidths::NAME) << res.name << " | "
                  << right << fixed << setprecision(OutputConfig::Precision::TIME) << setw(OutputConfig::ColumnWidths::TIME) << res.median_sec << " | "
                  << setw(OutputConfig::ColumnWidths::VAROPS) << res.varops_consumed << " | "
                  << setprecision(OutputConfig::Precision::BLOCK_TIME) << setw(OutputConfig::ColumnWidths::BLOCK_TIME_VAROPS) << res.block_time_varops_sec << " | "
                  << setprecision(OutputConfig::Precision::PER_VAROP) << setw(OutputConfig::ColumnWidths::TIME_PER_VAROP) << res.per_varop_ns << " | "
                  << setw(OutputConfig::ColumnWidths::WEIGHT) << res.weight << " | "
                  << setprecision(OutputConfig::Precision::PER_WEIGHT) << setw(OutputConfig::ColumnWidths::TIME_PER_WEIGHT) << res.time_per_weight_ns << " | "
                  << setprecision(OutputConfig::Precision::BLOCK_TIME) << setw(OutputConfig::ColumnWidths::BLOCK_WEIGHT_TIME) << res.block_weight_time_sec << " | "
                  << setprecision(OutputConfig::Precision::BLOCK_TIME) << setw(OutputConfig::ColumnWidths::BLOCK_TIME) << res.block_time_sec << endl;
    }
}

static void write_csv_results(const std::vector<BenchResult>& results, const std::string& filename) {
    // Open CSV file for writing using provided filename
    std::ofstream csv_file(filename);
    if (csv_file.is_open()) {
        // Write CSV header
        csv_file << "Test Name,Time (sec),VarOps Consumed,Block Time (VarOps) (s),Time/VarOp (ns),Weight,Time/Weight (ns),Block Weight Time (s),Block Time (s)\n";
        
        for (const auto& res : results) {
            csv_file << res.name << ","
                    << fixed << setprecision(OutputConfig::Precision::TIME) << res.median_sec << ","
                    << res.varops_consumed << ","
                    << setprecision(OutputConfig::Precision::BLOCK_TIME) << res.block_time_varops_sec << ","
                    << setprecision(OutputConfig::Precision::PER_VAROP) << res.per_varop_ns << ","
                    << res.weight << ","
                    << setprecision(OutputConfig::Precision::PER_WEIGHT) << res.time_per_weight_ns << ","
                    << setprecision(OutputConfig::Precision::BLOCK_TIME) << res.block_weight_time_sec << ","
                    << setprecision(OutputConfig::Precision::BLOCK_TIME) << res.block_time_sec << "\n";
        }
        
        csv_file.close();
        cout << "\nResults have been written to " << filename << "\n";
    }
}

static void print_schnorr_comparison(const ankerl::nanobench::Bench& bench) {
    // Add Schnorr signature comparison using configuration
    const ankerl::nanobench::Result *schnorr_result = find_result(bench, "Schnorr signature validation");
    if (schnorr_result) {
        double schnorr_single_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
        double schnorr_block_time = schnorr_single_time * SchnorrConfig::SIGNATURES_PER_BLOCK;
        cout << "\n=== Schnorr Signature Comparison ===" << endl;
        cout << "Time for " << SchnorrConfig::SIGNATURES_PER_BLOCK << " Schnorr signature validations: " 
             << fixed << setprecision(OutputConfig::Precision::BLOCK_TIME) << schnorr_block_time 
             << " seconds" << endl;
        cout << "Single Schnorr signature validation: " 
             << fixed << setprecision(OutputConfig::Precision::TIME) << schnorr_single_time 
             << " seconds" << endl;
    }
}

int main(int argc, char* argv[]) {
    // Check for filename argument
    std::string output_filename = OutputConfig::CSV_FILENAME; // Default filename
    if (argc > 1) {
        output_filename = argv[1];
    }
    
    auto bench = setup_benchmark();
    auto script_templates = create_script_templates();
    auto test_cases = create_test_cases(script_templates);
    
    run_all_benchmarks(bench, test_cases);
    
    auto results = collect_results(bench, test_cases);
    print_results(results);
    write_csv_results(results, output_filename);
    print_schnorr_comparison(bench);
    
    return 0;
}
