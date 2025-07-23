// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/val64.h>
#include <common/args.h>
#include <key.h>
#include <script/valtype_stack.h>
#include <fstream>
#include <util/translation.h>

const TranslateFn G_TRANSLATION_FUN{nullptr};
// =================================
//      Configuration Globals
// =================================

std::set<opcodetype> SELECTED_OPCODES;
constexpr uint64_t MAX_BLOCK_WEIGHT_UINT64 = MAX_BLOCK_WEIGHT;
constexpr uint64_t VAROPS_BUDGET_PER_BYTE_UINT64 = VAROPS_BUDGET_PER_BYTE;
constexpr uint64_t TOTAL_VAROPS_BUDGET = MAX_BLOCK_WEIGHT_UINT64 * VAROPS_BUDGET_PER_BYTE_UINT64;
bool SILENT_MODE = false;
std::string OUTPUT_FILE = "";

namespace Timing {
    int EPOCHS = 1;
    constexpr int EPOCH_ITERATIONS = 1;
    constexpr int SCHNORR_EPOCHS = 5;
    constexpr int SCHNORR_EPOCH_ITERATIONS = 1000;
    constexpr int WARMUP = 0;
}

constexpr int SIGNATURES_PER_BLOCK = 80000;

// =================================
//      Enums and Structs
// =================================

enum class ValuePattern {
    STANDARD,
    IDENTICAL,
    ZEROS,
    MAX_VALUE
};

struct StackTemplate {
    std::string name;
    uint64_t size;
    int count;
    ValuePattern pattern;
};

struct ScriptTemplate {
    std::string name;
    std::vector<opcodetype> opcodes;
    std::string sequence_name;
};

struct BenchTestCase {
    std::string name;
    ValtypeStack stack;
    CScript script;
    uint64_t varops_consumed{0};
};

struct BenchResult {
    std::string name;
    double median_sec;
    uint64_t varops_consumed;
    double per_varop_ns;
};

// =================================
//      Helper Functions
// =================================

static const ankerl::nanobench::Result* FindResult(const ankerl::nanobench::Bench& benches,
                                                   const std::string& name)
{
    for (auto& r : benches.results()) {
        if (r.config().mBenchmarkName == name)
            return &r;
    }
    return nullptr;
}

static ValtypeStack InitStack(
    uint64_t size,
    int count,
    ValuePattern pattern)
{
    ValtypeStack stack;
    uint8_t value1, value2;

    switch (pattern) {
    case ValuePattern::STANDARD:
        value1 = 1; value2 = 2; break;
    case ValuePattern::IDENTICAL:
        value1 = value2 = 1; break;
    case ValuePattern::ZEROS:
        value1 = value2 = 0; break;
    case ValuePattern::MAX_VALUE:
        value1 = value2 = 0xFF; break;
    }

    stack.push_back(std::vector<unsigned char>(size, value1));
    for (int i = 1; i < count; i++) {
        stack.push_back(std::vector<unsigned char>(size, value2));
    }
    return stack;
}

static CScript CreateScript(const std::vector<opcodetype>& opcodes) {
    CScript script;
    while (script.size() < MAX_BLOCK_WEIGHT) {
        for (const auto& opcode : opcodes) {
            script << opcode;
            if (script.size() >= MAX_BLOCK_WEIGHT) break;
        }
    }
    return script;
}

std::string GetSequenceName(const std::vector<opcodetype>& opcodes) {
    std::string name = "";
    for (const auto& opcode : opcodes) {
      auto opname = GetOpName(opcode);
      // remove OP_ prefix
      if (opname.find("OP_") == 0) {
        opname = opname.substr(3);
      }
      name += opname + "_";
    }
    name.pop_back();
    return name;
  }

// =================================
//      Benchmark Setup
// =================================

std::vector<StackTemplate> GetStackTemplates() {
    return {
        {"1Bx2", 1, 2, ValuePattern::IDENTICAL},
        {"10Bx2", 10, 2, ValuePattern::IDENTICAL},
        {"100Bx2", 100, 2, ValuePattern::IDENTICAL},
        {"520Bx2", 520, 2, ValuePattern::IDENTICAL},
        {"1KBx2", 1000, 2, ValuePattern::IDENTICAL},
        {"10KBx2", 10000, 2, ValuePattern::IDENTICAL},
        {"100KBx2", 100000, 2, ValuePattern::IDENTICAL},
        {"1MBx2", 1000000, 2, ValuePattern::IDENTICAL},
        {"2MBx2", 2000000, 2, ValuePattern::IDENTICAL},
        {"200Bx32k", 100, MAX_TAPSCRIPT_V2_STACK_SIZE - 5, ValuePattern::IDENTICAL}
    };
}

inline bool ShouldSkipCase(const std::string& opname, const std::string& stack_name) {
    static const std::map<std::string, std::vector<std::string>> size_limited_operations = {
        {"OP_MUL", {"1MBx2", "2MBx2", "4MBx2"}},
        {"OP_DIV", {"1MBx2", "2MBx2", "4MBx2"}},
        {"OP_RIPEMD160", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},
        {"OP_SHA1", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},
        {"OP_OVER", {"2MBx2", "4MBx2"}},
        {"OP_ROT", {"2MBx2", "4MBx2"}},
        {"OP_2ROT", {"2MBx2", "4MBx2"}},
        {"OP_2OVER", {"2MBx2", "4MBx2"}},
        {"OP_2SWAP", {"2MBx2", "4MBx2"}}
    };
    
    auto it = size_limited_operations.find(opname);
    if (it != size_limited_operations.end()) {
        for (const auto& limited_stack : it->second) {
            if (stack_name == limited_stack) return true;
        }
    }
    return false;
}

std::vector<std::vector<opcodetype>> GetOpcodes(opcodetype opcode) {
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
            return {{opcode, OP_DROP, OP_DUP}};

        // Bit operations (2 in -> 1 out)
        case OP_AND:
        case OP_OR:
        case OP_XOR:
        case OP_EQUAL:
            return {{OP_DUP, opcode, OP_DROP, OP_DUP}};

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
            return {{OP_DUP, opcode, OP_DROP, OP_DUP}, {opcode, OP_DUP}};

        // Stack manipulation (0 in -> 1 out)
        case OP_SIZE:
        case OP_OVER:
        case OP_TUCK:
        case OP_DEPTH:
        case OP_DUP:
        case OP_IFDUP:
            return {{opcode, OP_DROP}};

        case OP_CHECKLOCKTIMEVERIFY:
            return {{opcode}};

        case OP_2DROP:
            return {{OP_DUP, OP_DUP, opcode}};

        case OP_2OVER:
            return {{opcode, OP_DROP, OP_DROP}};

        // Stack manipulation (1 in -> 0 out)
        case OP_ROLL:
        case OP_VERIFY:
        case OP_NIP:
            return {{opcode, OP_DUP}};

        // Verify operations (2 in -> 0 out)
        case OP_EQUALVERIFY:
        case OP_NUMEQUALVERIFY:
            return {{OP_DUP, opcode, OP_DUP}};

        // Stack manipulation (0 in -> 0 out)
        case OP_NOP:
        case OP_SWAP:
        case OP_2SWAP:
        case OP_ROT:
        case OP_2ROT:
        case OP_INVERT:
        // case OP_PICK: 
            return {{opcode}};

        // Stack manipulation (0 in -> 2 out)
        case OP_2DUP:
            return {{opcode, OP_DROP, OP_DROP}};

        // Special cases (3 in -> 1 out)
        case OP_WITHIN:
        case OP_SUBSTR:
            return {{OP_DUP, OP_DUP, opcode, OP_DROP, OP_DUP}};

        case OP_TOALTSTACK:
            return {{opcode, OP_FROMALTSTACK}};

        case OP_DROP:
            return {{opcode, OP_DUP}};

        default:
            return {}; // Unsupported
    }
}
    
    
    ankerl::nanobench::Bench SetupBenchmark() {
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
    for (unsigned int op = 0x4c; op <= 0xba; op++) {
        opcodetype opcode = static_cast<opcodetype>(op);
        if (!SELECTED_OPCODES.empty() && SELECTED_OPCODES.find(opcode) == SELECTED_OPCODES.end()) {
            continue;
        }
        std::string opname = GetOpName(opcode);
        auto sequences = GetOpcodes(opcode);
        
        if (sequences.empty()) {
            printf("Warning: Skipping unsupported opcode 0x%02x (%s)\n", op, opname.c_str());
            continue;
        }
        
        // Create a template for each sequence
        for (const auto& opcodes : sequences) {
            std::string sequence_name = GetSequenceName(opcodes);
            std::string template_name = sequence_name;
            script_templates.emplace_back(template_name, opcodes, sequence_name);
        }
    }
    return script_templates;
}

static bool HandleSpecialCases(const ScriptTemplate& script_template, 
    const StackTemplate& stack_config,
    std::vector<BenchTestCase>& test_cases) {
// Handle shift operations (LSHIFT, RSHIFT)
if (script_template.name.find("LSHIFT") != std::string::npos || script_template.name.find("RSHIFT") != std::string::npos) {
if (stack_config.name == "1MB") {
auto stack = InitStack(stack_config.size, stack_config.count, stack_config.pattern);
stack.pop_back();
stack.push_back(std::vector<unsigned char>(1, 1));
test_cases.emplace_back(script_template.name + "_" + stack_config.name, stack, CreateScript(script_template.opcodes));
}
return true;
}

// Handle ROLL operations
if (script_template.name.find("ROLL") != std::string::npos) {
int maximum_size = MAX_TAPSCRIPT_V2_STACK_SIZE;
ValtypeStack stack;
int roll_index = MAX_TAPSCRIPT_V2_STACK_SIZE - 5;
for (int i = 0; i < maximum_size - 1; i++) {
stack.push_back(Val64(roll_index).move_to_valtype());
}
test_cases.emplace_back(script_template.name + "_MAX_STACK_SIZE", stack, CreateScript(script_template.opcodes));
return true;
}

// Handle stack manipulation operations (ROT, OVER, 2OVER, 2ROT, 2SWAP)
if (script_template.name.find("ROT") != std::string::npos || 
script_template.name.find("OVER") != std::string::npos || 
script_template.name.find("2OVER") != std::string::npos || 
script_template.name.find("2ROT") != std::string::npos || 
script_template.name.find("2SWAP") != std::string::npos) {
auto stack = InitStack(stack_config.size, 6, stack_config.pattern);
test_cases.emplace_back(script_template.name + "_" + stack_config.name, stack, CreateScript(script_template.opcodes));
test_cases.emplace_back(script_template.name + "_" + stack_config.name, stack, CreateScript(script_template.opcodes));
return true;
}

return false;
}

static std::vector<BenchTestCase> CreateTestCases() {
    std::vector<StackTemplate> config_stack_templates = GetStackTemplates();
    std::vector<ScriptTemplate> script_templates = CreateScriptTemplates();
    std::vector<BenchTestCase> test_cases;
    test_cases.reserve(script_templates.size() * config_stack_templates.size());

    for (const auto& script_template : script_templates) {
        for (auto& stack_config : config_stack_templates) {
            if (ShouldSkipCase(script_template.name, stack_config.name)) continue;
            
            if (HandleSpecialCases(script_template, stack_config, test_cases)) {
                continue;
            }
            
            test_cases.emplace_back(
                script_template.name + "_" + stack_config.name,
                InitStack(stack_config.size, stack_config.count, stack_config.pattern),
                CreateScript(script_template.opcodes)
            );
        }
    }
    
    std::sort(test_cases.begin(), test_cases.end(), [](const BenchTestCase& a, const BenchTestCase& b) { return a.name < b.name; });
    test_cases.erase(std::unique(test_cases.begin(), test_cases.end(), [](const BenchTestCase& a, const BenchTestCase& b) { return a.name == b.name; }), test_cases.end());
    
    return test_cases;
}

// =================================
//      Benchmark Execution
// =================================

static void RunBenchmark(ankerl::nanobench::Bench& bench, 
                         BenchTestCase& test_case) {
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;

    const uint64_t varops_block_budget = TOTAL_VAROPS_BUDGET;
    assert(varops_block_budget > 2e10);
    uint64_t working_budget = varops_block_budget;
    bool result = false;

    const size_t stack_pool_size = Timing::EPOCHS * 1;
    size_t stack_index = 0;
    std::vector<ValtypeStack> stack_pool;
    stack_pool.reserve(stack_pool_size);
    for (size_t i = 0; i < stack_pool_size; ++i) {
        stack_pool.push_back(test_case.stack);
    }

    bench.run(test_case.name, [&] {
        assert(stack_index < stack_pool_size);
        ValtypeStack& working_stack = stack_pool[stack_index];
        working_budget = varops_block_budget;
        result = EvalScript(working_stack, test_case.script, 0, checker,
                        SigVersion::TAPSCRIPT_V2, sdata, &serror, &working_budget);
        ++stack_index;
    });

    if (!result) {
        std::string error_msg = ScriptErrorString(serror);
        if (error_msg.find("Varops count exceeded") == std::string::npos) {
            printf("Script error: %s\n", error_msg.c_str());
        }
    }
    if (working_budget != varops_block_budget && test_case.varops_consumed == 0) {
        test_case.varops_consumed = varops_block_budget - working_budget;
    }
    serror = SCRIPT_ERR_OK;
}

static void RunSchnorrBenchmark(ankerl::nanobench::Bench &bench, const std::string& name) {
    bench.epochIterations(Timing::SCHNORR_EPOCH_ITERATIONS).epochs(Timing::SCHNORR_EPOCHS);
    
    KeyPair::ECC_Start();
    CKey key;
    std::vector<unsigned char> test_key(32, 0);
    test_key[31] = 1;
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
    bench.epochs(Timing::EPOCHS).epochIterations(Timing::EPOCH_ITERATIONS);
}

static void RunAllBenchmarks(ankerl::nanobench::Bench& bench, std::vector<BenchTestCase>& test_cases) {
    if (!SILENT_MODE) {
        printf("Running Schnorr signature benchmark...\n");
    }
    RunSchnorrBenchmark(bench, "Schnorr signature validation");
    
    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = FindResult(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    double schnorr_block_time = schnorr_median_time * SIGNATURES_PER_BLOCK;
    if (!SILENT_MODE) {
        printf("Schnorr block time: %.3f seconds\n", schnorr_block_time);
    }
    int bench_count = 0;
    
    for (BenchTestCase& test_case : test_cases) {
        RunBenchmark(bench, test_case);
        
        if (const auto* result = FindResult(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double schnorr_times = median_sec / schnorr_median_time;
            
            if (!SILENT_MODE) {
                printf("Benchmark %3d/%zu: %-30s %.3f seconds (%6.0f Schnorr sigs, %6.1f%% of varops budget consumed)\n", 
                       ++bench_count, test_cases.size(), test_case.name.c_str(), median_sec, schnorr_times, 
                       (double(test_case.varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
            } else {
                ++bench_count;
            }
        }
    }
}

// =================================
//      Result Processing
// =================================

static std::vector<BenchResult> CollectResults(const ankerl::nanobench::Bench& bench, const std::vector<BenchTestCase>& test_cases) {
    std::vector<BenchResult> results;
    results.reserve(test_cases.size());
    
    for (const auto& test_case : test_cases) {
        if (const auto* result = FindResult(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double per_varop_ns = test_case.varops_consumed > 0 ? (median_sec * 1e9) / test_case.varops_consumed : 0;
            results.emplace_back(test_case.name, median_sec, test_case.varops_consumed, per_varop_ns);
        }
    }

    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = FindResult(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    results.push_back(BenchResult{"Schnorr signature validation", schnorr_median_time * SIGNATURES_PER_BLOCK, 0, 0});
    std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) { return a.median_sec > b.median_sec; });
    
    return results;
}

static void PrintWorstCases(std::vector<BenchResult>& results) {
    std::sort(results.begin(), results.end(), [](const BenchResult& a, const BenchResult& b) { return a.median_sec > b.median_sec; });

    std::cout << "\n================================================================================\n";
    std::cout << "SLOWEST OPERATIONS\n";
    std::cout << "================================================================================\n";
    
    double schnorr_median_time = 0.0;
    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") {
            schnorr_median_time = result.median_sec;
            break;
        }
    }
    
    for (int i = 0; i < std::min(100, static_cast<int>(results.size())); i++) {
        double schnorr_times = schnorr_median_time > 0 ? results[i].median_sec / schnorr_median_time * SIGNATURES_PER_BLOCK : 0;
        printf("%d. %-30s %.3f seconds (%6.0f Schnorr sigs, %6.1f%% of varops budget consumed)\n",
               i + 1, results[i].name.c_str(), results[i].median_sec, schnorr_times,
               (double(results[i].varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
    }
    std::cout << "================================================================================\n";
}

static void SaveResultsToFile(const std::vector<BenchResult>& results, const std::string& filepath) {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filepath << " for writing" << std::endl;
        return;
    }
    
    double schnorr_median_time = 0.0;
    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") {
            schnorr_median_time = result.median_sec;
            break;
        }
    }
    
    // Write CSV header
    file << "Rank,Name,Seconds,Schnorr_Equivalents,Varops_Percentage\n";
    
    // Write all results as CSV
    for (size_t i = 0; i < results.size(); i++) {
        double schnorr_times = schnorr_median_time > 0 ? results[i].median_sec / schnorr_median_time * SIGNATURES_PER_BLOCK : 0;
        double varops_percentage = (double(results[i].varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0;
        
        file << (i + 1) << ","
             << results[i].name << ","
             << results[i].median_sec << ","
             << schnorr_times << ","
             << varops_percentage << "\n";
    }
    
    file.close();
    if (!SILENT_MODE) {
        std::cout << "Results saved to: " << filepath << std::endl;
    }
}

// =================================
//      Argument Parsing
// =================================

static opcodetype GetOpcodeFromName(const std::string& name) {
    static std::map<std::string, opcodetype> opcode_map;
    if (opcode_map.empty()) {
        for (unsigned int op = 0; op <= 0xff; ++op) {
            opcodetype opcode = static_cast<opcodetype>(op);
            std::string opname = GetOpName(opcode);
            if (opname != "OP_UNKNOWN") opcode_map[opname] = opcode;
        }
    }
    
    std::string upper_name = name;
    std::transform(upper_name.begin(), upper_name.end(), upper_name.begin(), ::toupper);
    
    if (opcode_map.count(upper_name)) return opcode_map[upper_name];
    if (opcode_map.count("OP_" + upper_name)) return opcode_map["OP_" + upper_name];
    
    throw std::invalid_argument("Unknown opcode name: " + name);
}

static void ParseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--opcodes") {
            i++;
            std::vector<std::string> opcode_names;
            while (i < argc && argv[i][0] != '-') {
                opcode_names.push_back(argv[i++]);
            }
            i--; 
            
            if (opcode_names.empty()) {
                std::cerr << "Error: --opcodes requires at least one opcode name" << std::endl;
                exit(1);
            }
            
            try {
                if (!SILENT_MODE) {
                    std::cout << "Running benchmarks for opcodes: ";
                    for (const auto& opcode_name : opcode_names) {
                        opcodetype opcode = GetOpcodeFromName(opcode_name);
                        SELECTED_OPCODES.insert(opcode);
                        std::cout << GetOpName(opcode) << " ";
                    }
                    std::cout << std::endl;
                } else {
                    for (const auto& opcode_name : opcode_names) {
                        opcodetype opcode = GetOpcodeFromName(opcode_name);
                        SELECTED_OPCODES.insert(opcode);
                    }
                }
            } catch (const std::invalid_argument& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                std::cerr << "Available opcodes: OP_ROLL, OP_SHA256, OP_ADD, OP_MUL, etc." << std::endl;
                exit(1);
            }
        } else if (arg == "--silent") {
            SILENT_MODE = true;
        } else if (arg == "--file" && i + 1 < argc) {
            OUTPUT_FILE = argv[++i];
            if (!SILENT_MODE) {
                std::cout << "Results will be saved to: " << OUTPUT_FILE << std::endl;
            }
        } else if (arg == "--epochs" && i + 1 < argc) {
            try {
                Timing::EPOCHS = std::stoi(argv[++i]);
                if (Timing::EPOCHS <= 0) throw std::invalid_argument("Epochs must be positive");
                if (!SILENT_MODE) {
                    std::cout << "Setting epochs to: " << Timing::EPOCHS << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing epochs: " << e.what() << std::endl;
                exit(1);
            }
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n"
                      << "Options:\n"
                      << "  --opcodes <op1> [op2] ...  Run benchmarks for specific opcodes\n"
                      << "  --epochs <number>          Set number of benchmark epochs\n"
                      << "  --silent                   Suppress output except for worst cases\n"
                      << "  --file <filepath>          Save all results to CSV file\n"
                      << "  --help, -h                 Show this help message\n\n"
                      << "Example opcodes: OP_ROLL, OP_SHA256, OP_ADD, OP_MUL, OP_CAT\n"
                      << "Example usage:\n"
                      << "  " << argv[0] << " --opcodes OP_ROLL OP_SHA256\n"
                      << "  " << argv[0] << " --opcodes OP_ADD OP_MUL --epochs 10\n"
                      << "  " << argv[0] << " --silent\n"
                      << "  " << argv[0] << " --file results.csv" << std::endl;
            exit(0);
        }
    }
}

// =================================
//      Main Function
// =================================

int main(int argc, char* argv[]) {
    ParseArguments(argc, argv);
    
    ankerl::nanobench::Bench bench = SetupBenchmark();
    std::vector<BenchTestCase> test_cases = CreateTestCases();

    RunAllBenchmarks(bench, test_cases);

    std::vector<BenchResult> results = CollectResults(bench, test_cases);
    PrintWorstCases(results);
    
    if (!OUTPUT_FILE.empty()) {
        SaveResultsToFile(results, OUTPUT_FILE);
    }
}
