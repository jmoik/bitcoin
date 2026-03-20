// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/val64.h>
#include <script/varops.h>
#include <common/args.h>
#include <key.h>
#include <script/valtype_stack.h>
#include <crypto/sha256.h>
#include <fstream>
#include <util/translation.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <sstream>
#include <cstdio>
#include <iostream>

const TranslateFn G_TRANSLATION_FUN{nullptr};

std::set<opcodetype> SELECTED_OPCODES;
constexpr uint64_t MAX_BLOCK_WEIGHT_UINT64 = MAX_BLOCK_WEIGHT;
constexpr uint64_t TOTAL_VAROPS_BUDGET = MAX_BLOCK_WEIGHT_UINT64 * varops::BUDGET_PER_BYTE;
bool SILENT_MODE = false;
std::string OUTPUT_FILE;

const std::set<opcodetype> GSR_ONLY_OPCODES = {
    OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT,
    OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV,
    OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT
};

namespace Timing {
    int EPOCHS = 5;
    constexpr int EPOCH_ITERATIONS = 1;
    constexpr int SCHNORR_EPOCHS = 5;
    constexpr int SCHNORR_EPOCH_ITERATIONS = 1000;
}

constexpr int SIGNATURES_PER_BLOCK = 80000;

struct StackTemplate {
    std::string name;
    uint64_t size;
    int count{2};
};

struct OpcodeSequence {
    std::vector<opcodetype> opcodes;
    int initial_elements{0};
    int max_elements{0};
    uint64_t max_element_bytes{4'000'000};
};

struct ScriptTemplate {
    std::string name;
    std::vector<opcodetype> opcodes;
    std::string sequence_name;
    std::vector<StackTemplate> stack_templates;
};

struct BenchTestCase {
    std::string name;
    ValtypeStack stack;
    CScript script;
    uint64_t varops_consumed{0};
    bool is_gsr_only{false};
    bool failed_immediately{false};
};

struct BenchResult {
    std::string name;
    double median_sec;
    uint64_t varops_consumed;
    double per_varop_ns;
    bool is_gsr_only{false};
};


static const ankerl::nanobench::Result* FindResult(const ankerl::nanobench::Bench& benches,
                                                   const std::string& name)
{
    for (auto& r : benches.results()) {
        if (r.config().mBenchmarkName == name)
            return &r;
    }
    return nullptr;
}

static ValtypeStack InitStack(uint64_t size, int count)
{
    return {std::vector<std::vector<unsigned char>>(count, std::vector<unsigned char>(size, 0xFF))};
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
    std::string name;
    for (const auto& opcode : opcodes) {
      auto opname = GetOpName(opcode);
      // remove OP_ prefix
      if (opname.starts_with("OP_")) {
        opname = opname.substr(3);
      }
      name += opname + "_";
    }
    name.pop_back();
    return name;
  }

static bool ContainsGsrOnlyOpcode(const std::vector<opcodetype>& opcodes) {
    return std::ranges::any_of(opcodes, [](opcodetype op) {
        return GSR_ONLY_OPCODES.contains(op);
    });
}

static bool IsGsrOnly(const std::vector<opcodetype>& opcodes, uint64_t stack_size) {
    return ContainsGsrOnlyOpcode(opcodes) || stack_size > MAX_SCRIPT_ELEMENT_SIZE;
}

std::vector<StackTemplate> GetStackTemplates(int initial_elements, int max_elements, uint64_t max_element_bytes) {
    static std::vector<StackTemplate> all_templates = {
        {"1Bx2",      1},
        {"2Bx2",      2},
        {"4Bx2",      4},
        {"8Bx2",      8},
        {"16Bx2",     16},
        {"32Bx2",     32},
        {"64Bx2",     64},
        {"128Bx2",    128},
        {"256Bx2",    256},
        {"520Bx2",    520},
        {"1KBx2",     1024},
        {"2KBx2",     2048},
        {"4KBx2",     4096},
        {"8KBx2",     8192},
        {"16KBx2",    16384},
        {"32KBx2",    32768},
        {"64KBx2",    65536},
        {"128KBx2",   131072},
        {"256KBx2",   262144},
        {"512KBx2",   524288},
        {"1MBx2",     1048576},
        {"1.3MBx2",   1'330'000},
        {"2MBx2",     2'000'000},
        {"2.6MBx2",   2'660'000},
        {"4MBx2",     4'000'000},
        {"100Bx16k",  100,     MAX_TAPSCRIPT_V2_STACK_SIZE/2 - 10},
        {"200Bx32k",  200,     MAX_TAPSCRIPT_V2_STACK_SIZE - 10},
    };

    std::vector<StackTemplate> result;
    for (const auto& entry : all_templates) {
        StackTemplate entry_copy = entry;
        uint64_t max_element_size = std::min(max_element_bytes, MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE / (uint64_t)max_elements);
        if (entry.size  > max_element_size) continue;
        if (initial_elements > 0 && entry.count == 2) {
            entry_copy.count = initial_elements;
        }
        result.push_back(entry_copy);
    }
    return result;
}


std::vector<OpcodeSequence> GetOpcodes(opcodetype opcode) {
    switch (opcode) {
        // (1 in -> 1 out)
        case OP_RIPEMD160:
        case OP_SHA1:
            return {
                {{opcode, OP_DROP, OP_DUP}, 2, 2, 520},
                {{OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}, 3, 6, 520},
            };

        // (1 in -> 1 out)
        case OP_2MUL:
            return {
                {{opcode, OP_DROP, OP_DUP}, 2, 2, 2'000'000},
                {{OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}, 3, 6, 2'000'000},
            };

        // (1 in -> 1 out)
        case OP_SHA256:
        case OP_HASH160:
        case OP_HASH256:
        case OP_NOT:
        case OP_ABS:
        case OP_NEGATE:
        case OP_1SUB:
        case OP_0NOTEQUAL:
        case OP_2DIV:
            return {
                {{opcode, OP_DROP, OP_DUP}, 2, 2},
                {{OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}, 3, 6},
            };

        case OP_1ADD:
            return {
                {{opcode, OP_DROP, OP_DUP}, 2, 2, 3'999'999},
                {{OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}, 3, 6, 3'999'999},
            };

        // (2 in -> 1 out)
        case OP_MUL:
        case OP_DIV:
        case OP_AND:
        case OP_OR:
        case OP_XOR:
        case OP_EQUAL:
        case OP_ADD:
        case OP_SUB:
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
        case OP_LSHIFT:
        case OP_RSHIFT:
        case OP_LEFT:
        case OP_RIGHT:
        case OP_MOD:
        case OP_CAT:
            return {{{OP_2DUP, opcode, OP_DROP}, 2, 4}};

        // (1 in -> 1 out)
        case OP_SIZE:
        case OP_DEPTH:
        case OP_DUP:
        case OP_IFDUP:
            return {{{opcode, OP_DROP}, 1, 2}};

        // (2 in -> 1 out)
        case OP_OVER:
        case OP_TUCK:
            return {{{opcode, OP_DROP}, 2, 3}};

        case OP_CHECKLOCKTIMEVERIFY:
            return {{{opcode}, 1, 1}};

        case OP_2OVER:
            return {{{opcode, OP_2DROP}, 4, 6}};

        // (1 in -> 0 out)
        case OP_ROLL:
        case OP_VERIFY:
        case OP_NIP:
            return {{{opcode, OP_DUP}, 2, 2}};

        // (2 in -> 0 out)
        case OP_EQUALVERIFY:
        case OP_NUMEQUALVERIFY:
            return {{{OP_2DUP, opcode}, 2, 4}};

        case OP_NOP:
        case OP_INVERT:
            return {{{opcode}, 1, 1}};

        case OP_SWAP:
            return {{{opcode}, 2, 2}};

        case OP_2SWAP:
            return {{{opcode}, 4, 4}};

        case OP_ROT:
            return {{{opcode}, 3, 3}};

        case OP_2ROT:
            return {{{opcode}, 6, 6}};

        case OP_PICK:
            return {{{opcode}, 1, 1}};

        // (0 in -> 2 out)
        case OP_2DUP:
            return {{{opcode, OP_2DROP}, 2, 4}};

        // (3 in -> 1 out)
        case OP_WITHIN:
        case OP_SUBSTR:
            return {{{OP_3DUP, opcode, OP_DROP}, 3, 6}};

        case OP_TOALTSTACK:
            return {{{opcode, OP_FROMALTSTACK}, 1, 1}};

        default:
            return {};
    }
}


static ankerl::nanobench::Bench SetupBenchmark() {
    ankerl::nanobench::Bench bench;
    bench.output(nullptr)
         .epochs(Timing::EPOCHS)
         .epochIterations(Timing::EPOCH_ITERATIONS);
    SHA256AutoDetect();
    return bench;
}


static std::string SizeOnly(const std::string& template_name) {
    auto pos = template_name.rfind('x');
    if (pos != std::string::npos) return template_name.substr(0, pos);
    return template_name;
}

static std::string FormatBytes(uint64_t bytes) {
    if (bytes >= 1024 * 1024 && bytes % (1024 * 1024) == 0)
        return strprintf("%uMB", bytes / (1024 * 1024));
    if (bytes >= 1024 && bytes % 1024 == 0)
        return strprintf("%uKB", bytes / 1024);
    return strprintf("%uB", bytes);
}

static bool HandleSpecialCases(const ScriptTemplate& script_template,
    const StackTemplate& stack_config,
    std::vector<BenchTestCase>& test_cases) {
    if (script_template.name.find("LEFT") != std::string::npos) {
        std::vector<opcodetype> left_sequence = {OP_2DUP, OP_LEFT, OP_DROP};
        CScript left_script = CreateScript(left_sequence);
        std::string sequence_name = GetSequenceName(left_sequence);

        std::vector<std::pair<std::string, uint64_t>> offsets;
        if (stack_config.size >= 20) {
            offsets.emplace_back("10B", 10);
        }
        if (stack_config.size >= 200) {
            offsets.emplace_back("100B", 100);
        }
        if (stack_config.size >= 2000) {
            offsets.emplace_back("1KB", 1000);
        }
        if (stack_config.size >= 20000) {
            offsets.emplace_back("10KB", 10000);
        }
        if (stack_config.size >= 200000) {
            offsets.emplace_back("100KB", 100000);
        }
        if (stack_config.size >= 2000000) {
            offsets.emplace_back("1MB", 1000000);
        }

        for (const auto& [offset_name, offset_val] : offsets) {
            auto stack = InitStack(stack_config.size, 1);
            stack.push_back(Val64(offset_val).move_to_valtype());
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_offset_" + offset_name;
            bool gsr_only = IsGsrOnly(left_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, left_script, 0, gsr_only});
        }
        return true;
    }

    if (script_template.name.find("RIGHT") != std::string::npos) {
        std::vector<opcodetype> right_sequence = {OP_2DUP, OP_RIGHT, OP_DROP};
        CScript right_script = CreateScript(right_sequence);
        std::string sequence_name = GetSequenceName(right_sequence);

        std::vector<std::pair<std::string, uint64_t>> offsets;
        if (stack_config.size >= 20) {
            offsets.emplace_back("10B", 10);
        }
        if (stack_config.size >= 200) {
            offsets.emplace_back("100B", 100);
        }
        if (stack_config.size >= 2000) {
            offsets.emplace_back("1KB", 1000);
        }
        if (stack_config.size >= 20000) {
            offsets.emplace_back("10KB", 10000);
        }
        if (stack_config.size >= 200000) {
            offsets.emplace_back("100KB", 100000);
        }
        if (stack_config.size >= 2000000) {
            offsets.emplace_back("1MB", 1000000);
        }

        for (const auto& [offset_name, offset_val] : offsets) {
            auto stack = InitStack(stack_config.size, 1);
            stack.push_back(Val64(offset_val).move_to_valtype());
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_offset_" + offset_name;
            bool gsr_only = IsGsrOnly(right_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, right_script, 0, gsr_only});
        }
        return true;
    }

    if (script_template.name.find("LSHIFT") != std::string::npos) {
        std::vector<opcodetype> lshift_sequence = {OP_2DUP, OP_LSHIFT, OP_DROP};
        CScript lshift_script = CreateScript(lshift_sequence);
        std::string sequence_name = GetSequenceName(lshift_sequence);

        std::vector<std::pair<std::string, uint64_t>> shifts;
        shifts.emplace_back("1bit", 1);
        shifts.emplace_back("8bits", 8);
        if (stack_config.size * 8 >= 64) {
            shifts.emplace_back("64bits", 64);
        }
        if (stack_config.size * 8 >= 1024) {
            shifts.emplace_back("1Kbits", 1024);
        }
        if (stack_config.size * 8 >= 10240) {
            shifts.emplace_back("10Kbits", 10240);
        }
        if (stack_config.size * 8 >= 102400) {
            shifts.emplace_back("100Kbits", 102400);
        }
        if (stack_config.size * 8 >= 1048576) {
            shifts.emplace_back("1Mbits", 1048576);
        }

        for (const auto& [shift_name, shift_val] : shifts) {
            auto stack = InitStack(stack_config.size, 1);
            stack.push_back(Val64(shift_val).move_to_valtype());
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_shift_" + shift_name;
            bool gsr_only = IsGsrOnly(lshift_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, lshift_script, 0, gsr_only});
        }
        return true;
    }

    if (script_template.name.find("RSHIFT") != std::string::npos) {
        std::vector<opcodetype> rshift_sequence = {OP_2DUP, OP_RSHIFT, OP_DROP};
        CScript rshift_script = CreateScript(rshift_sequence);
        std::string sequence_name = GetSequenceName(rshift_sequence);

        std::vector<std::pair<std::string, uint64_t>> shifts;
        shifts.emplace_back("1bit", 1);
        shifts.emplace_back("8bits", 8);
        if (stack_config.size * 8 >= 64) {
            shifts.emplace_back("64bits", 64);
        }
        if (stack_config.size * 8 >= 1024) {
            shifts.emplace_back("1Kbits", 1024);
        }
        if (stack_config.size * 8 >= 10240) {
            shifts.emplace_back("10Kbits", 10240);
        }
        if (stack_config.size * 8 >= 102400) {
            shifts.emplace_back("100Kbits", 102400);
        }
        if (stack_config.size * 8 >= 1048576) {
            shifts.emplace_back("1Mbits", 1048576);
        }

        for (const auto& [shift_name, shift_val] : shifts) {
            auto stack = InitStack(stack_config.size, 1);
            stack.push_back(Val64(shift_val).move_to_valtype());
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_shift_" + shift_name;
            bool gsr_only = IsGsrOnly(rshift_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, rshift_script, 0, gsr_only});
        }
        return true;
    }

    if (script_template.name.find("SUBSTR") != std::string::npos) {
        std::vector<opcodetype> substr_sequence = {OP_3DUP, OP_SUBSTR, OP_DROP};
        CScript substr_script = CreateScript(substr_sequence);
        std::string sequence_name = GetSequenceName(substr_sequence);

        std::vector<std::tuple<std::string, uint64_t, uint64_t>> substr_params;
        if (stack_config.size >= 20) {
            substr_params.emplace_back("start0_len10B", 0, 10);
            substr_params.emplace_back("start5B_len10B", 5, 10);
        }
        if (stack_config.size >= 200) {
            substr_params.emplace_back("start0_len100B", 0, 100);
            substr_params.emplace_back("start50B_len100B", 50, 100);
        }
        if (stack_config.size >= 2000) {
            substr_params.emplace_back("start0_len1KB", 0, 1000);
            substr_params.emplace_back("start500B_len1KB", 500, 1000);
        }
        if (stack_config.size >= 20000) {
            substr_params.emplace_back("start0_len10KB", 0, 10000);
            substr_params.emplace_back("start5KB_len10KB", 5000, 10000);
        }
        if (stack_config.size >= 200000) {
            substr_params.emplace_back("start0_len100KB", 0, 100000);
            substr_params.emplace_back("start50KB_len100KB", 50000, 100000);
        }
        if (stack_config.size >= 2000000) {
            substr_params.emplace_back("start0_len1MB", 0, 1000000);
            substr_params.emplace_back("start500KB_len1MB", 500000, 1000000);
        }

        for (const auto& [param_name, start_val, len_val] : substr_params) {
            auto stack = InitStack(stack_config.size, 1);
            stack.push_back(Val64(start_val).move_to_valtype());
            stack.push_back(Val64(len_val).move_to_valtype());
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_" + param_name;
            bool gsr_only = IsGsrOnly(substr_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, substr_script, 0, gsr_only});
        }
        return true;
    }

    if (script_template.name.find("XOR") != std::string::npos ||
        script_template.name.find("_OR_") != std::string::npos) {
        opcodetype bit_opcode = script_template.name.find("XOR") != std::string::npos ? OP_XOR : OP_OR;
        std::vector<opcodetype> bit_sequence = {OP_2DUP, bit_opcode, OP_DROP};
        CScript bit_script = CreateScript(bit_sequence);
        std::string sequence_name = GetSequenceName(bit_sequence);

        for (uint64_t s2_size : {stack_config.size / 2, stack_config.size / 4}) {
            if (s2_size == 0) continue;
            ValtypeStack stack;
            stack.push_back(std::vector<unsigned char>(stack_config.size, 0xFF));
            stack.push_back(std::vector<unsigned char>(s2_size, 0xFF));
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_" + FormatBytes(s2_size);
            bool gsr_only = IsGsrOnly(bit_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, bit_script, 0, gsr_only});
        }
        return false;
    }

    if (script_template.name.find("_MUL_") != std::string::npos) {
        std::vector<opcodetype> mul_sequence = {OP_2DUP, OP_MUL, OP_DROP};
        CScript mul_script = CreateScript(mul_sequence);
        std::string sequence_name = GetSequenceName(mul_sequence);

        for (uint64_t s2_size : {stack_config.size / 4, stack_config.size / 16, uint64_t{1}}) {
            if (s2_size == 0) continue;
            ValtypeStack stack;
            stack.push_back(std::vector<unsigned char>(stack_config.size, 0xFF));
            stack.push_back(std::vector<unsigned char>(s2_size, 0xFF));
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_" + FormatBytes(s2_size);
            bool gsr_only = IsGsrOnly(mul_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, mul_script, 0, gsr_only});
        }
        return false;
    }

    if (script_template.name.find("_DIV_") != std::string::npos ||
        script_template.name.find("_MOD_") != std::string::npos) {
        opcodetype div_opcode = script_template.name.find("_MOD_") != std::string::npos ? OP_MOD : OP_DIV;
        std::vector<opcodetype> div_sequence = {OP_2DUP, div_opcode, OP_DROP};
        CScript div_script = CreateScript(div_sequence);
        std::string sequence_name = GetSequenceName(div_sequence);

        for (uint64_t div_size : {stack_config.size / 4, stack_config.size / 16, uint64_t{1}}) {
            if (div_size == 0) continue;
            ValtypeStack stack;
            stack.push_back(std::vector<unsigned char>(stack_config.size, 0xFF));
            stack.push_back(std::vector<unsigned char>(div_size, 0xFF));
            std::string test_name = sequence_name + "_" + SizeOnly(stack_config.name) + "_divisor_" + FormatBytes(div_size);
            bool gsr_only = IsGsrOnly(div_sequence, stack_config.size);
            test_cases.push_back({test_name, stack, div_script, 0, gsr_only});
        }
        return false;
    }

    if (script_template.name.find("ROLL") != std::string::npos || script_template.name.find("PICK") != std::string::npos) {
        int maximum_size = MAX_TAPSCRIPT_V2_STACK_SIZE;
        ValtypeStack stack;
        int roll_index = MAX_TAPSCRIPT_V2_STACK_SIZE - 5;
        for (int i = 0; i < maximum_size - 1; i++) {
            stack.push_back(Val64(roll_index).move_to_valtype());
        }
        bool gsr_only = true;
        test_cases.push_back({script_template.name + "_MAX_STACK_SIZE", stack, CreateScript(script_template.opcodes), 0, gsr_only});
        return true;
    }

    return false;
}


static std::vector<ScriptTemplate> CreateScriptTemplates() {
    std::vector<ScriptTemplate> script_templates;
    for (unsigned int op = 0x4c; op <= 0xba; op++) {
        opcodetype opcode = static_cast<opcodetype>(op);
        if (!SELECTED_OPCODES.empty() && !SELECTED_OPCODES.contains(opcode)) continue;
        auto sequences = GetOpcodes(opcode);
        if (sequences.empty()) {
            std::cout << strprintf("Skipping unsupported opcode 0x%02x (%s)\n", op, GetOpName(opcode).c_str());
            continue;
        }
        for (const auto& seq : sequences) {
            std::string sequence_name = GetSequenceName(seq.opcodes);
            std::vector<StackTemplate> config_stack_templates = GetStackTemplates(seq.initial_elements, seq.max_elements, seq.max_element_bytes);
            script_templates.push_back({sequence_name, seq.opcodes, sequence_name, config_stack_templates});
        }
    }
    return script_templates;
}


static std::vector<BenchTestCase> CreateTestCases() {
    std::vector<ScriptTemplate> script_templates = CreateScriptTemplates();
    std::vector<BenchTestCase> test_cases;
    test_cases.reserve(script_templates.size());

    for (const auto& script_template : script_templates) {
        // Derive per-element size cap from max_elements (0 = no limit)
        for (auto& stack_config : script_template.stack_templates) {
            if (HandleSpecialCases(script_template, stack_config, test_cases)) {
                continue;
            }

            bool gsr_only = IsGsrOnly(script_template.opcodes, stack_config.size);
            test_cases.push_back({
                script_template.name + "_" + stack_config.name,
                InitStack(stack_config.size, stack_config.count),
                CreateScript(script_template.opcodes),
                0,
                gsr_only
            });
        }
    }

    std::sort(test_cases.begin(), test_cases.end(), [](const BenchTestCase& a, const BenchTestCase& b) { return a.name < b.name; });
    test_cases.erase(std::unique(test_cases.begin(), test_cases.end(), [](const BenchTestCase& a, const BenchTestCase& b) { return a.name == b.name; }), test_cases.end());

    return test_cases;
}

static void RunBenchmark(ankerl::nanobench::Bench& bench,
                         BenchTestCase& test_case) {
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;

    const uint64_t varops_block_budget = TOTAL_VAROPS_BUDGET;
    assert(varops_block_budget > 1e10);
    uint64_t working_budget = varops_block_budget;
    bool result = false;

    const size_t stack_pool_size = Timing::EPOCHS * Timing::EPOCH_ITERATIONS;
    size_t stack_index = 0;
    std::vector<ValtypeStack> stack_pool;
    stack_pool.reserve(stack_pool_size);
    for (size_t i = 0; i < stack_pool_size; ++i) {
        stack_pool.push_back(test_case.stack);
    }

    // warmup for every benchmark to provide more stable results, fixes OP_2DUP memory issues on intel chips
    CScript warmup_script = CreateScript(GetOpcodes(OP_NOP).front().opcodes);
    uint64_t warmup_budget = varops_block_budget;
    ScriptError warmup_error;
    ValtypeStack warmup_stack;
    EvalScript(warmup_stack, warmup_script, 0, checker,
                SigVersion::TAPSCRIPT_V2, sdata, warmup_budget, &warmup_error);


    bench.run(test_case.name, [&] {
        assert(stack_index < stack_pool_size);
        ValtypeStack& working_stack = stack_pool[stack_index];
        working_budget = varops_block_budget;
        result = EvalScript(working_stack, test_case.script, 0, checker,
                        SigVersion::TAPSCRIPT_V2, sdata, working_budget, &serror);
        ++stack_index;
    });

    if (!result) {
        std::string error_msg = ScriptErrorString(serror);
        if (error_msg.find("Varops count exceeded") == std::string::npos) {
            std::cout << strprintf("Script error: %s\n", error_msg.c_str());
        }
    }
    if (working_budget != varops_block_budget && test_case.varops_consumed == 0) {
        test_case.varops_consumed = varops_block_budget - working_budget;
    }
    if (!result && test_case.varops_consumed < TOTAL_VAROPS_BUDGET / 100) {
        std::string error_msg = ScriptErrorString(serror);
        if (error_msg.find("Varops count exceeded") != std::string::npos) {
            test_case.failed_immediately = true;
        }
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
    key.SignSchnorr(hash, vchSig, nullptr, hash);

    XOnlyPubKey xpub(pubkey);
    std::span<const unsigned char> sigbytes{vchSig.data(), vchSig.size()};
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
        std::cout << "Running Schnorr signature benchmark...\n";
    }
    RunSchnorrBenchmark(bench, "Schnorr signature validation");

    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = FindResult(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    double schnorr_block_time = schnorr_median_time * SIGNATURES_PER_BLOCK;
    if (!SILENT_MODE) {
        std::cout << strprintf("Schnorr block time: %.3f seconds\n", schnorr_block_time);
    }

    int bench_count = 0;

    for (BenchTestCase& test_case : test_cases) {
        RunBenchmark(bench, test_case);

        if (test_case.failed_immediately) continue;

        if (const auto* result = FindResult(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double schnorr_times = median_sec / schnorr_median_time;

            if (!SILENT_MODE) {
                std::cout << strprintf("%3d/%zu: %-30s %.3f seconds (%6.0f Schnorrs, %6.1f%% varops used)\n",
                       ++bench_count, test_cases.size(), test_case.name.c_str(), median_sec, schnorr_times,
                       (double(test_case.varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
            } else {
                ++bench_count;
            }
        }
    }
}

static std::vector<BenchResult> CollectResults(const ankerl::nanobench::Bench& bench, const std::vector<BenchTestCase>& test_cases) {
    std::vector<BenchResult> results;
    results.reserve(test_cases.size());

    for (const auto& test_case : test_cases) {
        if (test_case.failed_immediately) continue;
        if (const auto* result = FindResult(bench, test_case.name)) {
            double median_sec = result->median(ankerl::nanobench::Result::Measure::elapsed);
            double per_varop_ns = test_case.varops_consumed > 0 ? (median_sec * 1e9) / test_case.varops_consumed : 0;
            results.push_back({test_case.name, median_sec, test_case.varops_consumed, per_varop_ns, test_case.is_gsr_only});
        }
    }

    double schnorr_median_time = 0.0;
    if (const auto* schnorr_result = FindResult(bench, "Schnorr signature validation")) {
        schnorr_median_time = schnorr_result->median(ankerl::nanobench::Result::Measure::elapsed);
    }

    results.push_back({"Schnorr signature validation", schnorr_median_time * SIGNATURES_PER_BLOCK, 0, 0, false});
    std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) { return a.median_sec > b.median_sec; });

    return results;
}

static void PrintWorstCases(std::vector<BenchResult>& results) {
    std::sort(results.begin(), results.end(), [](const BenchResult& a, const BenchResult& b) { return a.median_sec > b.median_sec; });

    std::cout << "\n================================================================================\n";
    std::cout << "WORST-CASE COMPARISON\n";
    std::cout << "================================================================================\n";

    // Find worst existing (non-GSR) and worst GSR operations
    const BenchResult* worst_existing = nullptr;
    const BenchResult* worst_gsr = nullptr;
    const BenchResult* schnorr_result = nullptr;

    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") {
            schnorr_result = &result;
            continue;
        }
        if (!result.is_gsr_only) {
            if (!worst_existing || result.median_sec > worst_existing->median_sec) {
                worst_existing = &result;
            }
        } else {
            if (!worst_gsr || result.median_sec > worst_gsr->median_sec) {
                worst_gsr = &result;
            }
        }
    }

    // Also consider realistic Schnorr (~10K ops) as existing worst case data point
    double schnorr_15k = schnorr_result ? schnorr_result->median_sec * 10000.0 / SIGNATURES_PER_BLOCK : 0;
    double existing_worst_time = worst_existing ? worst_existing->median_sec : 0;

    // Print existing worst case
    std::cout << "\nEXISTING WORST CASE (pre-GSR):\n";
    if (worst_existing) {
        std::cout << strprintf("  %-50s %.3f sec (%5.1f%% varops)\n",
               worst_existing->name.c_str(), worst_existing->median_sec,
               (double(worst_existing->varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
    }
    if (schnorr_result) {
        std::cout << strprintf("  Schnorr signature validation (80K)        %10.3f sec\n", schnorr_result->median_sec);
        std::cout << strprintf("  Schnorr realistic (~10K, weight-limited)  %10.3f sec\n",
               schnorr_15k);
    }

    // Print GSR worst case
    std::cout << "\nGSR WORST CASE:\n";
    if (worst_gsr) {
        std::cout << strprintf("  %-50s %.3f sec (%5.1f%% varops)\n",
               worst_gsr->name.c_str(), worst_gsr->median_sec,
               (double(worst_gsr->varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
    }

    // Print ratio
    if (worst_gsr && existing_worst_time > 0) {
        double ratio = worst_gsr->median_sec / existing_worst_time;
        std::cout << strprintf("\n  RATIO (GSR worst / existing worst): %.3f\n", ratio);
    }

    // Print top 10 slowest GSR ops
    std::cout << "\nTOP 10 SLOWEST GSR OPERATIONS:\n\n";
    int gsr_count = 0;
    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") continue;
        if (!result.is_gsr_only) continue;
        std::cout << strprintf("%2d. %-50s %.3f sec  (%5.1f%% varops)\n",
               ++gsr_count, result.name.c_str(), result.median_sec,
               (double(result.varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
        if (gsr_count >= 10) break;
    }

    // Print top 5 slowest existing ops
    std::cout << "\nTOP 5 SLOWEST EXISTING OPERATIONS:\n\n";
    int existing_count = 0;
    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") continue;
        if (result.is_gsr_only) continue;
        std::cout << strprintf("%2d. %-50s %.3f sec  (%5.1f%% varops)\n",
               ++existing_count, result.name.c_str(), result.median_sec,
               (double(result.varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
        if (existing_count >= 5) break;
    }

    std::cout << "================================================================================\n";
}

static std::string GetSystemInfo() {
    std::ostringstream info;

    std::string cpu_name = "Unknown";
#if defined(__APPLE__)
    FILE* fp = popen("sysctl -n machdep.cpu.brand_string", "r");
    if (fp) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            cpu_name = buffer;
            // Remove trailing newline
            if (!cpu_name.empty() && cpu_name.back() == '\n') {
                cpu_name.pop_back();
            }
        }
        pclose(fp);
    }
#elif defined(__linux__)
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "model name", 10) == 0) {
                const char* sep = strchr(line, ':');
                if (sep) {
                    cpu_name = sep + 2; // Skip ": "
                    // Remove trailing newline
                    if (!cpu_name.empty() && cpu_name.back() == '\n') {
                        cpu_name.pop_back();
                    }
                    break;
                }
            }
        }
        fclose(cpuinfo);
    }
#endif

    // Get architecture
    std::string architecture = "Unknown";
#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    architecture = "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
    architecture = "x86";
#elif defined(__aarch64__) || defined(_M_ARM64)
    architecture = "ARM64";
#elif defined(__arm__) || defined(_M_ARM)
    architecture = "ARM";
#endif

    // Get compiler
    std::string compiler = "Unknown";
#if defined(__clang__)
    compiler = "Clang " + util::ToString(__clang_major__) + "." +
               util::ToString(__clang_minor__) + "." +
               util::ToString(__clang_patchlevel__);
#elif defined(__GNUC__)
    compiler = "GCC " + util::ToString(__GNUC__) + "." +
               util::ToString(__GNUC_MINOR__) + "." +
               util::ToString(__GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    compiler = "MSVC " + util::ToString(_MSC_VER);
#endif

    // Get SHA256 implementation
    std::string sha256_impl = SHA256AutoDetect();

    info << "# CPU: " << cpu_name << "\n";
    info << "# Architecture: " << architecture << "\n";
    info << "# Compiler: " << compiler << "\n";
    info << "# SHA256 Implementation: " << sha256_impl << "\n";

    return info.str();
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

    file << GetSystemInfo();
    file << "#\n";

    double slowest_100_percent_time = 0.0;
    for (const auto& result : results) {
        if (result.name != "Schnorr signature validation" &&
            result.varops_consumed >= TOTAL_VAROPS_BUDGET * 0.99) {
            if (result.median_sec > slowest_100_percent_time) {
                slowest_100_percent_time = result.median_sec;
            }
        }
    }

    if (slowest_100_percent_time > 0 && schnorr_median_time > 0) {
        double suggested_budget = varops::BUDGET_PER_BYTE / slowest_100_percent_time * schnorr_median_time;
        file << "# SUGGESTED MAXIMUM VAROPS BUDGET:\n";
        file << "# Based on slowest 100% varops operation (" << slowest_100_percent_time
             << " sec) vs Schnorr (" << schnorr_median_time << " sec):\n";
        file << "# Suggested budget: " << suggested_budget
             << " varops per weight unit (current: " << varops::BUDGET_PER_BYTE << ")\n";
        file << "# Formula: " << varops::BUDGET_PER_BYTE << " / " << slowest_100_percent_time
             << " * " << schnorr_median_time << " = " << suggested_budget << "\n";
        file << "#\n";
    }

    // Worst-case comparison
    const BenchResult* worst_existing = nullptr;
    const BenchResult* worst_gsr = nullptr;
    const BenchResult* schnorr_result_ptr = nullptr;
    for (const auto& result : results) {
        if (result.name == "Schnorr signature validation") { schnorr_result_ptr = &result; continue; }
        if (!result.is_gsr_only) {
            if (!worst_existing || result.median_sec > worst_existing->median_sec) worst_existing = &result;
        } else {
            if (!worst_gsr || result.median_sec > worst_gsr->median_sec) worst_gsr = &result;
        }
    }
    file << "# WORST-CASE COMPARISON:\n";
    if (worst_existing) {
        file << strprintf("# Worst existing (pre-GSR): %s  %.3f sec  (%.1f%% varops)\n",
            worst_existing->name.c_str(), worst_existing->median_sec,
            (double(worst_existing->varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
    }
    if (schnorr_result_ptr) {
        double schnorr_15k = schnorr_result_ptr->median_sec * 10000.0 / SIGNATURES_PER_BLOCK;
        file << strprintf("# Schnorr (80K sigs):       %.3f sec\n", schnorr_result_ptr->median_sec);
        file << strprintf("# Schnorr realistic (~10K): %.3f sec\n", schnorr_15k);
    }
    if (worst_gsr) {
        file << strprintf("# Worst GSR:                %s  %.3f sec  (%.1f%% varops)\n",
            worst_gsr->name.c_str(), worst_gsr->median_sec,
            (double(worst_gsr->varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0);
    }
    if (worst_gsr && worst_existing && worst_existing->median_sec > 0) {
        file << strprintf("# Ratio (GSR worst / existing worst): %.3f\n",
            worst_gsr->median_sec / worst_existing->median_sec);
    }
    file << "#\n";

    file << "Rank,Name,Seconds,Schnorr_Equivalents,Varops_Percentage,Is_GSR_Only\n";

    for (size_t i = 0; i < results.size(); i++) {
        double schnorr_times = schnorr_median_time > 0 ? results[i].median_sec / schnorr_median_time * SIGNATURES_PER_BLOCK : 0;
        double varops_percentage = (double(results[i].varops_consumed) / TOTAL_VAROPS_BUDGET) * 100.0;

        file << (i + 1) << ","
             << results[i].name << ","
             << results[i].median_sec << ","
             << schnorr_times << ","
             << varops_percentage << ","
             << (results[i].is_gsr_only ? "true" : "false") << "\n";
    }

    file.close();
    if (!SILENT_MODE) {
        std::cout << "Results saved to: " << filepath << std::endl;
    }
}

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

    if (opcode_map.contains(upper_name)) return opcode_map[upper_name];
    if (opcode_map.contains("OP_" + upper_name)) return opcode_map["OP_" + upper_name];

    throw std::invalid_argument("Unknown opcode name: " + name);
}

static void ParseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--opcodes") {
            i++;
            std::vector<std::string> opcode_names;
            while (i < argc && argv[i][0] != '-') {
                opcode_names.emplace_back(argv[i++]);
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
                auto epochs = ToIntegral<int>(argv[++i]);
                if (!epochs || *epochs <= 0) throw std::invalid_argument("Epochs must be positive");
                Timing::EPOCHS = *epochs;
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
        } else {
            std::cerr << "Error: unknown option '" << arg << "'" << std::endl;
            std::cerr << "Run with --help for usage information." << std::endl;
            exit(1);
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

    if (!OUTPUT_FILE.empty()) {
        SaveResultsToFile(results, OUTPUT_FILE);
    }
}
