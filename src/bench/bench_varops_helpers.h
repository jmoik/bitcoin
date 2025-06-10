// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BENCH_BENCH_VAROPS_HELPERS_H
#define BITCOIN_BENCH_BENCH_VAROPS_HELPERS_H

#include <bench/nanobench.h>
#include <bench/bench_config.h>

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

#include <cassert>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <limits>

// Use configuration constants from config file
using namespace BenchConfig;
using namespace std;

#define BLOCK_VAROPS uint64_t(StackSizes::FOUR_MB * VAROPS_BUDGET_PER_BYTE) // 4MB * 520 varops per byte

// Helper function to find a result by name
static const ankerl::nanobench::Result* find_result(const ankerl::nanobench::Bench& benches,
                                                   const std::string& name)
{
    for (auto& r : benches.results()) {
        if (r.config().mBenchmarkName == name)
            return &r;
    }
    return nullptr;
}

// Struct for benchmark test cases
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

// Centralized stack initialization function with parameters
static std::vector<std::vector<unsigned char>> init_stack(
    uint64_t size = StackSizes::ONE_MB,     // Size of each operand
    int count = 2,                          // Number of operands
    ValuePattern pattern = ValuePattern::STANDARD  // Pattern for values
) {
    std::vector<std::vector<unsigned char>> stack;
    
    uint8_t value1, value2;
    
    // Set values based on pattern
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

static CScript create_script(const std::vector<opcodetype>& opcodes, int repetitions = ScriptConfig::DEFAULT_REPETITIONS) {
    CScript script;
    for (int i = 0; i < repetitions; i++) {
        for (const auto& opcode : opcodes) {
            script << opcode;
        }
    }
    return script;
}

static void run_benchmark(ankerl::nanobench::Bench& bench, 
                         BenchTestCase& test_case) {
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;

    // uint64_t* varops_budget = new uint64_t(uint64_t(StackSizes::FOUR_MB) * VAROPS_BUDGET_PER_BYTE * 1e6);
    uint64_t* varops_budget = new uint64_t(BLOCK_VAROPS * 1e6);
    uint64_t initial_budget = *varops_budget;

    bench.run(test_case.name, [&] {
        std::vector<std::vector<unsigned char> > stack = test_case.stack;
        if (!EvalScript(stack, test_case.script, 0, checker,
                        SigVersion::TAPSCRIPT_V2, sdata, &serror, varops_budget)) {
            std::cerr << "EvalScript error " << ScriptErrorString(serror) << std::endl;
            assert(false);
        }
        if (*varops_budget != initial_budget && test_case.varops_consumed == 0) {
            test_case.varops_consumed = initial_budget - *varops_budget;
        }
    });
}

#endif // BITCOIN_BENCH_BENCH_VAROPS_HELPERS_H 