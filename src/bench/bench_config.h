#ifndef BITCOIN_BENCH_BENCH_CONFIG_H
#define BITCOIN_BENCH_BENCH_CONFIG_H

#include <vector>
#include <string>
#include <map>
#include <cstdint>

// Configuration namespace to avoid naming conflicts
namespace BenchConfig {

// =============================================================================
// BENCHMARK EXECUTION SETTINGS
// =============================================================================

// Testing mode - set to true for quick tests, false for full benchmarks
constexpr bool TESTING = false;

// Benchmark timing configuration
namespace Timing {
    constexpr int EPOCHS = TESTING ? 1 : 5;
    constexpr int MIN_EPOCH_ITERATIONS = 1;
    constexpr int MIN_EPOCH_TIME_MS = TESTING ? 10 : 1000;
    constexpr int WARMUP = TESTING ? 0 : 1;
}

// =============================================================================
// STACK SIZE DEFINITIONS (in bytes)
// =============================================================================

namespace StackSizes {
    constexpr uint64_t ONE_B = 1;
    constexpr uint64_t TEN_B = 10;
    constexpr uint64_t HUNDRED_B = 100;
    constexpr uint64_t ONE_KB = 1000;
    constexpr uint64_t TEN_KB = 10000;
    constexpr uint64_t HUNDRED_KB = 100000;
    constexpr uint64_t ONE_MB = 1000000;
    constexpr uint64_t TWO_MB = 2000000;
    constexpr uint64_t FOUR_MB = 4000000;
}

// =============================================================================
// VALUE PATTERNS FOR STACK INITIALIZATION
// =============================================================================

enum class ValuePattern {
    STANDARD,   // First operand 1, others 2
    IDENTICAL,  // All operands with same value (1)
    ZEROS,      // All operands filled with zeros
    MAX_VALUE   // All operands filled with 0xFF
};

// =============================================================================
// STACK TEMPLATE CONFIGURATIONS
// =============================================================================

struct StackTemplate {
    std::string name;
    uint64_t size;
    int count;
    ValuePattern pattern;
};

namespace StackTemplates {
    inline std::vector<StackTemplate> getTemplates() {
        if constexpr (TESTING) {
            return {
                {"1Bx2", StackSizes::ONE_B, 2, ValuePattern::IDENTICAL},
                {"10Bx2", StackSizes::TEN_B, 2, ValuePattern::IDENTICAL},
                // {"100Bx2", StackSizes::HUNDRED_B, 2, ValuePattern::IDENTICAL},
                // {"1KBx2", StackSizes::ONE_KB, 2, ValuePattern::IDENTICAL},
                // {"10KBx2", StackSizes::TEN_KB, 2, ValuePattern::IDENTICAL},
                // {"100KBx2", StackSizes::HUNDRED_KB, 2, ValuePattern::IDENTICAL},
                // {"1MBx2", StackSizes::ONE_MB, 2, ValuePattern::IDENTICAL},
                // {"2MBx2", StackSizes::TWO_MB, 2, ValuePattern::IDENTICAL},
                // {"4MBx2", StackSizes::FOUR_MB, 2, ValuePattern::IDENTICAL},
            };
        } else {
            return {
                {"1Bx2", StackSizes::ONE_B, 2, ValuePattern::IDENTICAL},
                {"10Bx2", StackSizes::TEN_B, 2, ValuePattern::IDENTICAL},
                {"100Bx2", StackSizes::HUNDRED_B, 2, ValuePattern::IDENTICAL},
                {"1KBx2", StackSizes::ONE_KB, 2, ValuePattern::IDENTICAL},
                {"10KBx2", StackSizes::TEN_KB, 2, ValuePattern::IDENTICAL},
                {"100KBx2", StackSizes::HUNDRED_KB, 2, ValuePattern::IDENTICAL},
                {"1MBx2", StackSizes::ONE_MB, 2, ValuePattern::IDENTICAL},
                {"2MBx2", StackSizes::TWO_MB, 2, ValuePattern::IDENTICAL},
                // {"4MBx2", StackSizes::FOUR_MB, 2, ValuePattern::IDENTICAL},
                // Uncomment these for more comprehensive testing:
                // {"4MBx2", StackSizes::FOUR_MB, 2, ValuePattern::STANDARD},
                // {"4MBx2_zeros", StackSizes::FOUR_MB, 2, ValuePattern::ZEROS},
                // {"4MBx2_identical", StackSizes::FOUR_MB, 2, ValuePattern::IDENTICAL},
                // {"4MBx2_maxval", StackSizes::FOUR_MB, 2, ValuePattern::MAX_VALUE},
                // {"1MBx2_identical", StackSizes::ONE_MB, 2, ValuePattern::IDENTICAL},
                // {"1KBx2_zeros", StackSizes::ONE_KB, 2, ValuePattern::ZEROS},
            };
        }
    }
}

// =============================================================================
// SCRIPT OPERATION CONFIGURATIONS
// =============================================================================

namespace ScriptConfig {
    // Default repetitions for most operations
    constexpr int DEFAULT_REPETITIONS = 1000;
    
    // Special repetitions for specific operations
    inline std::map<std::string, int> getSpecialRepetitions() {
        return {
            {"OP_MUL", TESTING ? 1 : 5}
        };
    }
    
    // Operations to skip entirely
    inline std::vector<std::string> getSkipOperations() {
        return {
            "OP_UNKNOWN",
            "0",
            "-1",
            "OP_NEGATE",
            "OP_ABS"
        };
    }
    
    // Operations that should skip large inputs due to size limits
    inline std::map<std::string, std::vector<std::string>> getSizeLimitedOperations() {
        return {
            {"OP_LSHIFT", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},
            {"OP_RSHIFT", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},
            {"OP_SUBSTR", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},
            {"OP_MUL", {"1MBx2", "2MBx2", "4MBx2"}},  // Quadratic cost - only skip very large inputs
            {"OP_DIV", {"1MBx2", "2MBx2", "4MBx2"}},  // Quadratic cost - only skip very large inputs
            {"OP_RIPEMD160", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}},  // 520-byte limit
            {"OP_SHA1", {"1KBx2", "10KBx2", "100KBx2", "1MBx2", "2MBx2", "4MBx2"}}       // 520-byte limit
        };
    }
    
    // Helper function to check if an operation should be skipped
    inline bool shouldSkipOperation(const std::string& opname) {
        auto skip_ops = getSkipOperations();
        for (const auto& skip_op : skip_ops) {
            if (opname == skip_op) return true;
        }
        
        // Skip numeric opcodes
        if (opname.length() > 0 && std::isdigit(opname[0])) return true;
        
        return false;
    }
    
    // Helper function to get repetitions for an operation
    inline int getRepetitions(const std::string& opname) {
        auto special_reps = getSpecialRepetitions();
        auto it = special_reps.find(opname);
        return (it != special_reps.end()) ? it->second : DEFAULT_REPETITIONS;
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

namespace OutputConfig {
    constexpr const char* CSV_FILENAME = "benchmark_results.csv";
    constexpr int TABLE_WIDTH = 118;
    
    // Column widths for console output
    namespace ColumnWidths {
        constexpr int NAME = 25;
        constexpr int TIME = 10;
        constexpr int VAROPS = 14;
        constexpr int BLOCK_TIME_VAROPS = 20;
        constexpr int TIME_PER_VAROP = 10;
        constexpr int WEIGHT = 8;
        constexpr int TIME_PER_WEIGHT = 14;
        constexpr int BLOCK_WEIGHT_TIME = 20;
        constexpr int BLOCK_TIME = 14;
    }
    
    // Precision settings for different metrics
    namespace Precision {
        constexpr int TIME = 6;
        constexpr int BLOCK_TIME = 4;
        constexpr int PER_VAROP = 3;
        constexpr int PER_WEIGHT = 3;
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

} // namespace BenchConfig

#endif // BITCOIN_BENCH_BENCH_CONFIG_H 