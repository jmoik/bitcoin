#include <bench/bench_config.h>
#include <iostream>
#include <iomanip>

using namespace std;
using namespace BenchConfig;

int main() {
    cout << "=== Benchmark Configuration Test ===" << endl;
    
    // Test basic configuration
    cout << "Testing mode: " << (TESTING ? "true" : "false") << endl;
    cout << "Epochs: " << Timing::EPOCHS << endl;
    cout << "Min epoch time (ms): " << Timing::MIN_EPOCH_TIME_MS << endl;
    cout << "Warmup: " << Timing::WARMUP << endl;
    
    // Test stack sizes
    cout << "\n=== Stack Sizes ===" << endl;
    cout << "ONE_B: " << StackSizes::ONE_B << endl;
    cout << "ONE_KB: " << StackSizes::ONE_KB << endl;
    cout << "ONE_MB: " << StackSizes::ONE_MB << endl;
    cout << "FOUR_MB: " << StackSizes::FOUR_MB << endl;
    
    // Test stack templates
    cout << "\n=== Stack Templates ===" << endl;
    auto templates = StackTemplates::getTemplates();
    for (const auto& tmpl : templates) {
        cout << "Template: " << tmpl.name 
             << ", Size: " << tmpl.size 
             << ", Count: " << tmpl.count 
             << ", Pattern: " << static_cast<int>(tmpl.pattern) << endl;
    }
    
    // Test script configuration
    cout << "\n=== Script Configuration ===" << endl;
    cout << "Default repetitions: " << ScriptConfig::DEFAULT_REPETITIONS << endl;
    
    auto special_reps = ScriptConfig::getSpecialRepetitions();
    cout << "Special repetitions:" << endl;
    for (const auto& pair : special_reps) {
        cout << "  " << pair.first << ": " << pair.second << endl;
    }
    
    auto skip_ops = ScriptConfig::getSkipOperations();
    cout << "Skip operations: ";
    for (const auto& op : skip_ops) {
        cout << op << " ";
    }
    cout << endl;
    
    // Test helper functions
    cout << "\n=== Helper Functions ===" << endl;
    cout << "Should skip OP_UNKNOWN: " << ScriptConfig::shouldSkipOperation("OP_UNKNOWN") << endl;
    cout << "Should skip OP_ADD: " << ScriptConfig::shouldSkipOperation("OP_ADD") << endl;
    cout << "Repetitions for OP_MUL: " << ScriptConfig::getRepetitions("OP_MUL") << endl;
    cout << "Repetitions for OP_ADD: " << ScriptConfig::getRepetitions("OP_ADD") << endl;
    cout << "Should skip large input for OP_LSHIFT with 1KBx2: " 
         << ScriptConfig::shouldSkipLargeInput("OP_LSHIFT", "1KBx2") << endl;
    cout << "Should skip large input for OP_ADD with 1KBx2: " 
         << ScriptConfig::shouldSkipLargeInput("OP_ADD", "1KBx2") << endl;
    
    // Test output configuration
    cout << "\n=== Output Configuration ===" << endl;
    cout << "CSV filename: " << OutputConfig::CSV_FILENAME << endl;
    cout << "Table width: " << OutputConfig::TABLE_WIDTH << endl;
    cout << "Name column width: " << OutputConfig::ColumnWidths::NAME << endl;
    cout << "Time precision: " << OutputConfig::Precision::TIME << endl;
    
    // Test Schnorr configuration
    cout << "\n=== Schnorr Configuration ===" << endl;
    cout << "Signatures per block: " << SchnorrConfig::SIGNATURES_PER_BLOCK << endl;
    auto test_key = SchnorrConfig::getTestKey();
    cout << "Test key size: " << test_key.size() << " bytes" << endl;
    cout << "Test key (first 8 bytes): ";
    for (size_t i = 0; i < min(size_t(8), test_key.size()); i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(test_key[i]) << " ";
    }
    cout << dec << endl;
    
    cout << "\n=== Configuration Test Complete ===" << endl;
    return 0;
} 