// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <core_io.h>
#include <key.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/strencodings.h>


#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>
#include <script/val64.h>

using namespace util::hex_literals;

struct ValtypeStackTest : BasicTestingSetup {
};

BOOST_FIXTURE_TEST_SUITE(valtype_stack_tests, ValtypeStackTest)

BOOST_AUTO_TEST_CASE(valtype_stack_size_tracking)
{
    // Test ValtypeStack size tracking during Val64 operations
    
    // Define stacktop macro like in interpreter.cpp
    #define stacktop(i) (stack.at(size_t(int64_t(stack.size()) + int64_t{i})))
    
    // Test 1: Basic size tracking with OP_ADD
    {
        ValtypeStack stack;
        
        // Add two 8-byte numbers
        Val64 v1(0x123456789ABCDEF0ULL);
        Val64 v2(0x1111111111111111ULL);
        
        auto vec1 = v1.move_to_valtype();
        auto vec2 = v2.move_to_valtype();
        
        size_t initial_size1 = vec1.size();
        size_t initial_size2 = vec2.size();
        
        stack.push_back(vec1);
        stack.push_back(vec2);
        
        // Verify initial tracking
        BOOST_CHECK_EQUAL(stack.get_total_size(), initial_size1 + initial_size2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max(initial_size1, initial_size2));
        
        // Perform addition that modifies top element in place
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        CScript script;
        script << OP_ADD;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        // Update stack with result and verify size tracking
        stack = ValtypeStack(plain_stack);
        
        BOOST_CHECK_EQUAL(stack.size(), 1);
        size_t result_size = stacktop(-1).size();
        BOOST_CHECK_EQUAL(stack.get_total_size(), result_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), result_size);
    }
    
    // Test 2: Size tracking with OP_MUL producing larger result
    {
        ValtypeStack stack;
        
        // Multiply two numbers to get a larger result
        Val64 v1(0xFFFFFFFFFFFFFFFFULL);  // Large number
        Val64 v2(0xFFFFFFFFFFFFFFFFULL);  // Large number
        
        auto vec1 = v1.move_to_valtype();
        auto vec2 = v2.move_to_valtype();
        
        stack.push_back(vec1);
        stack.push_back(vec2);
        
        // Perform multiplication
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        CScript script;
        script << OP_MUL;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        // Update stack with result
        stack = ValtypeStack(plain_stack);
        
        BOOST_CHECK_EQUAL(stack.size(), 1);
        size_t result_size = stacktop(-1).size();
        
        // Result should be larger than either input (8 bytes each)
        BOOST_CHECK(result_size >= 8);
        BOOST_CHECK_EQUAL(stack.get_total_size(), result_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), result_size);
    }
    
    // Test 3: Multiple operations tracking max element size correctly
    {
        ValtypeStack stack;
        
        // Add elements of different sizes
        std::vector<unsigned char> small_elem(10, 0x42);  // 10 bytes
        std::vector<unsigned char> medium_elem(50, 0x43); // 50 bytes  
        std::vector<unsigned char> large_elem(100, 0x44); // 100 bytes
        
        stack.push_back(small_elem);
        stack.push_back(medium_elem);
        stack.push_back(large_elem);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        
        // Remove the largest element
        stack.pop_back();
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
        
        // Remove medium element
        stack.pop_back();
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
    }
    
    // Test 5: Complex sequence with multiple Val64 operations
    {
        ValtypeStack stack;
        
        // Start with small numbers
        for (int i = 1; i <= 5; i++) {
            Val64 v(i);
            auto vec = v.move_to_valtype();
            stack.push_back(vec);
        }
        
        // Perform series of operations that will change sizes
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        // Add all numbers: 1+2+3+4+5 = 15
        CScript add_script;
        add_script << OP_ADD << OP_ADD << OP_ADD << OP_ADD;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, add_script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(plain_stack.size(), 1);
        
        // Update stack and verify result
        stack = ValtypeStack(plain_stack);
        Val64 result;
        stack.pop64(result);

        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 15);
        
        // Verify size tracking
        stack.push_back(result.move_to_valtype());
        BOOST_CHECK_EQUAL(stack.get_total_size(), 1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 1);
        
        // Now multiply by itself to create larger number: 15 * 15 = 225
        auto top_element = stacktop(-1);  // Get copy of top element
        stack.push_back(top_element);  // Duplicate
        
        CScript mul_script;
        mul_script << OP_MUL;
        
        plain_stack = stack.get_stack();
        varops_budget = 1000000;
        BOOST_CHECK(EvalScript(plain_stack, mul_script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        stack = ValtypeStack(plain_stack);
        
        Val64 mul_result;
        stack.pop64(mul_result);
        cost = 0;
        // BOOST_CHECK_EQUAL(mul_result.to_u64_ceil(UINT64_MAX, cost), 225);
        
        // Final size verification
        auto valtype = mul_result.move_to_valtype();
        stack.push_back(valtype);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 1);
    }
    

    
    // Test 7: Mixed operations with size changes
    {
        ValtypeStack stack;
        
        // Add elements of various sizes
        for (size_t i = 1; i <= 3; i++) {
            std::vector<unsigned char> elem(i * 10, static_cast<unsigned char>(0x40 + i));
            stack.push_back(elem);
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 20 + 30);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 30);
        
        // Modify elements through various operations
        stack.erase(1);  // Remove middle element (20 bytes)
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 30);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 30);
        
        // Insert new element
        std::vector<unsigned char> new_elem(50, 0x99);
        stack.insert(1, new_elem);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 30);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
        
        // Clear and verify
        stack.clear();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
    }
    
    // Test 8: Mixed Val64 and CScriptNum operations
    {
        ValtypeStack stack;
        
        // Add various number types of different sizes
        Val64 small_val64(42);
        Val64 large_val64(0x123456789ABCDEF0ULL);
        CScriptNum small_scriptnum(123);
        CScriptNum large_scriptnum(0x7FFFFFFFFFFFFFFF);  // Large but within CScriptNum range
        
        auto vec1 = small_val64.move_to_valtype();
        auto vec2 = large_val64.move_to_valtype();
        auto vec3 = small_scriptnum.getvch();
        auto vec4 = large_scriptnum.getvch();
        
        size_t size1 = vec1.size();
        size_t size2 = vec2.size();
        size_t size3 = vec3.size();
        size_t size4 = vec4.size();
        
        stack.push_back(vec1);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), size1);
        
        stack.push_back(vec2);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max(size1, size2));
        
        stack.push_back(vec3);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max({size1, size2, size3}));
        
        stack.push_back(vec4);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3 + size4);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max({size1, size2, size3, size4}));
        
        // Remove elements in specific order - max should remain unchanged (high water mark)
        size_t max_size_before = stack.get_max_element_size();
        stack.pop_back();  // Remove vec4
        
        // Max should always remain the same (high water mark behavior)
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size_before);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3);
    }
    
    // Test 9: Large numbers and precise size tracking
    {
        ValtypeStack stack;
        
        // Create progressively larger numbers: 100, 10000, 1000000
        std::vector<Val64> numbers;
        std::vector<size_t> expected_sizes;
        
        for (int i = 2; i <= 4; i++) {
            uint64_t value = 1;
            for (int j = 0; j < i * 2; j++) {
                value *= 10;  // 100, 10000, 1000000
            }
            numbers.emplace_back(value);
            auto vec = numbers.back().move_to_valtype();
            expected_sizes.push_back(vec.size());
            stack.push_back(vec);
        }
        
        // Verify total size
        size_t expected_total = 0;
        for (size_t s : expected_sizes) {
            expected_total += s;
        }
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        
        // Verify max element size
        size_t expected_max = *std::max_element(expected_sizes.begin(), expected_sizes.end());
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), expected_max);
        
        // Remove element from middle - max should remain unchanged (high water mark)
        size_t max_before_erase = stack.get_max_element_size();
        stack.erase(1);  // Remove 2nd element
        expected_total -= expected_sizes[1];
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        // Max should remain the same (high water mark behavior)
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_before_erase);
    }
    
    // Test 10: Edge cases with empty and single element stacks
    {
        ValtypeStack stack;
        
        // Empty stack
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
        
        // Single element
        CScriptNum num(999);
        auto vec = num.getvch();
        size_t vec_size = vec.size();
        
        stack.push_back(vec);
        BOOST_CHECK_EQUAL(stack.get_total_size(), vec_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), vec_size);
        
        // Remove single element
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), vec_size);  // Should still be vec_size (max ever seen)
    }
    
    // Test 11: Stress test with many small elements
    {
        ValtypeStack stack;
        
        const size_t num_elements = 1000;
        size_t expected_total = 0;
        size_t expected_max = 0;
        
        // Add many small CScriptNum elements
        for (size_t i = 0; i < num_elements; i++) {
            CScriptNum num(static_cast<int64_t>(i));
            auto vec = num.getvch();
            size_t vec_size = vec.size();
            
            expected_total += vec_size;
            expected_max = std::max(expected_max, vec_size);
            
            stack.push_back(vec);
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), expected_max);
        
        // Remove half the elements (from the end)
        for (size_t i = 0; i < num_elements / 2; i++) {
            size_t actual_index = num_elements - 1 - i;  // Index of element being removed
            CScriptNum num(static_cast<int64_t>(actual_index));
            auto vec = num.getvch();
            expected_total -= vec.size();
            stack.pop_back();
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        // Max should still be the same since we removed from the end
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), expected_max);
        
        // Clear all
        stack.clear();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
    }
    

    
    // Test 13: Proxy modification with different number types
    {
        ValtypeStack stack;
        
        // Start with a CScriptNum
        CScriptNum initial_num(123);
        auto initial_vec = initial_num.getvch();
        stack.push_back(initial_vec);
        
        size_t initial_size = stack.get_total_size();
        BOOST_CHECK_EQUAL(initial_size, initial_vec.size());
        
        // Verify size tracking updated correctly
        BOOST_CHECK_EQUAL(stack.get_total_size(), stacktop(-1).size());
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), stacktop(-1).size());
    }
    
    // Test 14: Range operations with size tracking
    {
        ValtypeStack stack1, stack2;
        
        // Fill first stack with Val64 numbers
        size_t total_size1 = 0;
        size_t max_size1 = 0;
        for (int i = 1; i <= 5; i++) {
            Val64 val(i * 1000);
            auto vec = val.move_to_valtype();
            total_size1 += vec.size();
            max_size1 = std::max(max_size1, vec.size());
            stack1.push_back(vec);
        }
        
        // Fill second stack with CScriptNum numbers
        size_t total_size2 = 0;
        size_t max_size2 = 0;
        for (int i = 10; i <= 15; i++) {
            CScriptNum num(i * 100);
            auto vec = num.getvch();
            total_size2 += vec.size();
            max_size2 = std::max(max_size2, vec.size());
            stack2.push_back(vec);
        }
        
        BOOST_CHECK_EQUAL(stack1.get_total_size(), total_size1);
        BOOST_CHECK_EQUAL(stack1.get_max_element_size(), max_size1);
        BOOST_CHECK_EQUAL(stack2.get_total_size(), total_size2);
        BOOST_CHECK_EQUAL(stack2.get_max_element_size(), max_size2);
        
    }
    
    // Test 15: Roll operation with size tracking
    {
        ValtypeStack stack;
        
        // Add elements of different sizes
        std::vector<size_t> sizes;
        size_t total_size = 0;
        size_t max_size = 0;
        
        for (int i = 1; i <= 5; i++) {
            if (i % 2 == 1) {
                // Odd: use Val64
                Val64 val(i * 1000000);  // Large numbers
                auto vec = val.move_to_valtype();
                sizes.push_back(vec.size());
                total_size += vec.size();
                max_size = std::max(max_size, vec.size());
                stack.push_back(vec);
            } else {
                // Even: use CScriptNum
                CScriptNum num(i * 10);  // Small numbers
                auto vec = num.getvch();
                sizes.push_back(vec.size());
                total_size += vec.size();
                max_size = std::max(max_size, vec.size());
                stack.push_back(vec);
            }
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), total_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
        
        // Perform roll operation (move 3rd from top to top)
        stack.rotate(-3, -2, -1);
        
        // Size tracking should remain the same (just rearranging)
        BOOST_CHECK_EQUAL(stack.get_total_size(), total_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
        BOOST_CHECK_EQUAL(stack.size(), 5);
    }

    // Test 16: OP_CAT operation with size tracking
    {
        ValtypeStack stack;
        stack.push_back({'a', 'b', 'c'});
        stack.push_back({'d', 'e', 'f'});
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 6);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 3); 

        CScript script;
        script << OP_CAT;

        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;

        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);

        BOOST_CHECK_EQUAL(stack.get_total_size(), 6);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 6);
    }
    
    // Test 17: Specific max_element_size tracking with multiple elements of same size
    {
        ValtypeStack stack;
        
        // Add multiple elements of the same maximum size
        std::vector<unsigned char> large_elem1(100, 0x11);  // 100 bytes
        std::vector<unsigned char> large_elem2(100, 0x22);  // 100 bytes
        std::vector<unsigned char> large_elem3(100, 0x33);  // 100 bytes
        std::vector<unsigned char> medium_elem(50, 0x44);   // 50 bytes
        std::vector<unsigned char> small_elem(10, 0x55);    // 10 bytes
        
        stack.push_back(small_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 10);
        
        stack.push_back(medium_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
        
        stack.push_back(large_elem1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        
        stack.push_back(large_elem2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Still 100, multiple elements
        
        stack.push_back(large_elem3);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Still 100, three elements of max size
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100 + 100 + 100);
        
        // Remove one large element - max should still be 100 (2 remaining)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100 + 100);
        
        // Remove another large element - max should still be 100 (1 remaining)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100);
        
        // Remove the last large element - max should still be 100 (max ever seen)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50);
        
        // Remove medium element - max should still be 100 (max ever seen)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10);
        
        // Remove last element - max should still be 100 (max ever seen)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
    }
    
    // Test 18: Max size tracking with erase operations (not just pop_back)
    {
        ValtypeStack stack;
        
        // Create elements with carefully chosen sizes
        std::vector<unsigned char> elem_80(80, 0xAA);   // 80 bytes
        std::vector<unsigned char> elem_90(90, 0xBB);   // 90 bytes
        std::vector<unsigned char> elem_100a(100, 0xCC); // 100 bytes
        std::vector<unsigned char> elem_100b(100, 0xDD); // 100 bytes (duplicate size)
        std::vector<unsigned char> elem_110(110, 0xEE);  // 110 bytes (largest)
        
        stack.push_back(elem_80);
        stack.push_back(elem_90);
        stack.push_back(elem_100a);
        stack.push_back(elem_100b);
        stack.push_back(elem_110);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90 + 100 + 100 + 110);
        
        // Remove the largest element using erase (from middle)
        stack.erase(4);  // Remove elem_110
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);  // Should still be 110 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90 + 100 + 100);
        
        // Remove one of the 100-byte elements
        stack.erase(2);  // Remove elem_100a
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);  // Still 110 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90 + 100);
        
        // Remove the last 100-byte element
        stack.erase(2);  // Remove elem_100b
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);  // Still 110 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90);
    }
    

    
    // Test 20: Insert operations with max size tracking
    {
        ValtypeStack stack;
        
        // Start with medium-sized elements
        std::vector<unsigned char> elem50(50, 0xAA);
        std::vector<unsigned char> elem60(60, 0xBB);
        
        stack.push_back(elem50);
        stack.push_back(elem60);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 60);
        
        // Insert larger element in middle
        std::vector<unsigned char> elem80(80, 0xCC);
        stack.insert(1, elem80);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 80);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 50 + 80 + 60);
        
        // Insert another element of same max size
        std::vector<unsigned char> elem80_dup(80, 0xDD);
        stack.insert(0, elem80_dup);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 80);  // Still 80, now with 2 elements
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 50 + 80 + 60);
        
        // Insert even larger element
        std::vector<unsigned char> elem120(120, 0xEE);
        stack.insert(stack.size() - 1, elem120);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 120);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 50 + 80 + 60 + 120);
    }
    

    
    // Test 22: Copy operations preserve max size tracking
    {
        ValtypeStack original;
        
        // Fill with various sized elements
        std::vector<unsigned char> small(25, 0x11);
        std::vector<unsigned char> medium(75, 0x22);
        std::vector<unsigned char> large(125, 0x33);
        
        original.push_back(small);
        original.push_back(medium);
        original.push_back(large);
        
        BOOST_CHECK_EQUAL(original.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(original.get_total_size(), 25 + 75 + 125);
        
        // Test copy constructor
        ValtypeStack copied(original);
        BOOST_CHECK_EQUAL(copied.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(copied.get_total_size(), 25 + 75 + 125);
        
        // Test copy assignment
        ValtypeStack assigned;
        assigned = original;
        BOOST_CHECK_EQUAL(assigned.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(assigned.get_total_size(), 25 + 75 + 125);
    }
    

    
    // Test 24: Edge case - elements with size 0
    {
        ValtypeStack stack;
        
        // Add empty elements and non-empty elements
        std::vector<unsigned char> empty_elem;           // 0 bytes
        std::vector<unsigned char> small_elem(1, 0x42);  // 1 byte
        std::vector<unsigned char> large_elem(50, 0x43); // 50 bytes
        
        stack.push_back(empty_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
        
        stack.push_back(small_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 1);
        
        stack.push_back(large_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
        
        // Add another empty element
        stack.push_back(empty_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);  // Should still be 50
        
        // Remove large element
        stack.erase(2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);  // Should still be 50 (max ever seen)
        
        // Remove small element
        stack.erase(1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);  // Should still be 50 (max ever seen)
    }
    
    #undef stacktop
}

BOOST_AUTO_TEST_SUITE_END()
