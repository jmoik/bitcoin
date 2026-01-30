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
#include <script/valtype_stack.h>

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

    // Test 1: Basic size tracking with arithmetic operations
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

        BOOST_CHECK(EvalGsrScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, varops_budget, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);

        BOOST_CHECK_EQUAL(stack.size(), 1);
        size_t result_size = stacktop(-1).size();
        BOOST_CHECK_EQUAL(stack.get_total_size(), result_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), result_size);
    }

    // Test 2: High water mark tracking (max element size never decreases)
    {
        ValtypeStack stack;

        // Add elements of different sizes
        std::vector<unsigned char> small_elem(10, 0x42);  // 10 bytes
        std::vector<unsigned char> medium_elem(50, 0x43); // 50 bytes
        std::vector<unsigned char> large_elem(100, 0x44); // 100 bytes

        stack.push_back(small_elem);
        stack.push_back(medium_elem);
        stack.push_back(large_elem);

        BOOST_CHECK_EQUAL(stack.get_total_size(), 160);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);

        // Remove the largest element - max should still be 100 (high water mark)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 60);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);

        // Remove medium element
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
    }

    // Test 3: Mixed operations (insert, erase, clear)
    {
        ValtypeStack stack;

        // Add elements of various sizes
        for (size_t i = 1; i <= 3; i++) {
            std::vector<unsigned char> elem(i * 10, static_cast<unsigned char>(0x40 + i));
            stack.push_back(elem);
        }

        BOOST_CHECK_EQUAL(stack.get_total_size(), 60);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 30);

        // Erase middle element
        stack.erase(1);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 40);

        // Insert larger element
        std::vector<unsigned char> new_elem(50, 0x99);
        stack.insert(1, new_elem);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 90);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);

        // Clear and verify
        stack.clear();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
    }

    // Test 4: OP_CAT operation with size tracking
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

        BOOST_CHECK(EvalGsrScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, varops_budget, &serror));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);

        BOOST_CHECK_EQUAL(stack.get_total_size(), 6);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 6);
    }

    // Test 5: Copy operations preserve size tracking
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
        BOOST_CHECK_EQUAL(original.get_total_size(), 225);

        // Test copy constructor
        ValtypeStack copied(original);
        BOOST_CHECK_EQUAL(copied.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(copied.get_total_size(), 225);

        // Test copy assignment
        ValtypeStack assigned;
        assigned = original;
        BOOST_CHECK_EQUAL(assigned.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(assigned.get_total_size(), 225);
    }

    // Test 6: Edge cases (empty elements and empty stack)
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
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);

        // Remove large element - high water mark stays
        stack.erase(2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
    }

    #undef stacktop
}

BOOST_AUTO_TEST_SUITE_END()
