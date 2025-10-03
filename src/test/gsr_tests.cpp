// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <test/util/json.h>
#include <test/data/gsr_tests.json.h>
#include <test/data/op_multi_tests.json.h>
#include <test/data/varops_tests.json.h>
#include <test/util/script.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/random.h>
#include <util/vector.h>
#include <univalue.h>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <ranges>
#include <stdexcept>


BOOST_FIXTURE_TEST_SUITE(gsr_tests, BasicTestingSetup)

static void PrintStackComparison(const std::string& test_name, 
                                const std::vector<std::vector<unsigned char>>& actual_stack,
                                const std::vector<std::vector<unsigned char>>& expected_stack)
{
    std::cerr << "Test '" << test_name << "' failed final stack check. Final stack:\n";
    for (size_t i = 0; i < std::max(actual_stack.size(), expected_stack.size()); ++i) {
        std::cerr << "  [" << i << "] ";
        if (i < expected_stack.size()) {
            std::cerr << "Expected: ";
            std::ranges::for_each(expected_stack[i], 
                [](auto c) { std::cerr << std::hex << +c << " "; });
        } else {
            std::cerr << "Expected: No element";
        }

        std::cerr << ", ";

        if (i < actual_stack.size()) {
            std::cerr << "Actual: ";
            std::ranges::for_each(actual_stack[i], 
                [](auto c) { std::cerr << std::hex << +c << " "; });
        } else {
            std::cerr << "Actual: No element";
        }
        std::cerr << std::dec << '\n';
    }
}

static std::vector<unsigned char> ParseHex(const std::string& hex)
{
    std::vector<unsigned char> result;
    if (hex.empty()) {
        return result;
    }
    
    result.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); ) {
        // Check for expansion notation {n}
        if (i < hex.length() && hex[i] == '{') {
            // Find the closing brace
            size_t close_brace = hex.find('}', i);
            if (close_brace == std::string::npos) {
                throw std::invalid_argument("Unclosed brace in hex string");
            }
            
            std::string count_str = hex.substr(i + 1, close_brace - i - 1);
            uint64_t repeat_count = std::stoull(count_str) - 1;
            
            if (result.empty()) {
                throw std::invalid_argument("No previous byte to repeat");
            }
            unsigned char prev_byte = result.back();
            
            for (uint64_t j = 0; j < repeat_count; ++j) {
                result.push_back(prev_byte);
            }
            
            i = close_brace + 1;
        } else {
            // Normal hex byte parsing
            if (i + 1 >= hex.length()) {
                throw std::invalid_argument("Incomplete hex byte");
            }
            result.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
            i += 2;
        }
    }
    return result;
}

static void RunJsonTests(const UniValue& tests, const std::string& suite_name, bool check_varops_budget = false)
{
    for (const UniValue& category_val : tests.getValues()) {
        std::string category_name = category_val["category"].get_str();
        
        for (const UniValue& test : category_val["tests"].getValues()) {
            std::string test_name = test["name"].get_str();
            std::string full_test_name = suite_name + "::" + test_name;
            
            try {

            CScript script;
            for (const UniValue& opcode_hex : test["opcodes"].getValues()) {
                try {
                    std::string hex_str = opcode_hex.get_str();
                    auto parsed_opcodes = ParseHex(hex_str);
                    script.insert(script.end(), parsed_opcodes.cbegin(), parsed_opcodes.cend());
                } catch (const std::exception& e) {
                    std::cerr << "Failed parsing opcode hex '" << opcode_hex.get_str() << "' in test '" << full_test_name << "': " << e.what() << std::endl;
                    throw;
                }
            }

            std::vector<std::vector<unsigned char>> initial_stack;
            if (test.exists("initial stack")) {
                const std::vector<UniValue>& stack_items = test["initial stack"].getValues();
                initial_stack.reserve(stack_items.size());
                for (const auto& item : stack_items) {
                    try {
                        initial_stack.push_back(ParseHex(item.get_str()));
                    } catch (const std::exception& e) {
                        std::cerr << "Failed parsing initial stack item '" << item.get_str() << "' in test '" << full_test_name << "': " << e.what() << std::endl;
                        throw;
                    }
                }
            }

            bool expected_success = test["success"].get_bool();

            std::vector<std::vector<unsigned char>> expected_final_stack;
            uint64_t expected_varops_budget_consumed = 0;

            if (expected_success) {
                if (test.exists("final stack")) {
                    const auto& final_stack_items = test["final stack"].getValues();
                    expected_final_stack.reserve(final_stack_items.size());
                    for (const auto& item : final_stack_items) {
                        try {
                            expected_final_stack.push_back(ParseHex(item.get_str()));
                        } catch (const std::exception& e) {
                            std::cerr << "Failed parsing final stack item '" << item.get_str() << "' in test '" << full_test_name << "': " << e.what() << std::endl;
                            throw;
                        }
                    }
                }
                if (test.exists("varops cost")) {
                    expected_varops_budget_consumed = test["varops cost"].getInt<uint64_t>();
                }
            }

            std::vector<std::vector<unsigned char>> stack = initial_stack;
            ScriptExecutionData sdata;
            ScriptError serror = SCRIPT_ERR_OK;
            BaseSignatureChecker checker;

            constexpr uint64_t budget = 100'000'000;
            uint64_t varops_budget = budget;

            bool success = EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget);

            BOOST_CHECK_MESSAGE(success == expected_success, "Test '" << full_test_name << "' failed success check.");
            
            if (expected_success) {
                if (stack != expected_final_stack) {
                    PrintStackComparison(full_test_name, stack, expected_final_stack);
                }
                BOOST_CHECK_MESSAGE(stack == expected_final_stack, "Test '" << full_test_name << "' failed final stack check.");
                if (check_varops_budget) {
                    uint64_t budget_consumed = budget - varops_budget;
                    BOOST_CHECK_MESSAGE(budget_consumed == expected_varops_budget_consumed, "Test '" << full_test_name << "' failed varops cost check. budget_consumed: " << budget_consumed << ", Expected: " << expected_varops_budget_consumed);
                }
            }
            
            } catch (const std::exception& e) {
                std::cerr << "Exception in test '" << full_test_name << "' (category: '" << category_name << "'): " << e.what() << std::endl;
                throw;
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(varops_json_tests)
{
    UniValue varops_tests = read_json(json_tests::varops_tests);
    RunJsonTests(varops_tests, "varops_tests", true);
}

BOOST_AUTO_TEST_CASE(gsr_json_tests)
{
    UniValue gsr_tests = read_json(json_tests::gsr_tests);
    RunJsonTests(gsr_tests, "gsr_tests", true);
}

BOOST_AUTO_TEST_CASE(op_multi_json_tests)
{
    UniValue op_multi_tests = read_json(json_tests::op_multi_tests);
    RunJsonTests(op_multi_tests, "op_multi_tests", true);
}


BOOST_AUTO_TEST_SUITE_END()
