// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <test/util/json.h>
#include <test/data/varops_tests.json.h>
#include <test/util/script.h>

#include <script/interpreter.h>
#include <script/script.h>
#include <script/varops.h>

#include <test/util/random.h>
#include <util/vector.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <ranges>


BOOST_FIXTURE_TEST_SUITE(varops_tests, BasicTestingSetup)

static std::vector<unsigned char> ParseHex(const std::string& hex)
{
    std::vector<unsigned char> result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        result.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return result;
}

BOOST_AUTO_TEST_CASE(varops_json_tests)
{
    UniValue tests = read_json(json_tests::varops_tests);

    for (const UniValue& category_val : tests.getValues()) {
        std::string category_name = category_val["category"].get_str();
        
        for (const UniValue& test : category_val["tests"].getValues()) {
            std::string test_name = test["name"].get_str();

            CScript script;
            for (const UniValue& opcode_hex : test["opcodes"].getValues()) {
                if (const auto parsed_opcodes = ParseHex(opcode_hex.get_str()); !parsed_opcodes.empty()) {
                    script.insert(script.end(), parsed_opcodes.cbegin(), parsed_opcodes.cend());
                }
            }

            std::vector<std::vector<unsigned char>> initial_stack;
            if (test.exists("initial stack")) {
                const std::vector<UniValue>& stack_items = test["initial stack"].getValues();
                initial_stack.reserve(stack_items.size());
                std::ranges::transform(stack_items, std::back_inserter(initial_stack),
                    [](const auto& item) { return ParseHex(item.get_str()); });
            }

            bool expected_success = test["success"].get_bool();

            std::vector<std::vector<unsigned char>> expected_final_stack;
            uint64_t expected_varops_consumed = 0;

            if (expected_success) {
                if (test.exists("final stack")) {
                    const auto& final_stack_items = test["final stack"].getValues();
                    expected_final_stack.reserve(final_stack_items.size());
                    std::ranges::transform(final_stack_items, std::back_inserter(expected_final_stack),
                        [](const auto& item) { return ParseHex(item.get_str()); });
                }
                if (test.exists("varops cost")) {
                    expected_varops_consumed = test["varops cost"].getInt<uint64_t>();
                }
            }

            std::vector<std::vector<unsigned char>> stack = initial_stack;
            ScriptExecutionData sdata;
            ScriptError serror = SCRIPT_ERR_OK;
            BaseSignatureChecker checker;

            constexpr uint64_t budget = 10'000'000;
            auto varops_budget = std::make_shared<uint64_t>(budget);
            uint64_t initial_budget = *varops_budget;

            bool success = EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT, sdata, &serror, varops_budget);

            BOOST_CHECK_MESSAGE(success == expected_success, "Test '" << test_name << "' failed success check.");
            
            if (expected_success) {
                    if (stack != expected_final_stack) {
                        // Print stack deviation on failure
                        std::cerr << "Test '" << test_name << "' failed final stack check. Final stack:\n";
                        const size_t max_size = std::max(stack.size(), expected_final_stack.size());
                        for (size_t i = 0; i < max_size; ++i) {
                            std::cerr << "  [" << i << "] ";
                            if (i < expected_final_stack.size()) {
                                std::cerr << "Expected: ";
                                std::ranges::for_each(expected_final_stack[i], 
                                    [](unsigned char c) { std::cerr << std::hex << static_cast<int>(c) << " "; });
                            } else {
                                std::cerr << "Expected: No element";
                            }

                            std::cerr << ", ";

                            if (i < stack.size()) {
                                std::cerr << "Actual: ";
                                std::ranges::for_each(stack[i], 
                                    [](unsigned char c) { std::cerr << std::hex << static_cast<int>(c) << " "; });
                            } else {
                                std::cerr << "Actual: No element";
                            }
                            std::cerr << std::dec << '\n';
                        }
                    }
                BOOST_CHECK_MESSAGE(stack == expected_final_stack, "Test '" << test_name << "' failed final stack check.");
                uint64_t consumed = initial_budget - *varops_budget;
                BOOST_CHECK_MESSAGE(consumed == expected_varops_consumed, "Test '" << test_name << "' failed varops cost check. Consumed: " << consumed << ", Expected: " << expected_varops_consumed);
            }
        }
    }
}


BOOST_AUTO_TEST_SUITE_END() 