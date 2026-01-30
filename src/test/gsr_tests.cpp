// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <test/util/json.h>
#include <test/data/gsr_tests.json.h>
#include <test/data/varops_tests.json.h>
#include <test/util/script.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/random.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>
#include <univalue.h>
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <ranges>
#include <stdexcept>
#include <script/valtype_stack.h>

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

static opcodetype GetOpCode(const std::string& name)
{
    // Handle numeric opcodes
    if (name == "0") return OP_0;
    if (name == "-1") return OP_1NEGATE;
    for (int i = 1; i <= 16; ++i) {
        if (name == util::ToString(i)) return static_cast<opcodetype>(OP_1 + i - 1);
    }

    // Handle named opcodes
    if (name == "OP_PUSHDATA1") return OP_PUSHDATA1;
    if (name == "OP_PUSHDATA2") return OP_PUSHDATA2;
    if (name == "OP_PUSHDATA4") return OP_PUSHDATA4;
    if (name == "OP_RESERVED") return OP_RESERVED;
    if (name == "OP_NOP") return OP_NOP;
    if (name == "OP_VER") return OP_VER;
    if (name == "OP_IF") return OP_IF;
    if (name == "OP_NOTIF") return OP_NOTIF;
    if (name == "OP_VERIF") return OP_VERIF;
    if (name == "OP_VERNOTIF") return OP_VERNOTIF;
    if (name == "OP_ELSE") return OP_ELSE;
    if (name == "OP_ENDIF") return OP_ENDIF;
    if (name == "OP_VERIFY") return OP_VERIFY;
    if (name == "OP_RETURN") return OP_RETURN;
    if (name == "OP_TOALTSTACK") return OP_TOALTSTACK;
    if (name == "OP_FROMALTSTACK") return OP_FROMALTSTACK;
    if (name == "OP_2DROP") return OP_2DROP;
    if (name == "OP_2DUP") return OP_2DUP;
    if (name == "OP_3DUP") return OP_3DUP;
    if (name == "OP_2OVER") return OP_2OVER;
    if (name == "OP_2ROT") return OP_2ROT;
    if (name == "OP_2SWAP") return OP_2SWAP;
    if (name == "OP_IFDUP") return OP_IFDUP;
    if (name == "OP_DEPTH") return OP_DEPTH;
    if (name == "OP_DROP") return OP_DROP;
    if (name == "OP_DUP") return OP_DUP;
    if (name == "OP_NIP") return OP_NIP;
    if (name == "OP_OVER") return OP_OVER;
    if (name == "OP_PICK") return OP_PICK;
    if (name == "OP_ROLL") return OP_ROLL;
    if (name == "OP_ROT") return OP_ROT;
    if (name == "OP_SWAP") return OP_SWAP;
    if (name == "OP_TUCK") return OP_TUCK;
    if (name == "OP_CAT") return OP_CAT;
    if (name == "OP_SUBSTR") return OP_SUBSTR;
    if (name == "OP_LEFT") return OP_LEFT;
    if (name == "OP_RIGHT") return OP_RIGHT;
    if (name == "OP_SIZE") return OP_SIZE;
    if (name == "OP_INVERT") return OP_INVERT;
    if (name == "OP_AND") return OP_AND;
    if (name == "OP_OR") return OP_OR;
    if (name == "OP_XOR") return OP_XOR;
    if (name == "OP_EQUAL") return OP_EQUAL;
    if (name == "OP_EQUALVERIFY") return OP_EQUALVERIFY;
    if (name == "OP_RESERVED1") return OP_RESERVED1;
    if (name == "OP_RESERVED2") return OP_RESERVED2;
    if (name == "OP_1ADD") return OP_1ADD;
    if (name == "OP_1SUB") return OP_1SUB;
    if (name == "OP_2MUL") return OP_2MUL;
    if (name == "OP_2DIV") return OP_2DIV;
    if (name == "OP_NEGATE") return OP_NEGATE;
    if (name == "OP_ABS") return OP_ABS;
    if (name == "OP_NOT") return OP_NOT;
    if (name == "OP_0NOTEQUAL") return OP_0NOTEQUAL;
    if (name == "OP_ADD") return OP_ADD;
    if (name == "OP_SUB") return OP_SUB;
    if (name == "OP_MUL") return OP_MUL;
    if (name == "OP_DIV") return OP_DIV;
    if (name == "OP_MOD") return OP_MOD;
    if (name == "OP_LSHIFT") return OP_LSHIFT;
    if (name == "OP_RSHIFT") return OP_RSHIFT;
    if (name == "OP_BOOLAND") return OP_BOOLAND;
    if (name == "OP_BOOLOR") return OP_BOOLOR;
    if (name == "OP_NUMEQUAL") return OP_NUMEQUAL;
    if (name == "OP_NUMEQUALVERIFY") return OP_NUMEQUALVERIFY;
    if (name == "OP_NUMNOTEQUAL") return OP_NUMNOTEQUAL;
    if (name == "OP_LESSTHAN") return OP_LESSTHAN;
    if (name == "OP_GREATERTHAN") return OP_GREATERTHAN;
    if (name == "OP_LESSTHANOREQUAL") return OP_LESSTHANOREQUAL;
    if (name == "OP_GREATERTHANOREQUAL") return OP_GREATERTHANOREQUAL;
    if (name == "OP_MIN") return OP_MIN;
    if (name == "OP_MAX") return OP_MAX;
    if (name == "OP_WITHIN") return OP_WITHIN;
    if (name == "OP_RIPEMD160") return OP_RIPEMD160;
    if (name == "OP_SHA1") return OP_SHA1;
    if (name == "OP_SHA256") return OP_SHA256;
    if (name == "OP_HASH160") return OP_HASH160;
    if (name == "OP_HASH256") return OP_HASH256;
    if (name == "OP_CODESEPARATOR") return OP_CODESEPARATOR;
    if (name == "OP_CHECKSIG") return OP_CHECKSIG;
    if (name == "OP_CHECKSIGVERIFY") return OP_CHECKSIGVERIFY;
    if (name == "OP_CHECKMULTISIG") return OP_CHECKMULTISIG;
    if (name == "OP_CHECKMULTISIGVERIFY") return OP_CHECKMULTISIGVERIFY;
    if (name == "OP_NOP1") return OP_NOP1;
    if (name == "OP_CHECKLOCKTIMEVERIFY") return OP_CHECKLOCKTIMEVERIFY;
    if (name == "OP_CHECKSEQUENCEVERIFY") return OP_CHECKSEQUENCEVERIFY;
    if (name == "OP_NOP4") return OP_NOP4;
    if (name == "OP_NOP5") return OP_NOP5;
    if (name == "OP_NOP6") return OP_NOP6;
    if (name == "OP_NOP7") return OP_NOP7;
    if (name == "OP_NOP8") return OP_NOP8;
    if (name == "OP_NOP9") return OP_NOP9;
    if (name == "OP_NOP10") return OP_NOP10;
    if (name == "OP_CHECKSIGADD") return OP_CHECKSIGADD;
    if (name == "OP_INVALIDOPCODE") return OP_INVALIDOPCODE;

    throw std::invalid_argument("Unknown opcode name: " + name);
}

static std::vector<unsigned char> ParseHexOrOpcode(const std::string& input)
{
    // Try to parse as opcode name first
    try {
        opcodetype opcode = GetOpCode(input);
        return {static_cast<unsigned char>(opcode)};
    } catch (const std::exception&) {
        // If opcode parsing fails, try to parse as hex
    }

    // Fall back to hex parsing
    return ParseHex(input);
}

static std::vector<unsigned char> ParseHex(const std::string& hex)
{
    std::vector<unsigned char> result;
    if (hex.empty()) {
        return result;
    }

    // Strip "0x" prefix if present
    std::string hex_data = hex;
    if (hex_data.length() >= 2 && hex_data[0] == '0' && (hex_data[1] == 'x' || hex_data[1] == 'X')) {
        hex_data = hex_data.substr(2);
    }

    // Empty string after stripping prefix means empty byte vector
    if (hex_data.empty()) {
        return result;
    }

    result.reserve(hex_data.length() / 2);

    for (size_t i = 0; i < hex_data.length(); ) {
        // Check for expansion notation {n}
        if (i < hex_data.length() && hex_data[i] == '{') {
            // Find the closing brace
            size_t close_brace = hex_data.find('}', i);
            if (close_brace == std::string::npos) {
                throw std::invalid_argument("Unclosed brace in hex string");
            }

            std::string count_str = hex_data.substr(i + 1, close_brace - i - 1);
            auto repeat_count_opt = ToIntegral<uint64_t>(count_str);
            if (!repeat_count_opt) {
                throw std::invalid_argument("Invalid repeat count");
            }
            uint64_t repeat_count = *repeat_count_opt - 1;

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
            if (i + 1 >= hex_data.length()) {
                throw std::invalid_argument("Incomplete hex byte");
            }
            unsigned char byte_val = 0;
            auto [ptr, ec] = std::from_chars(hex_data.data() + i, hex_data.data() + i + 2, byte_val, 16);
            if (ec != std::errc{}) {
                throw std::invalid_argument("Invalid hex byte");
            }
            result.push_back(byte_val);
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
            for (const UniValue& opcode_input : test["opcodes"].getValues()) {
                try {
                    const std::string& input_str = opcode_input.get_str();
                    auto parsed_opcodes = ParseHexOrOpcode(input_str);
                    script.insert(script.end(), parsed_opcodes.cbegin(), parsed_opcodes.cend());
                } catch (const std::exception& e) {
                    std::cerr << "Failed parsing opcode '" << opcode_input.get_str() << "' in test '" << full_test_name << "': " << e.what() << std::endl;
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
            ValtypeStack valtype_stack{stack};
            bool success = EvalGsrScript(valtype_stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, varops_budget, &serror);

            BOOST_CHECK_MESSAGE(success == expected_success, "Test '" << full_test_name << "' failed success check.");

            stack = valtype_stack.get_stack();
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

BOOST_AUTO_TEST_SUITE_END()
