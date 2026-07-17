// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/util/setup_common.h>

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

static void CheckAccounting(const ValtypeStack& stack, size_t total_size, size_t max_element_size)
{
    BOOST_CHECK_EQUAL(stack.get_total_size(), total_size);
    BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_element_size);
}

BOOST_FIXTURE_TEST_SUITE(valtype_stack_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valtype_stack_mutation_accounting)
{
    ValtypeStack stack;
    const valtype ten_bytes(10, 0x11);

    stack.push_back(ten_bytes);
    stack.push_back(valtype(20, 0x22));
    stack.push_back(valtype(30, 0x33));
    CheckAccounting(stack, 60, 30);

    stack.erase(1);
    CheckAccounting(stack, 40, 30);

    const valtype popped{stack.pop_back_valtype()};
    BOOST_CHECK(popped == valtype(30, 0x33));
    CheckAccounting(stack, 10, 30);

    stack.push_back(valtype(50, 0x44));
    CheckAccounting(stack, 60, 50);
    stack.pop_back();
    CheckAccounting(stack, 10, 50);

    stack.push_back(valtype{0x01, 0x02});
    Val64 value;
    BOOST_REQUIRE(stack.pop64(value));
    BOOST_CHECK(value.move_to_valtype() == valtype({0x01, 0x02}));
    CheckAccounting(stack, 10, 50);

    stack.pop_back();
    CheckAccounting(stack, 0, 50);
}

BOOST_AUTO_TEST_CASE(valtype_stack_const_copy_word_capacity)
{
    constexpr size_t WORD_BYTES{sizeof(uint64_t)};
    for (size_t size : {size_t{0}, size_t{1}, size_t{7}, size_t{8}, size_t{9}, size_t{15}, size_t{16}}) {
        const valtype original(size, 0x11);
        const size_t expected_capacity{size + (WORD_BYTES - size % WORD_BYTES) % WORD_BYTES};
        ValtypeStack stack;

        stack.push_back(original);
        BOOST_CHECK(stack.back() == original);
        BOOST_CHECK_EQUAL(stack.back().size(), size);
        BOOST_CHECK_GE(stack.back().capacity(), expected_capacity);
        CheckAccounting(stack, size, size);

        Val64 value;
        BOOST_REQUIRE(stack.pop64(value));
        BOOST_CHECK(value.move_to_valtype() == original);
        CheckAccounting(stack, 0, size);
    }
}

BOOST_AUTO_TEST_CASE(valtype_stack_erase_boundaries)
{
    ValtypeStack stack{std::vector<valtype>{
        valtype(10, 0xaa),
        valtype(20, 0xbb),
        valtype(30, 0xcc),
    }};
    CheckAccounting(stack, 60, 30);

    stack.erase(2);
    CheckAccounting(stack, 30, 30);
    stack.erase(0);
    CheckAccounting(stack, 20, 30);
    stack.erase(0);
    CheckAccounting(stack, 0, 30);
}

BOOST_AUTO_TEST_CASE(valtype_stack_empty_elements_and_failures)
{
    ValtypeStack stack;
    stack.push_back(valtype{});
    CheckAccounting(stack, 0, 0);
    stack.push_back(valtype(1, 0x42));
    CheckAccounting(stack, 1, 1);
    stack.push_back(valtype(50, 0x43));
    CheckAccounting(stack, 51, 50);
    stack.push_back(valtype{});
    CheckAccounting(stack, 51, 50);

    stack.erase(2);
    CheckAccounting(stack, 1, 50);

    ValtypeStack empty;
    Val64 value;
    BOOST_CHECK(!empty.pop64(value));
    BOOST_CHECK_THROW(empty.pop_back(), std::runtime_error);
    BOOST_CHECK_THROW(empty.pop_back_valtype(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(valtype_stack_copy_and_move_preserve_accounting)
{
    ValtypeStack original{std::vector<valtype>{
        valtype(25, 0x11),
        valtype(75, 0x22),
        valtype(125, 0x33),
    }};
    CheckAccounting(original, 225, 125);

    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization) -- exercises copy construction.
    const ValtypeStack copied{original};
    CheckAccounting(copied, 225, 125);

    ValtypeStack copy_assigned;
    copy_assigned = original;
    CheckAccounting(copy_assigned, 225, 125);

    ValtypeStack move_source{original};
    ValtypeStack moved{std::move(move_source)};
    CheckAccounting(moved, 225, 125);
    // NOLINTBEGIN(bugprone-use-after-move) -- moved-from stacks are specified to be empty and reusable.
    BOOST_CHECK(move_source.empty());
    BOOST_CHECK_EQUAL(move_source.size(), 0);
    CheckAccounting(move_source, 0, 0);
    move_source.push_back(valtype(10, 0x44));
    CheckAccounting(move_source, 10, 10);
    // NOLINTEND(bugprone-use-after-move)

    ValtypeStack move_assign_source{original};
    ValtypeStack move_assigned{std::vector<valtype>{valtype(200, 0x44)}};
    move_assigned = std::move(move_assign_source);
    CheckAccounting(move_assigned, 225, 125);
    // NOLINTBEGIN(bugprone-use-after-move) -- moved-from stacks are specified to be empty and reusable.
    BOOST_CHECK(move_assign_source.empty());
    BOOST_CHECK_EQUAL(move_assign_source.size(), 0);
    CheckAccounting(move_assign_source, 0, 0);
    move_assign_source.push_back(valtype(10, 0x55));
    CheckAccounting(move_assign_source, 10, 10);
    // NOLINTEND(bugprone-use-after-move)
}

BOOST_AUTO_TEST_CASE(valtype_stack_reordering_preserves_accounting)
{
    const std::vector<valtype> elements{
        valtype(1, 0x11),
        valtype(2, 0x22),
        valtype(3, 0x33),
    };
    const std::vector<valtype> rotated{elements[1], elements[2], elements[0]};
    const std::vector<valtype> swapped{elements[2], elements[1], elements[0]};

    ValtypeStack rotate_stack{elements};
    rotate_stack.rotate(-3, -2);
    BOOST_CHECK(rotate_stack.get_stack() == rotated);
    CheckAccounting(rotate_stack, 6, 3);

    ValtypeStack roll_stack{elements};
    roll_stack.roll(2);
    BOOST_CHECK(roll_stack.get_stack() == rotated);
    CheckAccounting(roll_stack, 6, 3);

    ValtypeStack swap_stack{elements};
    swap_stack.swap(-3, -1);
    BOOST_CHECK(swap_stack.get_stack() == swapped);
    CheckAccounting(swap_stack, 6, 3);
}

BOOST_AUTO_TEST_CASE(valtype_stack_evaluator_mutations_update_accounting)
{
    {
        Val64 first{0x123456789abcdef0ULL};
        Val64 second{0x1111111111111111ULL};
        ValtypeStack stack;
        stack.push_back(first.move_to_valtype());
        stack.push_back(second.move_to_valtype());

        BaseSignatureChecker checker;
        ScriptExecutionData execdata;
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        varops::Budget budget{1'000'000};
        CScript script;
        script << OP_ADD;

        BOOST_REQUIRE(EvalTapscriptV2(stack, script, 0, checker, execdata, budget, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1);
        CheckAccounting(stack, stack.back().size(), stack.back().size());
    }

    {
        ValtypeStack stack;
        stack.push_back(valtype{'a', 'b', 'c'});
        stack.push_back(valtype{'d', 'e', 'f'});
        CheckAccounting(stack, 6, 3);

        BaseSignatureChecker checker;
        ScriptExecutionData execdata;
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        varops::Budget budget{1'000'000};
        CScript script;
        script << OP_CAT;

        BOOST_REQUIRE(EvalTapscriptV2(stack, script, 0, checker, execdata, budget, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1);
        CheckAccounting(stack, 6, 6);
    }
}

BOOST_AUTO_TEST_SUITE_END()
