// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/valtype_stack.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

static void CheckAccounting(const ValtypeStack& stack, size_t total_size, size_t max_element_size)
{
    BOOST_CHECK_EQUAL(stack.GetTotalSize(), total_size);
    BOOST_CHECK_EQUAL(stack.GetMaxElementSize(), max_element_size);
}

/** Whether padding value to whole words keeps its buffer. Compares buffer
 *  addresses rather than checking capacity(), which _GLIBCXX_DEBUG_PEDANTIC
 *  reports as the size after a move. */
static bool HasWordPadding(valtype&& value)
{
    const unsigned char* const data{value.data()};
    value.resize(WordPaddedCapacity(value.size()));
    return value.data() == data;
}

BOOST_FIXTURE_TEST_SUITE(valtype_stack_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(valtype_stack_mutation_accounting)
{
    ValtypeStack stack;
    const valtype ten_bytes(10, 0x11);

    stack.push_back(ten_bytes);
    stack.push_back(valtype{});
    stack.push_back(valtype(20, 0x22));
    stack.push_back(valtype(30, 0x33));
    CheckAccounting(stack, 60, 30);
    BOOST_CHECK(stack.Top() == valtype(30, 0x33));
    BOOST_CHECK(stack.Top(3) == ten_bytes);

    stack.Erase(1);
    CheckAccounting(stack, 40, 30);
    BOOST_CHECK(stack.Top(1).empty());

    BOOST_CHECK(stack.PopValue() == valtype(30, 0x33));
    CheckAccounting(stack, 10, 30);

    stack.push_back(valtype(50, 0x44));
    CheckAccounting(stack, 60, 50);
    stack.pop_back();
    CheckAccounting(stack, 10, 50);
    stack.pop_back();
    CheckAccounting(stack, 10, 50);
    stack.pop_back();
    CheckAccounting(stack, 0, 50);
    BOOST_CHECK_EQUAL(stack.size(), 0U);
}

BOOST_AUTO_TEST_CASE(valtype_stack_copies_have_word_padding)
{
    std::vector<valtype> values;
    for (size_t size{0}; size <= 17; ++size) values.emplace_back(size, 0x11);
    // Initial values are copies too.
    ValtypeStack stack{values};
    for (const valtype& value : values) stack.push_back(value);

    for (size_t i{2 * values.size()}; i > 0; --i) {
        BOOST_CHECK(stack.Top() == values[(i - 1) % values.size()]);
        BOOST_CHECK(HasWordPadding(stack.PopValue()));
    }
}

BOOST_AUTO_TEST_CASE(valtype_stack_move_bounds_retained_capacity)
{
    for (size_t size : {size_t{0}, size_t{1}, size_t{8}, size_t{9}, size_t{4096}}) {
        for (size_t capacity : {size, 2 * size + 8, 2 * size + 16, 4 * size + 64, size_t{1} << 20}) {
            const size_t word_span{WordPaddedCapacity(size)};
            valtype element(size, 0x5a);
            element.reserve(capacity);
            const size_t moved_capacity{element.capacity()};
            const unsigned char* const moved_data{element.data()};
            ValtypeStack stack;
            stack.push_back(std::move(element));
            BOOST_CHECK(stack.Top() == valtype(size, 0x5a));
            BOOST_CHECK_LE(stack.Top().capacity(), 2 * word_span);
            // Values within the bound keep their buffer unless it lacks padding room.
            const bool keeps_buffer{moved_capacity >= word_span && moved_capacity <= 2 * word_span};
            BOOST_CHECK_EQUAL(stack.Top().data() == moved_data, keeps_buffer);
            CheckAccounting(stack, size, size);
            BOOST_CHECK(HasWordPadding(stack.PopValue()));
        }
    }
}

BOOST_AUTO_TEST_CASE(valtype_stack_push_copy_of_own_value)
{
    // The copy is made before the stack grows, which moves its values.
    const valtype bottom(33, 0x5a);
    ValtypeStack stack;
    stack.push_back(bottom);
    stack.push_back(valtype{0x01});
    size_t reallocations{0};
    for (size_t i{0}; i < 100; ++i) {
        const size_t capacity{stack.GetStack().capacity()};
        stack.push_back(stack.Top(stack.size() - 1));
        reallocations += stack.GetStack().capacity() != capacity;
        BOOST_CHECK(stack.Top() == bottom);
    }
    BOOST_CHECK_GT(reallocations, 0U);
    CheckAccounting(stack, 101 * bottom.size() + 1, bottom.size());
}

BOOST_AUTO_TEST_CASE(valtype_stack_reordering_by_depth)
{
    std::vector<valtype> values;
    for (size_t size{1}; size <= 5; ++size) values.emplace_back(size, static_cast<unsigned char>(size));
    const auto at_depth{[&](std::vector<valtype>& stack, size_t depth) { return stack.end() - 1 - depth; }};

    for (size_t depth{0}; depth < values.size(); ++depth) {
        BOOST_CHECK(ValtypeStack{values}.Top(depth) == values[values.size() - 1 - depth]);

        std::vector<valtype> expected;
        for (size_t count{0}; count <= depth + 1; ++count) {
            ValtypeStack rolled{values};
            expected = values;
            std::rotate(at_depth(expected, depth), at_depth(expected, depth) + count, expected.end());
            rolled.Roll(depth, count);
            BOOST_CHECK(rolled.GetStack() == expected);
            CheckAccounting(rolled, 15, 5);
        }

        for (size_t other{0}; other < values.size(); ++other) {
            ValtypeStack swapped{values};
            expected = values;
            std::iter_swap(at_depth(expected, depth), at_depth(expected, other));
            swapped.Swap(depth, other);
            BOOST_CHECK(swapped.GetStack() == expected);
            CheckAccounting(swapped, 15, 5);
        }

        ValtypeStack erased{values};
        expected = values;
        const size_t erased_size{at_depth(expected, depth)->size()};
        expected.erase(at_depth(expected, depth));
        erased.Erase(depth);
        BOOST_CHECK(erased.GetStack() == expected);
        CheckAccounting(erased, 15 - erased_size, 5);
    }
}

BOOST_AUTO_TEST_CASE(valtype_stack_missing_values_throw)
{
    ValtypeStack empty;
    BOOST_CHECK_THROW(empty.Top(), std::out_of_range);
    BOOST_CHECK_THROW(empty.pop_back(), std::out_of_range);
    BOOST_CHECK_THROW(empty.PopValue(), std::out_of_range);
    BOOST_CHECK_THROW(empty.Erase(0), std::out_of_range);
    BOOST_CHECK_THROW(empty.Roll(0), std::out_of_range);
    BOOST_CHECK_THROW(empty.Swap(0, 0), std::out_of_range);

    const std::vector<valtype> values{valtype(1, 0x11), valtype(2, 0x22)};
    ValtypeStack stack{values};
    BOOST_CHECK_THROW(stack.Top(2), std::out_of_range);
    BOOST_CHECK_THROW(stack.Top(SIZE_MAX), std::out_of_range);
    BOOST_CHECK_THROW(stack.Erase(2), std::out_of_range);
    BOOST_CHECK_THROW(stack.Roll(2), std::out_of_range);
    BOOST_CHECK_THROW(stack.Roll(1, 3), std::out_of_range);
    BOOST_CHECK_THROW(stack.Swap(0, 2), std::out_of_range);
    BOOST_CHECK_THROW(stack.Swap(2, 0), std::out_of_range);
    // A failed operation leaves the stack unchanged.
    BOOST_CHECK(stack.GetStack() == values);
    CheckAccounting(stack, 3, 2);
}

BOOST_AUTO_TEST_CASE(valtype_stack_move_preserves_accounting)
{
    const std::vector<valtype> elements{
        valtype(25, 0x11),
        valtype(75, 0x22),
        valtype(125, 0x33),
    };

    ValtypeStack move_source{elements};
    ValtypeStack moved{std::move(move_source)};
    CheckAccounting(moved, 225, 125);
    // NOLINTBEGIN(bugprone-use-after-move) -- moved-from stacks are specified to be empty and reusable.
    BOOST_CHECK_EQUAL(move_source.size(), 0);
    CheckAccounting(move_source, 0, 0);
    move_source.push_back(valtype(10, 0x44));
    CheckAccounting(move_source, 10, 10);
    // NOLINTEND(bugprone-use-after-move)

    ValtypeStack move_assign_source{elements};
    ValtypeStack move_assigned{std::vector<valtype>{valtype(200, 0x44)}};
    move_assigned = std::move(move_assign_source);
    CheckAccounting(move_assigned, 225, 125);
    // NOLINTBEGIN(bugprone-use-after-move) -- moved-from stacks are specified to be empty and reusable.
    BOOST_CHECK_EQUAL(move_assign_source.size(), 0);
    CheckAccounting(move_assign_source, 0, 0);
    move_assign_source.push_back(valtype(10, 0x55));
    CheckAccounting(move_assign_source, 10, 10);
    // NOLINTEND(bugprone-use-after-move)
}

BOOST_AUTO_TEST_SUITE_END()
