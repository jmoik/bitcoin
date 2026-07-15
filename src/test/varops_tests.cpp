// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/varops.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <limits>
#include <thread>
#include <utility>
#include <vector>

BOOST_AUTO_TEST_SUITE(varops_tests)

BOOST_AUTO_TEST_CASE(compositional_integer_accounting)
{
    // Spending more than once deducts only newly added whole-varop costs.
    varops::Meter meter;
    varops::Budget budget{3};
    meter.Add(1);
    BOOST_CHECK(meter.Spend(budget));
    BOOST_CHECK(meter.Spend(budget));
    BOOST_CHECK_EQUAL(budget.Remaining(), 2);
    meter.Add(2);
    BOOST_CHECK(meter.Spend(budget));
    BOOST_CHECK_EQUAL(budget.Remaining(), 0);
    meter.Add(1);
    BOOST_CHECK(!meter.Spend(budget));
    BOOST_CHECK_EQUAL(budget.Remaining(), 0);

    // An opcode that prepaid does not deduct again when it ends; what it adds
    // afterwards is deducted with the next opcode's charges.
    varops::Meter opcodes;
    varops::Budget opcode_budget{10};
    opcodes.Add(3);
    BOOST_CHECK(opcodes.Prepay(opcode_budget));
    opcodes.Add(2);
    BOOST_CHECK(opcodes.EndOpcode(opcode_budget));
    BOOST_CHECK_EQUAL(opcode_budget.Remaining(), 7);
    opcodes.Add(1);
    BOOST_CHECK(opcodes.EndOpcode(opcode_budget));
    BOOST_CHECK_EQUAL(opcode_budget.Remaining(), 4);
    opcodes.Add(5);
    BOOST_CHECK(!opcodes.EndOpcode(opcode_budget));
    BOOST_CHECK_EQUAL(opcode_budget.Remaining(), 4);
}

BOOST_AUTO_TEST_CASE(div_steps)
{
    // Rows cover every quotient limb plus a possible normalization carry limb,
    // with one comparison row when the dividend is shorter.
    BOOST_CHECK_EQUAL(varops::DivSteps(0, 0), 2);
    BOOST_CHECK_EQUAL(varops::DivSteps(5, 0), 7);
    BOOST_CHECK_EQUAL(varops::DivSteps(0, 1), 1);
    BOOST_CHECK_EQUAL(varops::DivSteps(1, 2), 1);
    BOOST_CHECK_EQUAL(varops::DivSteps(1, 9), 1);
    BOOST_CHECK_EQUAL(varops::DivSteps(1, 1), 2);
    BOOST_CHECK_EQUAL(varops::DivSteps(9, 1), 10);
    BOOST_CHECK_EQUAL(varops::DivSteps(9, 8), 3);
    BOOST_CHECK_EQUAL(varops::DivSteps(9, 9), 2);
}

BOOST_AUTO_TEST_CASE(budget_does_not_overspend)
{
    varops::Budget budget{10};

    BOOST_CHECK(budget.Spend(0));
    BOOST_CHECK_EQUAL(budget.Remaining(), 10);

    BOOST_CHECK(budget.Spend(4));
    BOOST_CHECK_EQUAL(budget.Remaining(), 6);

    BOOST_CHECK(!budget.Spend(7));
    BOOST_CHECK_EQUAL(budget.Remaining(), 6);

    BOOST_CHECK(budget.Spend(6));
    BOOST_CHECK_EQUAL(budget.Remaining(), 0);

    BOOST_CHECK(!budget.Spend(1));
    BOOST_CHECK_EQUAL(budget.Remaining(), 0);

    BOOST_CHECK(budget.Spend(0));
    BOOST_CHECK_EQUAL(budget.Remaining(), 0);
}

template <bool LOCK_FREE>
static void CheckSharedCounterIsThreadSafe()
{
    static constexpr int thread_count{8};
    static constexpr int subtractions_per_thread{4096};
    varops::SharedCounter<LOCK_FREE> counter{thread_count * subtractions_per_thread / 2};
    std::atomic<int> successes{0};
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (int i{0}; i < thread_count; ++i) {
        threads.emplace_back([&] {
            for (int j{0}; j < subtractions_per_thread; ++j) {
                if (counter.TrySubtract(1)) ++successes;
            }
        });
    }
    for (auto& thread : threads) thread.join();
    BOOST_CHECK_EQUAL(successes.load(), thread_count * subtractions_per_thread / 2);
    BOOST_CHECK_EQUAL(counter.Load(), 0U);
    BOOST_CHECK(!counter.TrySubtract(1));
}

BOOST_AUTO_TEST_CASE(shared_counter_variants_are_thread_safe)
{
    // Budget uses the lock-free variant where 64-bit atomics are lock-free;
    // test the spin-lock fallback here as well, since it compiles everywhere.
    CheckSharedCounterIsThreadSafe<true>();
    CheckSharedCounterIsThreadSafe<false>();
}

BOOST_AUTO_TEST_SUITE_END()
