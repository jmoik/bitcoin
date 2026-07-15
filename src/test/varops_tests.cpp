// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/varops.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

BOOST_AUTO_TEST_SUITE(varops_tests)

BOOST_AUTO_TEST_CASE(meter_deducts_once)
{
    // A meter checks its charges against the budget that remained when it was
    // created, and deducts them only when spent.
    varops::Budget budget{5};
    varops::Meter meter{budget};
    meter.Add(3);
    BOOST_CHECK(meter.Fits());
    BOOST_CHECK_EQUAL(budget.Remaining(), 5);
    meter.Add(2);
    BOOST_CHECK(meter.Fits());
    meter.Add(1);
    BOOST_CHECK(!meter.Fits());

    // Meters created together each see the whole budget. The deduction that
    // overruns it fails and deducts nothing.
    varops::Budget shared{5};
    varops::Meter first{shared}, second{shared};
    first.Add(3);
    second.Add(3);
    BOOST_CHECK(first.Fits());
    BOOST_CHECK(second.Fits());
    BOOST_CHECK(first.Spend(shared));
    BOOST_CHECK_EQUAL(shared.Remaining(), 2);
    BOOST_CHECK(!second.Spend(shared));
    BOOST_CHECK_EQUAL(shared.Remaining(), 2);
}

BOOST_AUTO_TEST_CASE(div_excess)
{
    // Q(n, m): bytes by which the dividend's word span exceeds the divisor's, zero
    // when the dividend is not longer.
    BOOST_CHECK_EQUAL(varops::DivExcess(0, 0), 0);
    BOOST_CHECK_EQUAL(varops::DivExcess(40, 0), 40);
    BOOST_CHECK_EQUAL(varops::DivExcess(1, 9), 0);
    BOOST_CHECK_EQUAL(varops::DivExcess(8, 8), 0);
    BOOST_CHECK_EQUAL(varops::DivExcess(9, 8), 8);
    BOOST_CHECK_EQUAL(varops::DivExcess(72, 1), 64);
    BOOST_CHECK_EQUAL(varops::DivExcess(72, 65), 0);
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
