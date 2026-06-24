// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <script/interpreter.h>
#include <script/varops.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

BOOST_AUTO_TEST_SUITE(varops_tests)

BOOST_AUTO_TEST_CASE(participating_input_funding)
{
    using valtype = std::vector<unsigned char>;
    CMutableTransaction tx;
    tx.vin.resize(2);
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    const CScript taproot{CScript{} << OP_1 << std::vector<unsigned char>(32, 1)};
    std::vector<CTxOut> spent_outputs(2, CTxOut{1, taproot});
    const valtype control(33, TAPROOT_LEAF_0XC2);
    for (auto& input : tx.vin) input.scriptWitness.stack = {{OP_TRUE}, control};
    auto budget = [&] { return GetTransactionVaropsBudget(CTransaction{tx}, spent_outputs); };
    auto whole_budget = [&] { return varops::TxBudget(GetTransactionWeight(CTransaction{tx})); };
    auto excluded_weight = [&] {
        return WITNESS_SCALE_FACTOR * ::GetSerializeSize(tx.vin[1]) +
               ::GetSerializeSize(tx.vin[1].scriptWitness.stack);
    };
    // Each funding Taproot script-path input pays one SIGCHECK for its commitment check.
    auto commitments = [](uint64_t n) { return n * varops::SignatureCost(); };
    BOOST_CHECK_EQUAL(budget(), whole_budget() - commitments(2));
    // Annex and output-key parity do not change the leaf version.
    tx.vin[0].scriptWitness.stack.back()[0] |= 1;
    tx.vin[0].scriptWitness.stack.push_back({ANNEX_TAG, 1, 2});
    BOOST_CHECK_EQUAL(budget(), whole_budget() - commitments(2));
    // A Tapleaf 0xC0 spend is excluded; a leaf version not yet defined funds the budget.
    tx.vin[1].scriptWitness.stack.back()[0] = TAPROOT_LEAF_TAPSCRIPT;
    BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()) - commitments(1));
    tx.vin[1].scriptWitness.stack.back()[0] = 0xc4;
    BOOST_CHECK_EQUAL(budget(), whole_budget() - commitments(2));
    // A key-path signature, even one starting with c2, is excluded.
    tx.vin[1].scriptWitness.stack = {valtype(64, 0xc2), {ANNEX_TAG}};
    BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()) - commitments(1));
    // Witness versions and program sizes not yet defined, P2A and P2SH-wrapped
    // Taproot fund the budget without a commitment check.
    tx.vin[1].scriptWitness.stack = {{OP_TRUE}, control};
    const CScript p2sh{CScript{} << OP_HASH160 << valtype(20, 1) << OP_EQUAL};
    for (const CScript& script : {CScript{} << OP_2 << valtype(32, 1), CScript{} << OP_1 << valtype(20, 1),
                                  CScript{} << OP_1 << valtype{0x4e, 0x73}, p2sh}) {
        spent_outputs[1].scriptPubKey = script;
        tx.vin[1].scriptSig = script == p2sh ? CScript{} << ToByteVector(taproot) : CScript{};
        BOOST_CHECK_EQUAL(budget(), whole_budget() - commitments(1));
    }
    // Legacy, v0 (native or P2SH-wrapped) and missing UTXOs cannot claim funding
    // by imitating a Tapleaf 0xC2 witness.
    const CScript v0{CScript{} << OP_0 << valtype(32, 1)};
    for (const CScript& script : {CScript{} << OP_TRUE, v0, p2sh, CScript{}}) {
        spent_outputs[1].scriptPubKey = script;
        tx.vin[1].scriptSig = script == p2sh ? CScript{} << ToByteVector(v0) : CScript{};
        BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()) - commitments(1));
    }
    // CompactSize boundaries count exactly, including scriptSig and witness prefixes.
    tx.vin[1].scriptSig.assign(253, 0);
    tx.vin[1].scriptWitness.stack = {valtype(253, 0)};
    BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()) - commitments(1));
    spent_outputs[0].SetNull();
    BOOST_CHECK_EQUAL(budget(), 0);
}

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
