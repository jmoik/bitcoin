// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/validation.h>
#include <script/interpreter.h>
#include <script/varops.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <thread>
#include <type_traits>
#include <utility>
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
    const valtype control(33, TAPROOT_LEAF_TAPSCRIPT_V2);
    for (auto& input : tx.vin) input.scriptWitness.stack = {{OP_TRUE}, control};
    auto budget = [&] { return GetTransactionVaropsBudget(CTransaction{tx}, spent_outputs); };
    auto whole_budget = [&] { return varops::TxBudget(GetTransactionWeight(CTransaction{tx})); };
    auto excluded_weight = [&] {
        return WITNESS_SCALE_FACTOR * ::GetSerializeSize(tx.vin[1]) +
               ::GetSerializeSize(tx.vin[1].scriptWitness.stack);
    };
    BOOST_CHECK_EQUAL(budget(), whole_budget());
    // Annex and output-key parity do not change the leaf version.
    tx.vin[0].scriptWitness.stack.back()[0] |= 1;
    tx.vin[0].scriptWitness.stack.push_back({ANNEX_TAG, 1, 2});
    BOOST_CHECK_EQUAL(budget(), whole_budget());
    for (const unsigned char version : {0xc0, 0xc4}) {
        tx.vin[1].scriptWitness.stack.back()[0] = version;
        BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()));
    }
    // A key-path signature, even one starting with c2, is not a v2 script.
    tx.vin[1].scriptWitness.stack = {valtype(64, 0xc2), {ANNEX_TAG}};
    BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()));
    // Legacy, v0 and missing UTXOs cannot claim funding by imitating a v2 witness.
    tx.vin[1].scriptWitness.stack = {{OP_TRUE}, control};
    for (const CScript& script : {CScript{} << OP_TRUE, CScript{} << OP_0 << valtype(32, 1), CScript{}}) {
        spent_outputs[1].scriptPubKey = script;
        BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()));
    }
    // CompactSize boundaries count exactly, including scriptSig and witness prefixes.
    tx.vin[1].scriptSig.assign(253, 0);
    tx.vin[1].scriptWitness.stack = {valtype(253, 0)};
    BOOST_CHECK_EQUAL(budget(), whole_budget() - varops::TxBudget(excluded_weight()));
    spent_outputs[0].SetNull();
    BOOST_CHECK_EQUAL(budget(), 0);
}

BOOST_AUTO_TEST_CASE(bip440_cost_constants)
{
    BOOST_CHECK_EQUAL(varops::BUDGET_PER_WEIGHT_UNIT, 10'000);
    BOOST_CHECK_EQUAL(varops::COST_PER_OPCODE, varops::FixedOpcodeCost());
    BOOST_CHECK_EQUAL(varops::ExecutionCost(OP_ADD), varops::FixedOpcodeCost());
    BOOST_CHECK_EQUAL(varops::ExecutionCost(OP_HASH160), varops::FixedOpcodeCost());
    BOOST_CHECK_EQUAL(varops::TxBudget(4), 40'000);
    BOOST_CHECK_EQUAL(varops::COST_PER_SIGOP, 500'000);
    BOOST_CHECK_EQUAL(varops::SigcheckCost(OP_CHECKSIG), varops::COST_PER_SIGOP);
    BOOST_CHECK_EQUAL(varops::SignatureCost(), varops::COST_PER_SIGOP);
    if constexpr (!varops::PRODUCER_LIFETIME_EXPERIMENT) {
        BOOST_CHECK_EQUAL(varops::CopyCost(0), 668);
        BOOST_CHECK_EQUAL(varops::CopyCost(1), 670);
    }
    BOOST_CHECK_EQUAL(varops::ReleaseCost(0), 0);
    BOOST_CHECK_EQUAL(varops::ReleaseCost(8), varops::PRODUCER_LIFETIME_EXPERIMENT ? 0 : 987);
}

BOOST_AUTO_TEST_CASE(compositional_integer_accounting)
{
    BOOST_CHECK_EQUAL(varops::FixedOpcodeCost(), 382);
    BOOST_CHECK_EQUAL(varops::SignatureCost(), varops::COST_PER_SIGOP);
    BOOST_CHECK_EQUAL(varops::Sha256Cost(1) - varops::Sha256Cost(0), 48);
    BOOST_CHECK_EQUAL(varops::PrepCost(9), 249);
    BOOST_CHECK_EQUAL(varops::HashCost(OP_SHA256, 32), 4479);
    BOOST_CHECK_EQUAL(varops::ScalarOutputCost(), varops::OutputCost(8));
    if constexpr (!varops::PRODUCER_LIFETIME_EXPERIMENT) BOOST_CHECK_EQUAL(varops::ScalarOutputCost(), 1241);

    // Spending more than once deducts only newly added whole-varop costs.
    varops::Meter meter;
    varops::Budget budget{3};
    meter.Add(1);
    BOOST_CHECK(meter.Spend(budget));
    BOOST_CHECK(meter.Spend(budget));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 2);
    meter.Add(2);
    BOOST_CHECK(meter.Spend(budget));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
    meter.Add(1);
    BOOST_CHECK(!meter.Spend(budget));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
}

BOOST_AUTO_TEST_CASE(divcore_fixed_and_cell_cost)
{
    const uint64_t fixed{varops::DivCoreCost(0, 0)};
    const uint64_t cell{varops::DivCoreCost(1, 1) - fixed};
    BOOST_CHECK_EQUAL(fixed, 1574);
    BOOST_CHECK_EQUAL(cell, 267);
    // Only a fixed setup term and a steps*divisor-limbs term remain.
    for (const size_t steps : {1U, 2U, 32U, 1024U}) {
        BOOST_CHECK_EQUAL(varops::DivCoreCost(steps, 0), fixed);
        for (const size_t limbs : {1U, 2U, 3U, 16U, 1024U}) {
            BOOST_CHECK_EQUAL(varops::DivCoreCost(steps, limbs), fixed + cell * steps * limbs);
        }
    }
    const uint64_t cost{varops::DivCoreCost(32, 1024)};
    varops::Budget exact{cost};
    BOOST_CHECK(exact.Spend(cost));
    BOOST_CHECK_EQUAL(*exact.Remaining(), 0);
    varops::Budget short_budget{cost - 1};
    BOOST_CHECK(!short_budget.Spend(cost));
    BOOST_CHECK_EQUAL(*short_budget.Remaining(), cost - 1);
}

static uint64_t ExpectedMulCost(size_t size_a, size_t size_b)
{
    const uint64_t a{static_cast<uint64_t>(size_a)};
    const uint64_t b{static_cast<uint64_t>(size_b)};
    const uint64_t wa{(a + 7) / 8 * 8};
    const uint64_t wb{(b + 7) / 8 * 8};
    return (a + b) * 3 + wa / 8 * wb * 27;
}

static uint64_t ExpectedDivModCost(size_t size_a, size_t size_b)
{
    const uint64_t a{(static_cast<uint64_t>(size_a) + 7) / 8 * 8};
    const uint64_t b{(static_cast<uint64_t>(size_b) + 7) / 8 * 8};
    return a * 18 + b * 4 + a * a * 2 / 3;
}

BOOST_AUTO_TEST_CASE(bip441_multiply_and_divide_costs_are_64_bit)
{
    static_assert(std::is_same_v<decltype(varops::MulCost(size_t{0}, size_t{0})), uint64_t>);

    BOOST_CHECK_EQUAL(varops::detail::WordSize(0), 0);
    BOOST_CHECK_EQUAL(varops::detail::WordSize(1), 8);
    BOOST_CHECK_EQUAL(varops::detail::WordSize(8), 8);
    BOOST_CHECK_EQUAL(varops::detail::WordSize(9), 16);

    for (const auto& [size_a, size_b] : {
             std::pair<size_t, size_t>{0, 0},
             std::pair<size_t, size_t>{1, 1},
             std::pair<size_t, size_t>{7, 1},
             std::pair<size_t, size_t>{8, 8},
             std::pair<size_t, size_t>{9, 9},
             std::pair<size_t, size_t>{4'000'000, 4'000'000},
         }) {
        BOOST_TEST_CONTEXT("sizes " << size_a << ", " << size_b)
        {
            BOOST_CHECK_EQUAL(varops::MulCost(size_a, size_b), ExpectedMulCost(size_a, size_b));
            BOOST_CHECK_EQUAL(varops::DivCost(size_a, size_b), ExpectedDivModCost(size_a, size_b));
            BOOST_CHECK_EQUAL(varops::ModCost(size_a, size_b), ExpectedDivModCost(size_a, size_b));
        }
    }

    BOOST_CHECK_GT(varops::MulCost(4'000'000, 4'000'000), uint64_t{std::numeric_limits<uint32_t>::max()});
    BOOST_CHECK_GT(varops::DivCost(4'000'000, 4'000'000), uint64_t{std::numeric_limits<uint32_t>::max()});
}

BOOST_AUTO_TEST_CASE(bip440_and_bip441_word_granular_cost_helpers)
{
    BOOST_CHECK_EQUAL(varops::LengthConversionCost(1), 8 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::LengthConversionCost(8), 8 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::LengthConversionCost(9), 16 * varops::COST_FAST);

    BOOST_CHECK_EQUAL(varops::CompareZeroCost(3), 8 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::ComparisonCost(1, 9), 16 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::BoolAndCost(1, 9), (8 + 16) * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::BoolOrCost(9, 1), (16 + 8) * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::WithinCost(1, 9, 17), (16 + 24) * varops::COST_FAST);

    BOOST_CHECK_EQUAL(varops::AddCost(1, 9), 16 * (varops::COST_ARITH + varops::COST_COPYING));
    BOOST_CHECK_EQUAL(varops::SubCost(9, 1), 16 * varops::COST_ARITH);
    BOOST_CHECK_EQUAL(varops::MinMaxCost(1, 9), 16 * varops::COST_OTHER);

    BOOST_CHECK_EQUAL(varops::InvertCost(9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::ByteReverseCost(0), 0);
    BOOST_CHECK_EQUAL(varops::ByteReverseCost(9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::AndCost(1, 9), (8 + 16) * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::OrCost(1, 9), 8 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::XorCost(9, 1), 8 * varops::COST_OTHER);

    BOOST_CHECK_EQUAL(varops::TwoMulCost(9), 16 * (varops::COST_COPYING + varops::COST_OTHER));
    BOOST_CHECK_EQUAL(varops::TwoDivCost(9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::UnalignedUpShiftCost(9, 0), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::UnalignedUpShiftCost(1, 9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::ChecksigAddIncrementCost(0), 8 * (varops::COST_ARITH + varops::COST_COPYING));
    BOOST_CHECK_EQUAL(varops::ChecksigAddIncrementCost(9), 16 * (varops::COST_ARITH + varops::COST_COPYING));
}

BOOST_AUTO_TEST_CASE(budget_does_not_overspend)
{
    varops::Budget budget{10};

    BOOST_CHECK(budget.Spend(0));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 10);

    BOOST_CHECK(budget.Spend(4));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 6);

    BOOST_CHECK(!budget.Spend(7));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 6);

    BOOST_CHECK(budget.Spend(6));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);

    BOOST_CHECK(!budget.Spend(1));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);

    BOOST_CHECK(budget.Spend(0));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
}

BOOST_AUTO_TEST_CASE(budget_can_be_unmetered)
{
    auto budget{varops::Budget::Unmetered()};

    BOOST_CHECK(!budget.Remaining());
    BOOST_CHECK(budget.Spend(std::numeric_limits<uint64_t>::max()));
    BOOST_CHECK(!budget.Remaining());
}

BOOST_AUTO_TEST_CASE(budget_is_transaction_wide_and_thread_safe)
{
    static constexpr int thread_count{32};
    static constexpr int spends_per_thread{4096};
    static constexpr uint64_t budget_amount{thread_count * spends_per_thread / 2};

    varops::Budget budget{budget_amount};
    std::atomic<uint64_t> successful_spends{0};
    std::atomic<int> ready_threads{0};
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;

    threads.reserve(thread_count);
    for (int i{0}; i < thread_count; ++i) {
        threads.emplace_back([&] {
            ready_threads.fetch_add(1, std::memory_order_acq_rel);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int spend{0}; spend < spends_per_thread; ++spend) {
                if (budget.Spend(1)) {
                    successful_spends.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    while (ready_threads.load(std::memory_order_acquire) != thread_count) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);

    for (std::thread& thread : threads) {
        thread.join();
    }

    BOOST_CHECK_EQUAL(successful_spends.load(std::memory_order_relaxed), budget_amount);
    BOOST_CHECK(!budget.Spend(1));
}

BOOST_AUTO_TEST_SUITE_END()
