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
    BOOST_CHECK_EQUAL(varops::CopyCost(0), 1600);
    BOOST_CHECK_EQUAL(varops::CopyCost(1), 1607);
}

BOOST_AUTO_TEST_CASE(compositional_integer_accounting)
{
    BOOST_CHECK_EQUAL(varops::FixedOpcodeCost(), 350);
    BOOST_CHECK_EQUAL(varops::SignatureCost(), varops::COST_PER_SIGOP);
    BOOST_CHECK_EQUAL(varops::HashBlockSpan(0), 64);
    BOOST_CHECK_EQUAL(varops::HashBlockSpan(55), 64);
    BOOST_CHECK_EQUAL(varops::HashBlockSpan(56), 128);
    BOOST_CHECK_EQUAL(varops::HashBlockSpan(520), 576);
    BOOST_CHECK_EQUAL(varops::Sha256Cost(55), varops::Sha256Cost(0));
    BOOST_CHECK_EQUAL(varops::Sha256Cost(56) - varops::Sha256Cost(55), 57 * 64);
    BOOST_CHECK_EQUAL(varops::PrepCost(9), 316);
    BOOST_CHECK_EQUAL(varops::HashCost(OP_SHA256, 32), 4098);
    BOOST_CHECK_EQUAL(varops::ReadCost(9), 264);
    BOOST_CHECK_EQUAL(varops::ArithCost(8), 340);
    BOOST_CHECK_EQUAL(varops::BitCost(8), 116);
    BOOST_CHECK_EQUAL(varops::ByteReverseCost(8), 206);
    BOOST_CHECK_EQUAL(varops::MoveCost(2), 350);
    BOOST_CHECK_EQUAL(varops::MulCost(2, 3), 1784);
    BOOST_CHECK_EQUAL(varops::Ripemd160Cost(32), 3016);
    BOOST_CHECK_EQUAL(varops::Sha1Cost(32), 1992);
    BOOST_CHECK_EQUAL(varops::TweakCost(), 168200);
    BOOST_CHECK_EQUAL(varops::ProduceCost(8), 1656);
    BOOST_CHECK_EQUAL(varops::NormalizeCost(8), 366);
    BOOST_CHECK_EQUAL(varops::ScalarOutputCost(), 2022);
    BOOST_CHECK_EQUAL(varops::ScalarOutputCost(), varops::OutputCost(8));

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

BOOST_AUTO_TEST_CASE(divcore_fixed_step_and_cell_cost)
{
    const uint64_t fixed{varops::DivCoreCost(0, 0)};
    const uint64_t step{varops::DivCoreCost(1, 0) - fixed};
    const uint64_t cell{varops::DivCoreCost(1, 1) - fixed - step};
    BOOST_CHECK_EQUAL(fixed, 11050);
    BOOST_CHECK_EQUAL(step, 580);
    BOOST_CHECK_EQUAL(cell, 255);
    // A fixed setup term, a per-row term and a rows*divisor-limbs term.
    for (const size_t steps : {1U, 2U, 32U, 1024U}) {
        BOOST_CHECK_EQUAL(varops::DivCoreCost(steps, 0), fixed + step * steps);
        for (const size_t limbs : {1U, 2U, 3U, 16U, 1024U}) {
            BOOST_CHECK_EQUAL(varops::DivCoreCost(steps, limbs), fixed + step * steps + cell * steps * limbs);
        }
    }
    const uint64_t cost{varops::DivCoreCost(32, 1024)};
    varops::Budget exact{cost};
    BOOST_CHECK(exact.Spend(cost));
    BOOST_CHECK_EQUAL(*exact.Remaining(), 0);
    varops::Budget short_budget{cost - 1};
    BOOST_CHECK(!short_budget.Spend(cost));
    BOOST_CHECK_EQUAL(*short_budget.Remaining(), cost - 1);

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

BOOST_AUTO_TEST_CASE(maximum_superlinear_charges_fit_in_64_bits)
{
    BOOST_CHECK_EQUAL(varops::WordSpan(0), 0);
    BOOST_CHECK_EQUAL(varops::WordSpan(1), 8);
    BOOST_CHECK_EQUAL(varops::WordSpan(8), 8);
    BOOST_CHECK_EQUAL(varops::WordSpan(9), 16);

    // Recompute the largest OP_MUL and OP_DIV/OP_MOD charges in 128 bits: the
    // uint64_t charges must equal them, so no intermediate wrapped.
    using u128 = unsigned __int128;
    const u128 limbs{varops::MAX_V2_LIMBS};
    const u128 mul{1450 + 41 * limbs + 42 * limbs * limbs + varops::MAX_MUL_STORAGE_CHARGE};
    BOOST_CHECK(mul == u128{varops::MulCost(varops::MAX_V2_LIMBS, varops::MAX_V2_LIMBS) + varops::MAX_MUL_STORAGE_CHARGE});
    BOOST_CHECK(mul > std::numeric_limits<uint32_t>::max());

    const u128 fixed{varops::DivCoreCost(0, 0)};
    const u128 step{varops::DivCoreCost(1, 0) - varops::DivCoreCost(0, 0)};
    const u128 cell{varops::DivCoreCost(1, 1) - varops::DivCoreCost(1, 0)};
    for (const auto& [dividend, divisor] : {std::pair{varops::MAX_V2_LIMBS, uint64_t{1}},
                                            std::pair{varops::MAX_V2_LIMBS, varops::MAX_V2_LIMBS / 2},
                                            std::pair{varops::MAX_V2_LIMBS, varops::MAX_V2_LIMBS}}) {
        const uint64_t steps{varops::DivSteps(dividend, divisor)};
        BOOST_CHECK(fixed + step * steps + cell * steps * divisor == u128{varops::DivCoreCost(steps, divisor)});
    }
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
