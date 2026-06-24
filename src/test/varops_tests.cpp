// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <consensus/validation.h>
#include <script/interpreter.h>
#include <script/varops.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <limits>
#include <thread>
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

BOOST_AUTO_TEST_CASE(maximum_superlinear_charges_fit_in_64_bits)
{
    // Recompute the largest OP_MUL and OP_DIV/OP_MOD charges in 256 bits from
    // their coefficients: the uint64_t charges must equal them, so no
    // intermediate wrapped.
    using Wide = arith_uint256;
    const Wide mul_fixed{varops::MulCost(0, 0)};
    const Wide mul_longer{varops::MulCost(1, 0) - varops::MulCost(0, 0)};
    const Wide mul_shorter{varops::MulCost(0, 1) - varops::MulCost(0, 0)};
    const Wide mul_cell{Wide{varops::MulCost(1, 1)} - mul_fixed - mul_longer - mul_shorter};
    const Wide limbs{varops::MAX_V2_LIMBS};
    const Wide mul{mul_fixed + mul_longer * limbs + mul_shorter * limbs + mul_cell * limbs * limbs +
                   Wide{varops::MAX_MUL_STORAGE_CHARGE}};
    BOOST_CHECK(mul == Wide{varops::MulCost(varops::MAX_V2_LIMBS, varops::MAX_V2_LIMBS) + varops::MAX_MUL_STORAGE_CHARGE});
    BOOST_CHECK(mul > Wide{std::numeric_limits<uint32_t>::max()});

    const Wide fixed{varops::DivCost(0, 0)};
    const Wide step{varops::DivCost(1, 0) - varops::DivCost(0, 0)};
    const Wide cell{varops::DivCost(1, 1) - varops::DivCost(1, 0)};
    for (const auto& [dividend, divisor] : {std::pair{varops::MAX_V2_LIMBS, uint64_t{1}},
                                            std::pair{varops::MAX_V2_LIMBS, varops::MAX_V2_LIMBS / 2},
                                            std::pair{varops::MAX_V2_LIMBS, varops::MAX_V2_LIMBS}}) {
        const Wide steps{varops::DivSteps(dividend, divisor)};
        BOOST_CHECK(fixed + step * steps + cell * steps * Wide{divisor} ==
                    Wide{varops::DivCost(varops::DivSteps(dividend, divisor), divisor)});
    }
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
