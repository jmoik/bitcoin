// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The reusable macros vectors are run by tapleaf_0xc2_vector_tests.

#include <script/interpreter.h>
#include <script/reusable_macros.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace {

struct Execution {
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t charge{0};
    //! The script transaction introspection sees, if execution began.
    std::optional<CScript> tapscript;
};

Execution Execute(const CScript& script, uint64_t budget)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    varops::Budget varops_budget{budget};
    ValtypeStack stack;
    Execution execution;
    EvalTapleaf0xC2(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, execdata, varops_budget, &execution.error);
    execution.charge = budget - varops_budget.Remaining();
    if (execdata.m_tapscript_init) execution.tapscript = CScript(execdata.m_tapscript.begin(), execdata.m_tapscript.end());
    return execution;
}

uint64_t UnrollingCharge(const CScript& script)
{
    reusable_macros::Program program{script};
    BOOST_REQUIRE(reusable_macros::Decode(program) == reusable_macros::DecodeResult::WELL_FORMED);
    constexpr uint64_t ample{std::numeric_limits<uint64_t>::max()};
    varops::Budget budget{ample};
    CScript unrolled;
    BOOST_REQUIRE(reusable_macros::Unroll(program, budget, unrolled, nullptr));
    return ample - budget.Remaining();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(tapleaf_0xc2_macro_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unrolling_is_charged_before_execution)
{
    // OP_MACRO <OP_DUP OP_DROP> OP_0 OP_IF OP_CALLMACRO 0 OP_ENDIF OP_1
    const std::vector<unsigned char> bytes{ParseHex("d002767500" "63" "d100" "68" "51")};
    const CScript script{bytes.begin(), bytes.end()};
    const uint64_t unrolling{UnrollingCharge(script)};

    // One varop short, nothing is charged and execution does not begin.
    const Execution short_unrolling{Execute(script, unrolling - 1)};
    BOOST_CHECK_EQUAL(short_unrolling.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK_EQUAL(short_unrolling.charge, 0);
    BOOST_CHECK(!short_unrolling.tapscript);

    // With exactly the unrolling charge, execution begins with the committed
    // script and fails at its first instruction.
    const Execution exact_unrolling{Execute(script, unrolling)};
    BOOST_CHECK_EQUAL(exact_unrolling.error, SCRIPT_ERR_VAROP_COUNT);
    BOOST_CHECK_EQUAL(exact_unrolling.charge, unrolling);
    BOOST_CHECK(exact_unrolling.tapscript == script);
}

BOOST_AUTO_TEST_SUITE_END()
