// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/op_tx.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <streams.h>
#include <test/data/op_tx.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;
using Stack = std::vector<valtype>;

constexpr uint64_t DEFAULT_VAROPS{40'000'000'000};

valtype TaggedHashPrefix(std::string_view tag)
{
    uint256 tag_hash;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size()).Finalize(tag_hash.begin());
    valtype result{tag_hash.begin(), tag_hash.end()};
    result.insert(result.end(), tag_hash.begin(), tag_hash.end());
    return result;
}

valtype DecodeHex(const UniValue& value)
{
    if (value.isStr()) return ParseHex(value.get_str());
    if (!value.isObject() || !value.exists("repeat") || !value.exists("count")) {
        throw std::invalid_argument("invalid expanded hex value");
    }
    const valtype pattern{ParseHex(value["repeat"].get_str())};
    const uint64_t count{value["count"].getInt<uint64_t>()};
    if (pattern.size() > 0 && count > std::numeric_limits<size_t>::max() / pattern.size()) {
        throw std::length_error("expanded hex value too large");
    }
    valtype result;
    result.reserve(pattern.size() * count);
    for (uint64_t i{0}; i < count; ++i)
        result.insert(result.end(), pattern.begin(), pattern.end());
    return result;
}

std::optional<valtype> DecodeOptionalHex(const UniValue& value)
{
    if (value.isNull()) return std::nullopt;
    return DecodeHex(value);
}

Stack DecodeStack(const UniValue& values)
{
    Stack result;
    if (values.isNull()) return result;
    for (const UniValue& value : values.getValues()) {
        if (value.isObject() && value.exists("items")) {
            const valtype element{DecodeHex(value["element"])};
            const uint64_t count{value["items"].getInt<uint64_t>()};
            if (count > result.max_size() - result.size()) throw std::length_error("stack too large");
            result.insert(result.end(), count, element);
        } else {
            result.push_back(DecodeHex(value));
        }
    }
    return result;
}

CTransaction DecodeTransaction(const UniValue& value)
{
    CMutableTransaction tx;
    SpanReader{DecodeHex(value)} >> TX_WITH_WITNESS(tx);
    return CTransaction{tx};
}

CTxOut DecodeTxOut(const UniValue& value)
{
    CTxOut output;
    SpanReader{DecodeHex(value)} >> output;
    return output;
}

class OpTxChecker final : public BaseSignatureChecker
{
    const CTransaction& m_tx;
    const uint32_t m_input_index;
    const std::span<const CTxOut> m_spent_outputs;

public:
    OpTxChecker(const CTransaction& tx, uint32_t input_index, std::span<const CTxOut> spent_outputs)
        : m_tx{tx}, m_input_index{input_index}, m_spent_outputs{spent_outputs}
    {
    }

    std::optional<ScriptTransactionData> GetTransactionData() const override
    {
        return ScriptTransactionData{
            m_tx.version,
            m_tx.vin,
            m_tx.vout,
            m_tx.nLockTime,
            m_input_index,
            m_spent_outputs,
        };
    }
};

ScriptError ExpectedError(const std::string& error)
{
    if (error == "missing_selector" || error == "missing_scope_operand") {
        return SCRIPT_ERR_INVALID_STACK_OPERATION;
    }
    if (error == "varops_exhausted") return SCRIPT_ERR_VAROP_COUNT;
    if (error == "stack_item_limit") return SCRIPT_ERR_STACK_SIZE;
    if (error == "stack_byte_limit") return SCRIPT_ERR_TOTAL_STACK_SIZE;
    if (error == "element_size_limit") return SCRIPT_ERR_STACK_ELEMENT_SIZE;
    if (error == "amount_overflow" || error == "unavailable_context" ||
        error == "unavailable_record" || error == "invalid_current_input") {
        return SCRIPT_ERR_TX_CONTEXT;
    }
    return SCRIPT_ERR_TX_SELECTOR;
}

valtype TestControlBlock()
{
    valtype control_block(TAPROOT_CONTROL_BASE_SIZE, 0);
    control_block[0] = TAPROOT_LEAF_TAPSCRIPT_V2;
    return control_block;
}

void InitOpTxContext(ScriptExecutionData& execdata, const CScript& script,
                     const valtype& control_block)
{
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapscript_init = true;
    execdata.m_tapscript = script;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT_V2, script);
    execdata.m_control_block_init = true;
    execdata.m_control_block = control_block;
    execdata.m_taptree_root_init = true;
    execdata.m_taptree_root = ComputeTaprootMerkleRoot(control_block, execdata.m_tapleaf_hash);
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xffffffff;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(op_tx_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reference_vectors)
{
    const UniValue vectors{read_json(json_tests::op_tx)};
    BOOST_REQUIRE_EQUAL(vectors.size(), 76);

    for (const UniValue& test : vectors.getValues()) {
        const std::string id{test["id"].get_str()};
        BOOST_TEST_CONTEXT(id)
        {
            const CTransaction tx{DecodeTransaction(test["spending_tx"])};
            std::vector<CTxOut> spent_outputs;
            for (const UniValue& output : test["spent_outputs"].getValues()) {
                spent_outputs.push_back(DecodeTxOut(output));
            }

            const uint32_t input_index{test["input_index"].getInt<uint32_t>()};
            const OpTxChecker checker{tx, input_index, spent_outputs};

            const UniValue& context{test["context"]};
            const std::optional<valtype> annex{DecodeOptionalHex(context["annex"])};
            const std::optional<valtype> tapscript{DecodeOptionalHex(context["tapscript"])};
            const std::optional<valtype> control_block{DecodeOptionalHex(context["control_block"])};
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = annex.has_value();
            if (annex) {
                execdata.m_annex = *annex;
            }
            if (tapscript) {
                execdata.m_tapscript_init = true;
                execdata.m_tapscript = *tapscript;
                execdata.m_tapleaf_hash_init = true;
                execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT_V2, *tapscript);
            }
            if (control_block) {
                execdata.m_control_block_init = true;
                execdata.m_control_block = *control_block;
                if (execdata.m_tapleaf_hash_init && control_block->size() >= TAPROOT_CONTROL_BASE_SIZE &&
                    control_block->size() <= TAPROOT_CONTROL_MAX_SIZE &&
                    (control_block->size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE == 0) {
                    execdata.m_taptree_root_init = true;
                    execdata.m_taptree_root = ComputeTaprootMerkleRoot(*control_block, execdata.m_tapleaf_hash);
                }
            }
            if (!context["codesep_pos"].isNull()) {
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = context["codesep_pos"].getInt<uint32_t>();
            }

            Stack initial_stack{test.exists("initial_stack") ? DecodeStack(test["initial_stack"]) : Stack{}};
            const Stack scope_operands{
                test.exists("scope_operands") ? DecodeStack(test["scope_operands"]) : Stack{}};
            Stack invocation_stack{initial_stack};
            invocation_stack.insert(invocation_stack.end(), scope_operands.begin(), scope_operands.end());
            ValtypeStack stack{invocation_stack};
            if (!test["selector"].isNull()) stack.push_back(DecodeHex(test["selector"]));
            ValtypeStack altstack{
                test.exists("initial_altstack") ? DecodeStack(test["initial_altstack"]) : Stack{}};
            const uint64_t budget{test.exists("available_varops") ? test["available_varops"].getInt<uint64_t>() : DEFAULT_VAROPS};
            varops::Budget varops_budget{budget};
            ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};

            const OpTxResult result{EvalOpTx(stack, altstack, checker, execdata, varops_budget, &error)};
            const UniValue& expected{test["expected"]};
            const bool expected_success{expected["success"].get_bool()};
            BOOST_CHECK_EQUAL(result != OpTxResult::ERROR, expected_success);
            if (expected_success) {
                const bool expected_immediate{expected.exists("immediate_success") && expected["immediate_success"].get_bool()};
                BOOST_CHECK_EQUAL(result == OpTxResult::IMMEDIATE_SUCCESS, expected_immediate);
                const Stack expected_outputs{DecodeStack(expected["outputs"])};
                Stack expected_stack{
                    expected_immediate ? std::move(invocation_stack) : std::move(initial_stack)};
                expected_stack.insert(expected_stack.end(), expected_outputs.begin(), expected_outputs.end());
                BOOST_CHECK(stack.GetStack() == expected_stack);
                const uint64_t consumed{budget - *varops_budget.Remaining()};
                BOOST_CHECK_EQUAL(consumed, expected["varops"].getInt<uint64_t>());
            } else if (!expected_success) {
                BOOST_CHECK_EQUAL(error, ExpectedError(expected["error"].get_str()));
                if (scope_operands.empty()) BOOST_CHECK(stack.GetStack() == initial_stack);
                BOOST_CHECK_EQUAL(*varops_budget.Remaining(), budget);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(interpreter_dispatch_and_execution_cost)
{
    CMutableTransaction mutable_tx;
    mutable_tx.version = 2;
    mutable_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mutable_tx.vout.emplace_back(1, CScript{});
    const CTransaction tx{mutable_tx};
    const std::vector<CTxOut> spent_outputs{CTxOut{2, CScript{}}};
    const OpTxChecker checker{tx, 0, spent_outputs};

    CScript script;
    script << valtype{0x00, 0x02, 0x00, 0x00, 0x00, 0x00} << OP_TX;
    ScriptExecutionData execdata;
    const valtype control_block{TestControlBlock()};
    InitOpTxContext(execdata, script, control_block);
    ValtypeStack stack;
    varops::Budget budget{varops::COST_PER_OPCODE + varops::ExecutionCost(OP_TX) +
                          3 + 6 * varops::COST_COPYING};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_REQUIRE(EvalTapscriptV2(stack, script, SCRIPT_VERIFY_NONE, checker, execdata, budget, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1);
    BOOST_CHECK(stack.back() == valtype{0x02});
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
}

BOOST_AUTO_TEST_CASE(runtime_range_operands)
{
    CMutableTransaction mutable_tx;
    mutable_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    mutable_tx.vout.emplace_back(10, CScript{});
    mutable_tx.vout.emplace_back(20, CScript{});
    mutable_tx.vout.emplace_back(30, CScript{});
    const CTransaction tx{mutable_tx};
    const std::vector<CTxOut> spent_outputs{CTxOut{40, CScript{}}};
    const OpTxChecker checker{tx, 0, spent_outputs};

    const valtype output_count{0x00, 0x40, 0x00, 0x00, 0x00, 0x00};
    const valtype output_range_amounts{0x00, 0x00, 0x00, 0x04, 0x00, 0x01};
    CScript script;
    script << valtype{0xaa} << OP_1;
    script << output_count << OP_TX << OP_1 << OP_SUB;
    script << output_range_amounts << OP_TX;

    ScriptExecutionData execdata;
    const valtype control_block{TestControlBlock()};
    InitOpTxContext(execdata, script, control_block);
    ValtypeStack stack;
    auto budget{varops::Budget::Unmetered()};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_REQUIRE(EvalTapscriptV2(stack, script, SCRIPT_VERIFY_NONE, checker, execdata, budget, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 3);
    BOOST_CHECK(stack.at(0) == valtype{0xaa});
    BOOST_CHECK(stack.at(1) == valtype{20});
    BOOST_CHECK(stack.at(2) == valtype{30});
}

BOOST_AUTO_TEST_CASE(undefined_selector_fails_closed)
{
    const valtype selector{0x00, 0x00, 0x00, 0x01, 0x00, 0x04};
    BaseSignatureChecker checker;
    ScriptExecutionData execdata;

    {
        ValtypeStack stack{Stack{selector}};
        ValtypeStack altstack;
        varops::Budget budget{0};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(EvalOpTx(stack, altstack, checker, execdata, budget, &error) == OpTxResult::ERROR);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_TX_SELECTOR);
        BOOST_CHECK_EQUAL(stack.size(), 0);
        BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
    }

    const auto eval_script{[&](const CScript& script, script_verify_flags flags, ScriptError expected_error) {
        ValtypeStack stack;
        auto budget{varops::Budget::Unmetered()};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool success{EvalTapscriptV2(stack, script, flags, checker, execdata, budget, &error)};
        BOOST_CHECK_EQUAL(success, expected_error == SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(error, expected_error);
    }};

    eval_script(CScript{} << selector << OP_TX << OP_1, SCRIPT_VERIFY_NONE, SCRIPT_ERR_TX_SELECTOR);
    eval_script(CScript{} << OP_0 << OP_IF << selector << OP_TX << OP_ENDIF << OP_1,
                SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(future_selector_version_succeeds)
{
    const valtype selector{0x01};
    BaseSignatureChecker checker;
    ScriptExecutionData execdata;

    {
        ValtypeStack stack{Stack{valtype{}, selector}};
        ValtypeStack altstack;
        varops::Budget budget{0};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(EvalOpTx(stack, altstack, checker, execdata, budget, &error) ==
                    OpTxResult::IMMEDIATE_SUCCESS);
        BOOST_REQUIRE_EQUAL(stack.size(), 1);
        BOOST_CHECK(stack.back().empty());
        BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
    }

    const auto eval_script{[&](const CScript& script, script_verify_flags flags,
                               ScriptError expected_error) {
        ValtypeStack stack;
        auto budget{varops::Budget::Unmetered()};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool success{EvalTapscriptV2(stack, script, flags, checker, execdata, budget, &error)};
        BOOST_CHECK_EQUAL(success, expected_error == SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(error, expected_error);
    }};

    eval_script(CScript{} << selector << OP_TX << OP_RETURN, SCRIPT_VERIFY_NONE, SCRIPT_ERR_OK);
    eval_script(CScript{} << selector << OP_TX << OP_IF, SCRIPT_VERIFY_NONE, SCRIPT_ERR_OK);
    eval_script(CScript{} << selector << OP_TX, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
    eval_script(CScript{} << OP_0 << OP_IF << selector << OP_TX << OP_ENDIF << OP_1,
                SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(bip341_sighash_construction_csfs)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey xonly_pubkey{key.GetPubKey()};
    const valtype pubkey{xonly_pubkey.begin(), xonly_pubkey.end()};

    // Each aggregate selector emits the exact serialization committed by BIP 341.
    const valtype globals{0x00, 0x07, 0x00, 0x00, 0x00, 0x00};
    const valtype prevouts{0x00, 0x01, 0x00, 0x20, 0x03, 0x00};
    const valtype amounts{0x00, 0x01, 0x00, 0x20, 0x04, 0x00};
    const valtype scriptpubkeys{0x00, 0x01, 0x00, 0x20, 0x08, 0x00};
    const valtype sequences{0x00, 0x01, 0x00, 0x20, 0x20, 0x00};
    const valtype outputs{0x00, 0x01, 0x00, 0x02, 0x00, 0x03};
    const valtype input_index{0x00, 0x01, 0x01, 0x00, 0x00, 0x00};
    const valtype tapscript{0x00, 0x01, 0x04, 0x00, 0x00, 0x00};
    const valtype codesep_position{0x00, 0x01, 0x80, 0x00, 0x00, 0x00};

    CScript script;
    valtype sighash_prefix{TaggedHashPrefix("TapSighash")};
    sighash_prefix.push_back(0x00); // epoch
    sighash_prefix.push_back(SIGHASH_DEFAULT);
    script << sighash_prefix;

    const auto append_value{[&](const valtype& selector) {
        script << selector << OP_TX << OP_CAT;
    }};
    const auto append_hash{[&](const valtype& selector) {
        script << selector << OP_TX << OP_SHA256 << OP_CAT;
    }};

    append_value(globals);
    append_hash(prevouts);
    append_hash(amounts);
    append_hash(scriptpubkeys);
    append_hash(sequences);
    append_hash(outputs);
    script << valtype{0x02} << OP_CAT; // script-path spend without annex
    append_value(input_index);

    valtype tapleaf_prefix{TaggedHashPrefix("TapLeaf")};
    tapleaf_prefix.push_back(TAPROOT_LEAF_TAPSCRIPT_V2);
    script << tapleaf_prefix << tapscript << OP_TX << OP_CAT << OP_SHA256 << OP_CAT;
    script << valtype{0x00} << OP_CAT; // key version
    append_value(codesep_position);
    script << OP_SHA256 << pubkey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mutable_tx;
    mutable_tx.version = 2;
    mutable_tx.nLockTime = 500'000;
    mutable_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 3}, CScript{}, 0xfffffffd);
    mutable_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 7}, CScript{}, 0xfffffffc);
    mutable_tx.vout.emplace_back(80'000, CScript{} << OP_TRUE);
    mutable_tx.vout.emplace_back(39'000, CScript{} << valtype{0xaa, 0xbb});
    const CTransaction tx{mutable_tx};
    const std::vector<CTxOut> spent_outputs{
        CTxOut{50'000, CScript{} << OP_TRUE},
        CTxOut{70'000, CScript{} << valtype{0x51, 0x52}},
    };
    PrecomputedTransactionData precomputed;
    precomputed.Init(tx, std::vector<CTxOut>{spent_outputs}, /*force=*/true);

    ScriptExecutionData sighash_execdata;
    sighash_execdata.m_annex_init = true;
    sighash_execdata.m_annex_present = false;
    sighash_execdata.m_tapleaf_hash =
        (HashWriter{HASHER_TAPLEAF} << TAPROOT_LEAF_TAPSCRIPT_V2 << script).GetSHA256();
    sighash_execdata.m_tapleaf_hash_init = true;
    sighash_execdata.m_codeseparator_pos = 0xffffffff;
    sighash_execdata.m_codeseparator_pos_init = true;

    uint256 expected_sighash;
    BOOST_REQUIRE(SignatureHashSchnorr(expected_sighash, sighash_execdata, tx, /*in_pos=*/1,
                                       SIGHASH_DEFAULT, SigVersion::TAPSCRIPT_V2, precomputed,
                                       MissingDataBehavior::FAIL));
    std::array<unsigned char, 64> signature;
    BOOST_REQUIRE(key.SignSchnorr(expected_sighash, signature, /*merkle_root=*/nullptr, uint256::ZERO));

    const OpTxChecker checker{tx, 1, spent_outputs};
    ScriptExecutionData execdata;
    const valtype control_block{TestControlBlock()};
    InitOpTxContext(execdata, script, control_block);
    ValtypeStack stack{Stack{valtype{signature.begin(), signature.end()}}};
    varops::Budget budget{DEFAULT_VAROPS};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    BOOST_REQUIRE(EvalTapscriptV2(stack, script, SCRIPT_VERIFY_NONE, checker, execdata, budget, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(), 1);
    BOOST_CHECK(stack.back() == valtype{0x01});
}

BOOST_AUTO_TEST_CASE(bip118_style_anyprevout_sighash_construction_csfs)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey xonly_pubkey{key.GetPubKey()};
    const valtype pubkey{xonly_pubkey.begin(), xonly_pubkey.end()};

    // SIGHASH_ANYPREVOUT | SIGHASH_ALL omits every outpoint aggregate and the
    // current outpoint, while retaining the current amount, script, and sequence.
    constexpr uint8_t SIGHASH_ANYPREVOUT_ALL{0x41};
    const valtype globals{0x00, 0x07, 0x00, 0x00, 0x00, 0x00};
    const valtype outputs{0x00, 0x01, 0x00, 0x02, 0x00, 0x03};
    const valtype amount_scriptpubkey{0x00, 0x01, 0x00, 0x10, 0x0c, 0x00};
    const valtype sequence{0x00, 0x01, 0x00, 0x10, 0x20, 0x00};
    const valtype tapscript{0x00, 0x01, 0x04, 0x00, 0x00, 0x00};
    const valtype codesep_position{0x00, 0x01, 0x80, 0x00, 0x00, 0x00};

    CScript script;
    valtype sighash_prefix{TaggedHashPrefix("TapSighash")};
    sighash_prefix.push_back(0x00); // epoch
    sighash_prefix.push_back(SIGHASH_ANYPREVOUT_ALL);
    script << sighash_prefix;

    const auto append_value{[&](const valtype& selector) {
        script << selector << OP_TX << OP_CAT;
    }};
    const auto append_hash{[&](const valtype& selector) {
        script << selector << OP_TX << OP_SHA256 << OP_CAT;
    }};

    append_value(globals);
    append_hash(outputs);
    script << valtype{0x02} << OP_CAT; // script-path spend without annex
    append_value(amount_scriptpubkey);
    append_value(sequence);

    valtype tapleaf_prefix{TaggedHashPrefix("TapLeaf")};
    tapleaf_prefix.push_back(TAPROOT_LEAF_TAPSCRIPT_V2);
    script << tapleaf_prefix << tapscript << OP_TX << OP_CAT << OP_SHA256 << OP_CAT;
    script << valtype{0x01} << OP_CAT; // BIP 118 key version
    append_value(codesep_position);
    script << OP_SHA256 << pubkey << OP_CHECKSIGFROMSTACK;

    CMutableTransaction mutable_tx;
    mutable_tx.version = 2;
    mutable_tx.nLockTime = 500'000;
    mutable_tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 3}, CScript{}, 0xfffffffd);
    mutable_tx.vout.emplace_back(119'000, CScript{} << OP_TRUE);
    const CTransaction original_tx{mutable_tx};
    const std::vector<CTxOut> spent_outputs{
        CTxOut{120'000, CScript{} << OP_1 << pubkey},
    };
    BOOST_REQUIRE_EQUAL(GetSerializeSize(spent_outputs[0].scriptPubKey), 35);

    HashWriter outputs_writer;
    for (const CTxOut& output : original_tx.vout)
        outputs_writer << output;
    const uint256 outputs_hash{outputs_writer.GetSHA256()};
    const uint256 tapleaf_hash{
        (HashWriter{HASHER_TAPLEAF} << TAPROOT_LEAF_TAPSCRIPT_V2 << script).GetSHA256()};
    const uint256 expected_sighash{
        (HashWriter{HASHER_TAPSIGHASH}
         << uint8_t{0x00} << SIGHASH_ANYPREVOUT_ALL << original_tx.version << original_tx.nLockTime
         << outputs_hash << uint8_t{0x02} << spent_outputs[0].nValue << spent_outputs[0].scriptPubKey
         << original_tx.vin[0].nSequence << tapleaf_hash << uint8_t{0x01} << uint32_t{0xffffffff})
            .GetSHA256()};
    std::array<unsigned char, 64> signature;
    BOOST_REQUIRE(key.SignSchnorr(expected_sighash, signature, /*merkle_root=*/nullptr, uint256::ZERO));

    const auto check_signature{[&](const CTransaction& tx, bool expected_valid) {
        const OpTxChecker checker{tx, 0, spent_outputs};
        ScriptExecutionData execdata;
        const valtype control_block{TestControlBlock()};
        InitOpTxContext(execdata, script, control_block);
        ValtypeStack stack{Stack{valtype{signature.begin(), signature.end()}}};
        varops::Budget budget{DEFAULT_VAROPS};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const bool success{
            EvalTapscriptV2(stack, script, SCRIPT_VERIFY_NONE, checker, execdata, budget, &error)};
        if (!expected_valid) {
            BOOST_CHECK(!success);
            BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SCHNORR_SIG);
            return;
        }
        BOOST_REQUIRE_MESSAGE(success, ScriptErrorString(error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1);
        BOOST_CHECK(stack.back() == valtype{0x01});
    }};

    check_signature(original_tx, true);

    // Replacing the current outpoint preserves the signature because neither
    // the aggregate prevouts nor the current outpoint is selected.
    mutable_tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ZERO), 7};
    check_signature(CTransaction{mutable_tx}, true);

    // The current sequence is selected explicitly and remains committed.
    --mutable_tx.vin[0].nSequence;
    check_signature(CTransaction{mutable_tx}, false);
}

BOOST_AUTO_TEST_SUITE_END()
