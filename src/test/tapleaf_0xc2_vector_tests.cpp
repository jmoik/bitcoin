// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Runs the BIP 441 test vectors: one file per BIP of the Tapleaf 0xC2 package,
// copied unchanged from the bip-0441 directory of the BIPs repository.

#include <addresstype.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/signingprovider.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <streams.h>
#include <test/data/tapleaf_0xc2.json.h>
#include <test/data/varops.json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;
using Stack = std::vector<valtype>;

//! Consensus rules with Tapleaf 0xC2 active; policy rules are not part of the vectors.
constexpr script_verify_flags CONSENSUS_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG |
                                              SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                              SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_TAPROOT |
                                              SCRIPT_VERIFY_TAPLEAF_0XC2};

//! Error names are the ScriptError identifiers without the SCRIPT_ERR_ prefix.
constexpr auto SCRIPT_ERRORS{std::to_array<std::pair<ScriptError, std::string_view>>({
#define SCRIPT_ERROR_NAME(name) {SCRIPT_ERR_##name, #name}
    SCRIPT_ERROR_NAME(UNKNOWN_ERROR), SCRIPT_ERROR_NAME(EVAL_FALSE), SCRIPT_ERROR_NAME(OP_RETURN),
    SCRIPT_ERROR_NAME(SCRIPTNUM), SCRIPT_ERROR_NAME(SCRIPT_SIZE), SCRIPT_ERROR_NAME(PUSH_SIZE),
    SCRIPT_ERROR_NAME(OP_COUNT), SCRIPT_ERROR_NAME(STACK_SIZE), SCRIPT_ERROR_NAME(SIG_COUNT),
    SCRIPT_ERROR_NAME(PUBKEY_COUNT), SCRIPT_ERROR_NAME(VERIFY), SCRIPT_ERROR_NAME(EQUALVERIFY),
    SCRIPT_ERROR_NAME(CHECKMULTISIGVERIFY), SCRIPT_ERROR_NAME(CHECKSIGVERIFY), SCRIPT_ERROR_NAME(NUMEQUALVERIFY),
    SCRIPT_ERROR_NAME(BAD_OPCODE), SCRIPT_ERROR_NAME(DISABLED_OPCODE), SCRIPT_ERROR_NAME(INVALID_STACK_OPERATION),
    SCRIPT_ERROR_NAME(INVALID_ALTSTACK_OPERATION), SCRIPT_ERROR_NAME(UNBALANCED_CONDITIONAL),
    SCRIPT_ERROR_NAME(NEGATIVE_LOCKTIME), SCRIPT_ERROR_NAME(UNSATISFIED_LOCKTIME), SCRIPT_ERROR_NAME(SIG_HASHTYPE),
    SCRIPT_ERROR_NAME(SIG_DER), SCRIPT_ERROR_NAME(MINIMALDATA), SCRIPT_ERROR_NAME(SIG_PUSHONLY),
    SCRIPT_ERROR_NAME(SIG_HIGH_S), SCRIPT_ERROR_NAME(SIG_NULLDUMMY), SCRIPT_ERROR_NAME(PUBKEYTYPE),
    SCRIPT_ERROR_NAME(CLEANSTACK), SCRIPT_ERROR_NAME(MINIMALIF), SCRIPT_ERROR_NAME(SIG_NULLFAIL),
    SCRIPT_ERROR_NAME(WITNESS_PROGRAM_WRONG_LENGTH), SCRIPT_ERROR_NAME(WITNESS_PROGRAM_WITNESS_EMPTY),
    SCRIPT_ERROR_NAME(WITNESS_PROGRAM_MISMATCH), SCRIPT_ERROR_NAME(WITNESS_MALLEATED),
    SCRIPT_ERROR_NAME(WITNESS_MALLEATED_P2SH), SCRIPT_ERROR_NAME(WITNESS_UNEXPECTED),
    SCRIPT_ERROR_NAME(WITNESS_PUBKEYTYPE), SCRIPT_ERROR_NAME(SCHNORR_SIG_SIZE), SCRIPT_ERROR_NAME(SCHNORR_SIG_HASHTYPE),
    SCRIPT_ERROR_NAME(SCHNORR_SIG), SCRIPT_ERROR_NAME(TAPROOT_WRONG_CONTROL_SIZE),
    SCRIPT_ERROR_NAME(TAPSCRIPT_VALIDATION_WEIGHT), SCRIPT_ERROR_NAME(TAPSCRIPT_CHECKMULTISIG),
    SCRIPT_ERROR_NAME(TAPSCRIPT_MINIMALIF), SCRIPT_ERROR_NAME(TAPSCRIPT_EMPTY_PUBKEY),
    SCRIPT_ERROR_NAME(OP_CODESEPARATOR), SCRIPT_ERROR_NAME(SIG_FINDANDDELETE), SCRIPT_ERROR_NAME(DIVIDE_BY_ZERO),
    SCRIPT_ERROR_NAME(SUB_UNDERFLOW), SCRIPT_ERROR_NAME(VAROP_COUNT), SCRIPT_ERROR_NAME(TOTAL_STACK_SIZE),
    SCRIPT_ERROR_NAME(STACK_ELEMENT_SIZE), SCRIPT_ERROR_NAME(HASH_OPERAND_SIZE),
#undef SCRIPT_ERROR_NAME
})};

std::string ErrorName(ScriptError error)
{
    const auto it{std::ranges::find(SCRIPT_ERRORS, error, &std::pair<ScriptError, std::string_view>::first)};
    if (it == SCRIPT_ERRORS.end()) throw std::invalid_argument("unnamed script error " + ScriptErrorString(error));
    return std::string{it->second};
}

// ---------------------------------------------------------------------------
// Hex, stacks and scripts. "XX{n}" is n bytes XX.

valtype ParseHexRuns(std::string_view input)
{
    if (input.starts_with("0x")) input.remove_prefix(2);
    valtype result;
    while (!input.empty()) {
        const size_t open{input.find('{')};
        const std::string_view literal{input.substr(0, open)};
        if (!IsHex(literal) && !literal.empty()) throw std::invalid_argument("invalid hex " + std::string{literal});
        const valtype bytes{ParseHex(literal)};
        result.insert(result.end(), bytes.begin(), bytes.end());
        if (open == std::string_view::npos) break;
        const size_t close{input.find('}', open)};
        if (close == std::string_view::npos || result.empty()) throw std::invalid_argument("invalid repetition");
        const std::optional<uint64_t> count{ToIntegral<uint64_t>(input.substr(open + 1, close - open - 1))};
        if (!count || *count == 0) throw std::invalid_argument("invalid repetition count");
        result.insert(result.end(), *count - 1, result.back());
        input.remove_prefix(close + 1);
    }
    return result;
}

std::string HexRuns(std::span<const unsigned char> bytes)
{
    static constexpr size_t MIN_RUN{16};
    std::string result;
    for (size_t i{0}; i < bytes.size();) {
        size_t run{1};
        while (i + run < bytes.size() && bytes[i + run] == bytes[i]) ++run;
        if (run >= MIN_RUN) {
            result += HexStr(bytes.subspan(i, 1)) + "{" + util::ToString(run) + "}";
        } else {
            result += HexStr(bytes.subspan(i, run));
        }
        i += run;
    }
    return result;
}

Stack ParseStack(const UniValue& values)
{
    Stack stack;
    for (const UniValue& value : values.getValues()) {
        if (value.isObject()) {
            const valtype element{ParseHexRuns(value["element"].get_str())};
            stack.insert(stack.end(), value["count"].getInt<uint64_t>(), element);
        } else {
            stack.push_back(ParseHexRuns(value.get_str()));
        }
    }
    return stack;
}

UniValue StackJson(const Stack& stack)
{
    static constexpr size_t MIN_REPEAT{16};
    UniValue result{UniValue::VARR};
    for (size_t i{0}; i < stack.size();) {
        size_t run{1};
        while (i + run < stack.size() && stack[i + run] == stack[i]) ++run;
        if (run >= MIN_REPEAT) {
            UniValue repeated{UniValue::VOBJ};
            repeated.pushKV("element", HexRuns(stack[i]));
            repeated.pushKV("count", run);
            result.push_back(std::move(repeated));
            i += run;
        } else {
            result.push_back(HexRuns(stack[i]));
            ++i;
        }
    }
    return result;
}

const std::map<std::string, opcodetype, std::less<>>& OpcodeNames()
{
    static const auto names{[] {
        std::map<std::string, opcodetype, std::less<>> result;
        for (unsigned int code{0}; code <= 0xff; ++code) {
            const opcodetype opcode{static_cast<opcodetype>(code)};
            const std::string name{GetOpName(opcode)};
            if (name.starts_with("OP_") && name != "OP_UNKNOWN") result.emplace(name, opcode);
        }
        result.emplace("OP_0", OP_0);
        result.emplace("OP_1NEGATE", OP_1NEGATE);
        for (int n{1}; n <= 16; ++n) result.emplace("OP_" + util::ToString(n), static_cast<opcodetype>(OP_1 + n - 1));
        return result;
    }()};
    return names;
}

//! A script is a list of tokens: opcode names ("OP_ADD") and raw bytes ("0x...").
CScript ParseScript(const UniValue& tokens)
{
    CScript script;
    for (const UniValue& token_value : tokens.getValues()) {
        const std::string& token{token_value.get_str()};
        if (token.starts_with("OP_")) {
            const auto it{OpcodeNames().find(token)};
            if (it == OpcodeNames().end()) throw std::invalid_argument("unknown opcode " + token);
            script.push_back(static_cast<unsigned char>(it->second));
        } else if (token.starts_with("0x")) {
            const valtype bytes{ParseHexRuns(token)};
            script.insert(script.end(), bytes.begin(), bytes.end());
        } else {
            throw std::invalid_argument("invalid script token " + token);
        }
    }
    return script;
}

CMutableTransaction ParseTransaction(const UniValue& hex)
{
    CMutableTransaction tx;
    SpanReader{ParseHexRuns(hex.get_str())} >> TX_WITH_WITNESS(tx);
    return tx;
}

std::vector<CTxOut> ParseOutputs(const UniValue& values)
{
    std::vector<CTxOut> outputs;
    for (const UniValue& value : values.getValues()) SpanReader{ParseHexRuns(value.get_str())} >> outputs.emplace_back();
    return outputs;
}

// ---------------------------------------------------------------------------
// Groups. Each vector gives inputs; Evaluate*() computes the expected fields.

const std::map<std::string, std::vector<std::string_view>, std::less<>> RESULT_FIELDS{
    {"primitives", {"varops"}},
    {"scripts", {"final_stack", "varops", "error"}},
    {"transactions", {"budget", "varops", "error"}},
    {"signing", {"script_pubkey", "leaf_hash", "control_block", "sighash"}},
};

UniValue EvaluatePrimitive(const UniValue& vector)
{
    const std::string& name{vector["primitive"].get_str()};
    const auto arg{[&](std::string_view key) { return vector[std::string{key}].getInt<uint64_t>(); }};
    uint64_t cost;
    if (name == "BASE") {
        cost = varops::BaseCost();
    } else if (name == "READ") {
        cost = varops::ReadCost(arg("n"));
    } else if (name == "WRITE") {
        cost = varops::WriteCost(arg("n"));
    } else if (name == "ARITH") {
        cost = varops::ArithCost(arg("n"));
    } else if (name == "MOVE") {
        cost = varops::MoveCost(arg("k"));
    } else if (name == "MUL") {
        cost = varops::MulCost(arg("n"), arg("m"));
    } else if (name == "DIV") {
        cost = varops::DivCost(arg("n"), arg("m"));
    } else if (name == "HASH") {
        cost = varops::HashCost(arg("n"));
    } else if (name == "SIGCHECK") {
        cost = varops::SignatureCost();
    } else {
        throw std::invalid_argument("unknown primitive " + name);
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("varops", cost);
    return result;
}

struct Context {
    CTransaction tx;
    std::vector<CTxOut> spent_outputs;
    uint32_t input_index;
    std::optional<valtype> annex;
};

Context ParseContext(const UniValue& context)
{
    std::optional<valtype> annex;
    if (context.exists("annex")) annex = ParseHexRuns(context["annex"].get_str());
    return Context{CTransaction{ParseTransaction(context["tx"])}, ParseOutputs(context["spent_outputs"]),
                   context["input_index"].getInt<uint32_t>(), std::move(annex)};
}

//! Run a script on a stack as the Tapleaf 0xC2 script of a script-path spend.
//! With "final", the final result rule applies too, as for the witness.
UniValue RunScript(const UniValue& vector, uint64_t budget)
{
    const CScript script{ParseScript(vector["script"])};
    ValtypeStack stack{vector.exists("stack") ? ParseStack(vector["stack"]) : Stack{}};
    const bool final{vector.exists("final") && vector["final"].get_bool()};

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xffffffff;
    std::optional<Context> context;
    std::optional<PrecomputedTransactionData> txdata;
    std::optional<GenericTransactionSignatureChecker<CTransaction>> tx_checker;
    const BaseSignatureChecker no_transaction;
    if (vector.exists("context")) {
        context.emplace(ParseContext(vector["context"]));
        txdata.emplace();
        txdata->Init(context->tx, std::vector<CTxOut>{context->spent_outputs}, /*force=*/true);
        tx_checker.emplace(&context->tx, context->input_index, context->spent_outputs.at(context->input_index).nValue,
                           *txdata, MissingDataBehavior::FAIL);
        if (context->annex) {
            execdata.m_annex_present = true;
            execdata.m_annex_hash = (HashWriter{} << *context->annex).GetSHA256();
        }
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_0XC2, script);
    }
    const BaseSignatureChecker& checker{tx_checker ? static_cast<const BaseSignatureChecker&>(*tx_checker) : no_transaction};

    varops::Budget varops_budget{budget};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    bool immediate_success{false};
    bool ok{EvalTapleaf0xC2(stack, script, CONSENSUS_FLAGS, checker, execdata, varops_budget, &error, &immediate_success)};
    if (ok && final && !immediate_success) ok = CheckTapleaf0xC2ScriptResult(stack, &error);

    UniValue result{UniValue::VOBJ};
    if (!ok) {
        result.pushKV("error", ErrorName(error));
        return result;
    }
    if (!final) result.pushKV("final_stack", StackJson(stack.GetStack()));
    result.pushKV("varops", budget - varops_budget.Remaining());
    return result;
}

//! A script that uses varops must also fail with one varop less: the budget
//! limits exactly what the script is charged.
UniValue EvaluateScript(const UniValue& vector)
{
    const uint64_t budget{vector.exists("budget") ? vector["budget"].getInt<uint64_t>() : std::numeric_limits<uint64_t>::max()};
    UniValue result{RunScript(vector, budget)};
    if (result.exists("varops") && result["varops"].getInt<uint64_t>() > 0) {
        const UniValue short_budget{RunScript(vector, result["varops"].getInt<uint64_t>() - 1)};
        BOOST_CHECK_MESSAGE(short_budget.exists("error") && short_budget["error"].get_str() == "VAROP_COUNT",
                            "one varop less gives " << short_budget.write());
    }
    return result;
}

//! Validate every input's scripts against the transaction's shared budget.
UniValue EvaluateTransaction(const UniValue& vector)
{
    const CTransaction tx{ParseTransaction(vector["tx"])};
    const std::vector<CTxOut> spent_outputs{ParseOutputs(vector["spent_outputs"])};
    if (spent_outputs.size() != tx.vin.size()) throw std::invalid_argument("one spent output per input");
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent_outputs}, /*force=*/true);
    const uint64_t budget{GetTransactionVaropsBudget(tx, spent_outputs)};
    varops::Budget varops_budget{budget};

    UniValue result{UniValue::VOBJ};
    result.pushKV("budget", budget);
    for (size_t i{0}; i < tx.vin.size(); ++i) {
        const TransactionSignatureChecker checker{&tx, static_cast<unsigned int>(i), spent_outputs[i].nValue, txdata,
                                                  MissingDataBehavior::FAIL};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        if (!VerifyScript(tx.vin[i].scriptSig, spent_outputs[i].scriptPubKey, &tx.vin[i].scriptWitness,
                          CONSENSUS_FLAGS, checker, &error, varops_budget)) {
            result.pushKV("error", ErrorName(error));
            return result;
        }
    }
    result.pushKV("varops", budget - varops_budget.Remaining());
    return result;
}

//! A Taproot output with Tapleaf 0xC2 leaves: its scriptPubKey, the spent
//! leaf's hash and control block, and the signature message hash of a spend.
UniValue EvaluateSigning(const UniValue& vector)
{
    TaprootBuilder builder;
    std::vector<std::pair<CScript, uint8_t>> leaves;
    for (const UniValue& leaf : vector["leaves"].getValues()) {
        const CScript script{ParseScript(leaf["script"])};
        const uint8_t version{ParseHexRuns(leaf["version"].get_str()).at(0)};
        builder.Add(leaf["depth"].getInt<int>(), script, version, /*track=*/true);
        leaves.emplace_back(script, version);
    }
    const valtype internal_key_bytes{ParseHexRuns(vector["internal_key"].get_str())};
    builder.Finalize(XOnlyPubKey{internal_key_bytes});
    const auto& [leaf_script, leaf_version]{leaves.at(vector["spend_leaf"].getInt<size_t>())};
    const valtype leaf_bytes{leaf_script.begin(), leaf_script.end()};
    const TaprootSpendData spend_data{builder.GetSpendData()};
    const auto& control_blocks{spend_data.scripts.at({leaf_bytes, leaf_version})};

    const Context context{ParseContext(vector["context"])};
    PrecomputedTransactionData txdata;
    txdata.Init(context.tx, std::vector<CTxOut>{context.spent_outputs}, /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = context.annex.has_value();
    if (context.annex) execdata.m_annex_hash = (HashWriter{} << *context.annex).GetSHA256();
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = ComputeTapleafHash(leaf_version, leaf_script);
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = vector.exists("codesep_pos") ? vector["codesep_pos"].getInt<uint32_t>() : 0xffffffff;
    uint256 sighash;
    const uint8_t hash_type{static_cast<uint8_t>(vector["hash_type"].getInt<int>())};
    if (!SignatureHashSchnorr(sighash, execdata, context.tx, context.input_index, hash_type, SigVersion::TAPLEAF_0XC2,
                              txdata, MissingDataBehavior::FAIL)) {
        throw std::invalid_argument("no signature message for this hash type");
    }

    UniValue result{UniValue::VOBJ};
    const CScript script_pubkey{GetScriptForDestination(builder.GetOutput())};
    result.pushKV("script_pubkey", HexStr(script_pubkey));
    result.pushKV("leaf_hash", HexStr(execdata.m_tapleaf_hash));
    result.pushKV("control_block", HexStr(*control_blocks.begin()));
    result.pushKV("sighash", HexStr(sighash));
    return result;
}

UniValue Evaluate(std::string_view group, const UniValue& vector)
{
    if (group == "primitives") return EvaluatePrimitive(vector);
    if (group == "scripts") return EvaluateScript(vector);
    if (group == "transactions") return EvaluateTransaction(vector);
    if (group == "signing") return EvaluateSigning(vector);
    throw std::invalid_argument("unknown group " + std::string{group});
}

bool SameResult(std::string_view field, const UniValue& expected, const UniValue& actual)
{
    if (field == "final_stack") return ParseStack(expected) == ParseStack(actual);
    return expected.write() == actual.write();
}

//! Check every vector of a file, or, with fill, replace its result fields.
UniValue RunFile(UniValue file, bool fill)
{
    for (const auto& [group, fields] : RESULT_FIELDS) {
        if (!file.exists(group)) continue;
        UniValue categories{UniValue::VARR};
        for (const UniValue& category : file[group].getValues()) {
            const std::string& category_name{category["category"].get_str()};
            UniValue vectors{UniValue::VARR};
            for (const UniValue& vector : category["vectors"].getValues()) {
                BOOST_TEST_CONTEXT(group << " / " << category_name << " / " << vector["comment"].get_str())
                {
                    const UniValue actual{Evaluate(group, vector)};
                    UniValue updated{UniValue::VOBJ};
                    for (const std::string& key : vector.getKeys()) {
                        if (std::ranges::find(fields, key) == fields.end()) updated.pushKV(key, vector[key]);
                    }
                    for (const std::string_view field : fields) {
                        const std::string key{field};
                        if (fill) {
                            if (actual.exists(key)) updated.pushKV(key, actual[key]);
                            continue;
                        }
                        BOOST_CHECK_MESSAGE(vector.exists(key) == actual.exists(key),
                                            key << (actual.exists(key) ? " expected " + actual[key].write() : " not expected"));
                        if (vector.exists(key) && actual.exists(key)) {
                            BOOST_CHECK_MESSAGE(SameResult(field, vector[key], actual[key]),
                                                key << " is " << actual[key].write().substr(0, 200));
                        }
                    }
                    vectors.push_back(std::move(updated));
                }
            }
            UniValue updated_category{UniValue::VOBJ};
            updated_category.pushKV("category", category_name);
            updated_category.pushKV("vectors", std::move(vectors));
            categories.push_back(std::move(updated_category));
        }
        file.pushKV(group, std::move(categories));
    }
    return file;
}

void RunVectors(std::string_view name, std::string_view embedded)
{
    // With BIP441_VECTORS_FILL=<dir>, read <dir>/<name>.json, compute its
    // result fields and write <dir>/<name>.filled.json instead of checking.
    if (const char* dir{std::getenv("BIP441_VECTORS_FILL")}) {
        const std::string path{std::string{dir} + "/" + std::string{name}};
        std::ifstream in{path + ".json"};
        const std::string text{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
        UniValue file;
        if (!file.read(text)) throw std::runtime_error("cannot read " + path + ".json");
        std::ofstream{path + ".filled.json"} << RunFile(std::move(file), /*fill=*/true).write(1);
        return;
    }
    UniValue file;
    BOOST_REQUIRE(file.read(embedded));
    RunFile(std::move(file), /*fill=*/false);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(tapleaf_0xc2_vector_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(varops) { RunVectors("varops", json_tests::varops); }
BOOST_AUTO_TEST_CASE(tapleaf_0xc2) { RunVectors("tapleaf_0xc2", json_tests::tapleaf_0xc2); }

BOOST_AUTO_TEST_SUITE_END()
