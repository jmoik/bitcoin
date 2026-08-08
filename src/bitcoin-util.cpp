// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/license_info.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <streams.h>
#include <univalue.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("grind", "Perform proof of work on hex header string");
    argsman.AddCommand("getchainparams", "Get hardcoded parameters for the selected chain");
    argsman.AddCommand("evalscript", "Evaluate a standalone Tapscript v2 script from a JSON request on standard input");

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " bitcoin-util utility version " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The bitcoin-util tool provides bitcoin related functionality that does not rely on the ability to access a running node. Available [commands] are listed below.\n"
                "\n"
                "Usage:  bitcoin-util [options] [command]\n"
                "or:     bitcoin-util [options] grind <hex-block-header>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static void grind_task(uint32_t nBits, CBlockHeader header, uint32_t offset, uint32_t step, std::atomic<bool>& found, uint32_t& proposed_nonce)
{
    arith_uint256 target;
    bool neg, over;
    target.SetCompact(nBits, &neg, &over);
    if (target == 0 || neg || over) return;
    header.nNonce = offset;

    uint32_t finish = std::numeric_limits<uint32_t>::max() - step;
    finish = finish - (finish % step) + offset;

    while (!found && header.nNonce < finish) {
        const uint32_t next = (finish - header.nNonce < 5000*step) ? finish : header.nNonce + 5000*step;
        do {
            if (UintToArith256(header.GetHash()) <= target) {
                if (!found.exchange(true)) {
                    proposed_nonce = header.nNonce;
                }
                return;
            }
            header.nNonce += step;
        } while(header.nNonce != next);
    }
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1) {
        strPrint = "Must specify block header to grind";
        return EXIT_FAILURE;
    }

    CBlockHeader header;
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    uint32_t nBits = header.nBits;
    std::atomic<bool> found{false};
    uint32_t proposed_nonce{};

    std::vector<std::thread> threads;
    int n_tasks = std::max(1u, std::thread::hardware_concurrency());
    threads.reserve(n_tasks);
    for (int i = 0; i < n_tasks; ++i) {
        threads.emplace_back(grind_task, nBits, header, i, n_tasks, std::ref(found), std::ref(proposed_nonce));
    }
    for (auto& t : threads) {
        t.join();
    }
    if (found) {
        header.nNonce = proposed_nonce;
    } else {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static int GetChainParams(const std::vector<std::string>& args, std::string& strPrint)
{
    if (!args.empty()) {
        strPrint = "getchainparams does not take arguments";
        return EXIT_FAILURE;
    }

    const auto& params = Params();
    const auto& consensus = params.GetConsensus();

    UniValue result{UniValue::VOBJ};
    result.pushKV("chain", params.GetChainTypeString());
    result.pushKV("test_chain", params.IsTestChain());
    result.pushKV("genesis", HexStr(consensus.hashGenesisBlock));
    result.pushKV("subsidy_halving_interval", consensus.nSubsidyHalvingInterval);

    if (consensus.signet_blocks) {
        UniValue signet{UniValue::VOBJ};
        signet.pushKV("challenge", HexStr(consensus.signet_challenge));
        result.pushKV("signet", signet);
    }

    {
        UniValue pow{UniValue::VOBJ};
        pow.pushKV("limit", consensus.powLimit.ToString());
        if (!consensus.fPowNoRetargeting) {
            pow.pushKV("target_spacing", TicksSeconds(consensus.PowTargetSpacing()));
            pow.pushKV("difficulty_retarget_interval", consensus.DifficultyAdjustmentInterval());
            std::string mindiff_blocks = (consensus.fPowAllowMinDifficultyBlocks ?
                  (consensus.enforce_BIP94 ? "bip94" : "yes") : "no");
            pow.pushKV("mindiff_blocks", mindiff_blocks);
        }
        result.pushKV("pow", pow);
    }

    {
        UniValue net{UniValue::VOBJ};
        net.pushKV("default_port", params.GetDefaultPort());
        net.pushKV("magic", HexStr(params.MessageStart()));
        UniValue dns{UniValue::VARR};
        for (const auto& seed : params.DNSSeeds()) {
            dns.push_back(seed);
        }
        net.pushKV("dns_seeds", dns);
        result.pushKV("net", net);
    }

    {
        UniValue addr{UniValue::VOBJ};
        addr.pushKV("bech32_hrp", params.Bech32HRP());
        result.pushKV("addresses", addr);
    }

    strPrint = result.write(/*prettyIndent=*/2);
    return EXIT_SUCCESS;
}

static const UniValue& RequiredEvalScriptField(const UniValue& request, const std::string& name)
{
    if (!request.exists(name)) {
        throw std::runtime_error(strprintf("Missing required field \"%s\"", name));
    }
    return request[name];
}

static std::vector<unsigned char> ParseEvalScriptHex(const UniValue& value, const std::string& name)
{
    if (!value.isStr()) {
        throw std::runtime_error(strprintf("Field \"%s\" must be a hex string", name));
    }
    const std::string& hex{value.get_str()};
    if (!hex.empty() && !IsHex(hex)) {
        throw std::runtime_error(strprintf("Field \"%s\" is not valid hex", name));
    }
    return ParseHex(hex);
}

static int EvalScriptCommand(const std::vector<std::string>& args, std::string& strPrint)
{
    if (!args.empty()) {
        throw std::runtime_error("evalscript reads one JSON request from standard input and takes no arguments");
    }

    const std::string input{std::istreambuf_iterator<char>{std::cin}, std::istreambuf_iterator<char>()};
    UniValue request;
    if (!request.read(input) || !request.isObject()) {
        throw std::runtime_error("evalscript standard input must be one JSON object");
    }

    const UniValue& protocol{RequiredEvalScriptField(request, "protocol")};
    if (!protocol.isNum() || protocol.getInt<int>() != 1) {
        throw std::runtime_error("Field \"protocol\" must be 1");
    }
    const UniValue& sigversion{RequiredEvalScriptField(request, "sigversion")};
    if (!sigversion.isStr() || sigversion.get_str() != "tapscript_v2") {
        throw std::runtime_error("Field \"sigversion\" must be \"tapscript_v2\"");
    }

    const auto script_bytes{ParseEvalScriptHex(RequiredEvalScriptField(request, "script"), "script")};
    const CScript script{script_bytes.begin(), script_bytes.end()};

    const UniValue& stack_value{RequiredEvalScriptField(request, "stack")};
    if (!stack_value.isArray()) {
        throw std::runtime_error("Field \"stack\" must be an array of hex strings");
    }
    std::vector<valtype> initial_stack;
    initial_stack.reserve(stack_value.size());
    for (const UniValue& item : stack_value.getValues()) {
        initial_stack.push_back(ParseEvalScriptHex(item, "stack item"));
    }

    const UniValue& budget_value{RequiredEvalScriptField(request, "varops_budget")};
    if (!budget_value.isNum()) {
        throw std::runtime_error("Field \"varops_budget\" must be an unsigned integer");
    }
    const uint64_t budget_amount{budget_value.getInt<uint64_t>()};

    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget budget{budget_amount};
    ValtypeStack stack{initial_stack};
    bool success{false};

    const std::optional<bool> op_success{
        CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    if (op_success.has_value()) {
        success = *op_success;
    } else if (stack.size() > MAX_TAPSCRIPT_V2_STACK_SIZE) {
        error = SCRIPT_ERR_STACK_SIZE;
    } else if (stack.GetTotalSize() > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE) {
        error = SCRIPT_ERR_TOTAL_STACK_SIZE;
    } else if (stack.GetMaxElementSize() > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) {
        error = SCRIPT_ERR_STACK_ELEMENT_SIZE;
    } else {
        bool immediate_success{false};
        success = EvalTapscriptV2(
            stack,
            script,
            SCRIPT_VERIFY_NONE,
            BaseSignatureChecker{},
            execdata,
            budget,
            &error,
            &immediate_success);
        if (success && !immediate_success) {
            success = CheckTapscriptV2ScriptResult(stack, budget, &error);
        }
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("protocol", 1);
    result.pushKV("context", "standalone");
    result.pushKV("sigversion", "tapscript_v2");
    result.pushKV("success", success);
    if (success) {
        result.pushKV("error", UniValue{});
    } else {
        result.pushKV("error", ScriptErrorString(error));
    }

    UniValue final_stack{UniValue::VARR};
    for (const valtype& item : stack.GetStack()) {
        final_stack.push_back(HexStr(item));
    }
    result.pushKV("stack-after", std::move(final_stack));
    result.pushKV("varops-budget-remaining", budget.Remaining().value());

    strPrint = result.write();
    return EXIT_SUCCESS;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "getchainparams") {
            ret = GetChainParams(cmd->args, strPrint);
        } else if (cmd->command == "evalscript") {
            ret = EvalScriptCommand(cmd->args, strPrint);
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
