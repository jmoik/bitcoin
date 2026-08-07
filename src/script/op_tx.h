// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_OP_TX_H
#define BITCOIN_SCRIPT_OP_TX_H

#include <script/script_error.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>

class ValtypeStack;
class CTxIn;
class CTxOut;

namespace varops {
class Budget;
class Meter;
} // namespace varops

/** Read-only transaction context exposed to transaction-introspection opcodes. */
struct ScriptTransactionData {
    uint32_t version;
    std::span<const CTxIn> inputs;
    std::span<const CTxOut> outputs;
    uint32_t lock_time;
    uint32_t input_index;
    std::span<const CTxOut> spent_outputs;
};

/** The script path spend running OP_TX, as its current-execution fields return it. */
struct OpTxScriptContext {
    //! Empty without an annex.
    std::span<const unsigned char> annex;
    std::span<const unsigned char> tapscript;
    uint256 tapleaf_hash;
    std::span<const unsigned char> control_block;
    uint256 taptree_root;
    uint32_t codeseparator_pos;
};

enum class OpTxResult {
    SCRIPT_ERROR,
    NORMAL,
    IMMEDIATE_SUCCESS,
};

/**
 * Execute OP_TX after its scope operands and selector have been pushed onto
 * stack. Without tx or context, a valid selector fails. Its charges, BASE
 * included, are added to meter and prepaid from varops_budget before the
 * results are produced.
 */
OpTxResult EvalOpTx(ValtypeStack& stack, const ValtypeStack& altstack,
                    const std::optional<ScriptTransactionData>& tx, const std::optional<OpTxScriptContext>& context,
                    varops::Meter& meter, varops::Budget& varops_budget, ScriptError* serror);

/** Execute OP_TX as the only charged opcode. */
OpTxResult EvalOpTx(ValtypeStack& stack, const ValtypeStack& altstack,
                    const std::optional<ScriptTransactionData>& tx, const std::optional<OpTxScriptContext>& context,
                    varops::Budget& varops_budget, ScriptError* serror);

#endif // BITCOIN_SCRIPT_OP_TX_H
