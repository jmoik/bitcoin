// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_OP_TX_H
#define BITCOIN_SCRIPT_OP_TX_H

#include <primitives/transaction.h> // IWYU pragma: keep
#include <script/script_error.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>

class ValtypeStack;

namespace varops {
class Meter;
} // namespace varops

namespace op_tx {

/** Read-only transaction context exposed to transaction-introspection opcodes. */
struct TxView {
    uint32_t version;
    std::span<const CTxIn> inputs;
    std::span<const CTxOut> outputs;
    uint32_t lock_time;
    uint32_t input_index;
    std::span<const CTxOut> spent_outputs;
};

/** The script path spend running OP_TX, as its current-execution fields return it. */
struct ScriptContext {
    //! Empty without an annex.
    std::span<const unsigned char> annex;
    std::span<const unsigned char> tapscript;
    uint256 tapleaf_hash;
    std::span<const unsigned char> control_block;
    uint256 taptree_root;
    uint32_t codeseparator_pos;
};

enum class Result {
    SCRIPT_ERROR,
    NORMAL,
    IMMEDIATE_SUCCESS,
};

/**
 * Execute OP_TX after its scope operands and selector have been pushed onto
 * stack. Without tx or context, a valid selector fails. Its charges, BASE
 * included, are added to meter, and checked against the budget before the
 * results are produced (varops::Meter::Fits).
 */
Result Eval(ValtypeStack& stack, const ValtypeStack& altstack,
            const std::optional<TxView>& tx, const std::optional<ScriptContext>& context,
            varops::Meter& meter, ScriptError* serror);

} // namespace op_tx

#endif // BITCOIN_SCRIPT_OP_TX_H
