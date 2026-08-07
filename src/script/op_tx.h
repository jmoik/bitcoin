// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_SCRIPT_OP_TX_H
#define BITCOIN_SCRIPT_OP_TX_H

#include <script/script_error.h>

class BaseSignatureChecker;
class ValtypeStack;
struct ScriptExecutionData;
namespace varops {
class Budget;
} // namespace varops

enum class OpTxResult {
    ERROR,
    NORMAL,
    IMMEDIATE_SUCCESS,
};

/** Execute OP_TX after its scope operands and selector have been pushed onto stack. */
OpTxResult EvalOpTx(ValtypeStack& stack, const ValtypeStack& altstack,
                    const BaseSignatureChecker& checker, const ScriptExecutionData& execdata,
                    varops::Budget& varops_budget, ScriptError* serror);

#endif // BITCOIN_SCRIPT_OP_TX_H
