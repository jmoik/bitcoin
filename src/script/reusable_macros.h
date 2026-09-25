// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_REUSABLE_MACROS_H
#define BITCOIN_SCRIPT_REUSABLE_MACROS_H

#include <script/script.h>
#include <script/script_error.h>

#include <cstdint>
#include <vector>

namespace varops {
class Budget;
} // namespace varops

/** Unrolling totals of a stored sequence, saturating at the maximum value. */
struct MacroTotals {
    //! Serialized length after unrolling.
    uint64_t length{0};
    //! Instructions after unrolling.
    uint64_t instructions{0};
    //! References visited while unrolling, including nested ones.
    uint64_t references{0};
    //! Instructions contributed by references.
    uint64_t substituted{0};
};

/** Declarations and main script of a statically decoded Tapscript v2 committed script. */
struct MacroProgram {
    struct Body {
        CScript::const_iterator begin;
        CScript::const_iterator end;
        MacroTotals totals;
    };

    const CScript& script;
    std::vector<Body> bodies;
    CScript::const_iterator main_begin;
    MacroTotals main_totals;

    explicit MacroProgram(const CScript& script_in) : script{script_in}, main_begin{script_in.begin()} {}
};

enum class MacroDecodeResult {
    WELL_FORMED, //!< Every declaration and instruction decodes.
    OP_SUCCESS,  //!< An OP_SUCCESSx is reached before any decoding failure.
    MALFORMED,   //!< A decoding failure is reached before any OP_SUCCESSx.
};

/**
 * Decode a whole Tapscript v2 committed script once, in serialized order,
 * before execution. The first OP_SUCCESSx or decoding failure decides. The
 * declarations and unrolling totals of a well-formed script are recorded in
 * program.
 */
MacroDecodeResult DecodeTapscriptV2(MacroProgram& program);

/**
 * Check the unrolled size limit, charge the unrolling and construct the
 * unrolled script of a well-formed program: the main script with every
 * reference replaced by the unrolled body it names. A script without
 * declarations is not copied and leaves unrolled empty.
 */
bool UnrollTapscriptV2(const MacroProgram& program, varops::Budget& varops_budget, CScript& unrolled, ScriptError* serror);

#endif // BITCOIN_SCRIPT_REUSABLE_MACROS_H
