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

namespace reusable_macros {

/** Unrolling totals of a stored sequence, saturating at the maximum value. */
struct Totals {
    //! Serialized length after unrolling.
    uint64_t length{0};
    //! Instructions after unrolling.
    uint64_t instructions{0};
    //! References visited while unrolling, including nested ones.
    uint64_t references{0};
    //! Instructions contributed by references.
    uint64_t substituted{0};
};

/** Declarations and main script of a statically decoded Tapleaf 0xC2 committed script. */
struct Program {
    /**
     * One declaration. A declaration can be as small as two script bytes, so
     * the record is kept compact: offsets into the committed script, whose
     * size fits in 32 bits, and totals narrowed where the limits allow.
     */
    struct Body {
        //! Byte offsets of the body in the committed script.
        uint32_t begin;
        uint32_t end;
        //! Unrolled length and instructions, saturating at the maximum value.
        //! A body reaching it unrolls past MAX_TAPLEAF_0XC2_UNROLLED_SIZE, and
        //! instructions never exceed length.
        uint32_t length;
        uint32_t instructions;
        //! References visited while unrolling, saturating at the maximum value.
        uint64_t references;
    };

    const CScript& script;
    std::vector<Body> bodies;
    CScript::const_iterator main_begin;
    Totals main_totals;

    explicit Program(const CScript& script_in) : script{script_in}, main_begin{script_in.begin()} {}
};

enum class DecodeResult {
    WELL_FORMED, //!< Every declaration and instruction decodes.
    OP_SUCCESS,  //!< An OP_SUCCESSx is reached before any decoding failure.
    MALFORMED,   //!< A decoding failure is reached before any OP_SUCCESSx.
};

/**
 * Decode a whole Tapleaf 0xC2 committed script once, in serialized order,
 * before execution. The first OP_SUCCESSx or decoding failure decides. The
 * declarations and unrolling totals of a well-formed script are recorded in
 * program.
 */
DecodeResult Decode(Program& program);

/**
 * Check the unrolled size limit, charge the unrolling and construct the
 * unrolled script of a well-formed program: the main script with every
 * reference replaced by the unrolled body it names. A script without
 * declarations is not copied and leaves unrolled empty.
 */
bool Unroll(const Program& program, varops::Budget& varops_budget, CScript& unrolled, ScriptError* serror);

} // namespace reusable_macros

#endif // BITCOIN_SCRIPT_REUSABLE_MACROS_H
