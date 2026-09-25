// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/reusable_macros.h>

#include <prevector.h>
#include <script/varops.h>
#include <serialize.h>
#include <streams.h>
#include <util/overflow.h>

#include <compare>
#include <ios>
#include <limits>
#include <span>

namespace {

using ScriptIterator = CScript::const_iterator;

bool SetError(ScriptError* serror, ScriptError error)
{
    if (serror) *serror = error;
    return false;
}

/** Read a canonical CompactSize that lies wholly within [pc, end). */
bool ReadMacroCompactSize(ScriptIterator& pc, ScriptIterator end, uint64_t& value)
{
    SpanReader reader{std::span{pc, end}};
    try {
        value = ReadCompactSize(reader, /*range_check=*/false);
    } catch (const std::ios_base::failure&) {
        return false;
    }
    pc = end - reader.size();
    return true;
}

/**
 * Read one instruction that lies wholly within [pc, end). OP_CALLMACRO's
 * CompactSize index is part of the instruction and is returned in index.
 */
bool ReadMacroInstruction(ScriptIterator& pc, ScriptIterator end, opcodetype& opcode, uint64_t& index)
{
    if (!GetScriptOp(pc, end, opcode, nullptr)) return false;
    return opcode != OP_CALLMACRO || ReadMacroCompactSize(pc, end, index);
}

/**
 * Decode one stored sequence: a macro body or the main script. If every
 * instruction decodes, its unrolling totals are recorded in totals.
 */
MacroDecodeResult DecodeMacroSequence(ScriptIterator pc, ScriptIterator end, const std::vector<MacroProgram::Body>& bodies,
                                      MacroTotals& totals)
{
    while (pc < end) {
        const ScriptIterator begin{pc};
        opcodetype opcode;
        uint64_t index{0};
        if (!ReadMacroInstruction(pc, end, opcode, index)) return MacroDecodeResult::MALFORMED;
        if (IsTapscriptV2OpSuccess(opcode)) return MacroDecodeResult::OP_SUCCESS;
        // Declarations exist only in the prefix, and a body may reference only
        // earlier declarations.
        if (opcode == OP_MACRO || (opcode == OP_CALLMACRO && index >= bodies.size())) {
            return MacroDecodeResult::MALFORMED;
        }
        if (opcode == OP_CALLMACRO) {
            const MacroTotals& target{bodies[index].totals};
            totals.length = SaturatingAdd(totals.length, target.length);
            totals.instructions = SaturatingAdd(totals.instructions, target.instructions);
            totals.references = SaturatingAdd(totals.references, SaturatingAdd(uint64_t{1}, target.references));
            totals.substituted = SaturatingAdd(totals.substituted, target.instructions);
        } else {
            totals.length = SaturatingAdd(totals.length, static_cast<uint64_t>(pc - begin));
            totals.instructions = SaturatingAdd(totals.instructions, uint64_t{1});
        }
    }
    return MacroDecodeResult::WELL_FORMED;
}

} // namespace

MacroDecodeResult DecodeTapscriptV2(MacroProgram& program)
{
    ScriptIterator pc{program.script.begin()};
    const ScriptIterator end{program.script.end()};
    while (pc != end && *pc == OP_MACRO) {
        ++pc;
        uint64_t body_length;
        if (!ReadMacroCompactSize(pc, end, body_length) || body_length > static_cast<uint64_t>(end - pc)) {
            return MacroDecodeResult::MALFORMED;
        }
        const ScriptIterator body_end{pc + static_cast<CScript::difference_type>(body_length)};
        MacroTotals totals;
        // The body's reference limit is its own index: the declarations read so far.
        if (const auto result{DecodeMacroSequence(pc, body_end, program.bodies, totals)};
            result != MacroDecodeResult::WELL_FORMED) {
            return result;
        }
        program.bodies.push_back({pc, body_end, totals});
        pc = body_end;
    }
    program.main_begin = pc;
    return DecodeMacroSequence(pc, end, program.bodies, program.main_totals);
}

bool UnrollTapscriptV2(const MacroProgram& program, varops::Budget& varops_budget, CScript& unrolled, ScriptError* serror)
{
    const MacroTotals& totals{program.main_totals};
    if (totals.length > MAX_TAPSCRIPT_V2_UNROLLED_SIZE) return SetError(serror, SCRIPT_ERR_SCRIPT_SIZE);

    // Instructions of the main script are funded by their weight; substituted
    // instructions and visited references are not. With declarations, the
    // unrolled script is built as a new value.
    const uint64_t units{SaturatingAdd(totals.substituted, totals.references)};
    const uint64_t script_charge{program.bodies.empty() ? 0 : varops::WriteCost(totals.length)};
    if (units > (std::numeric_limits<uint64_t>::max() - script_charge) / varops::BaseCost()) {
        return SetError(serror, SCRIPT_ERR_VAROP_COUNT);
    }
    const uint64_t charge{units * varops::BaseCost() + script_charge};
    if (!varops_budget.Spend(charge)) return SetError(serror, SCRIPT_ERR_VAROP_COUNT);

    unrolled.clear();
    // Without declarations the unrolled script is the committed script itself.
    if (program.bodies.empty()) return true;
    unrolled.reserve(totals.length);
    struct Frame {
        ScriptIterator pc;
        ScriptIterator end;
    };
    // References go only to earlier declarations, so the frame stack is at most
    // one deeper than the number of declarations.
    std::vector<Frame> frames{{program.main_begin, program.script.end()}};
    while (!frames.empty()) {
        Frame& frame{frames.back()};
        if (frame.pc == frame.end) {
            frames.pop_back();
            continue;
        }
        const ScriptIterator begin{frame.pc};
        opcodetype opcode;
        uint64_t index{0};
        // Static decoding has validated every instruction and reference.
        if (!ReadMacroInstruction(frame.pc, frame.end, opcode, index) ||
            (opcode == OP_CALLMACRO && index >= program.bodies.size())) {
            return SetError(serror, SCRIPT_ERR_BAD_OPCODE);
        }
        if (opcode == OP_CALLMACRO) {
            const auto& body{program.bodies[index]};
            frames.push_back({body.begin, body.end});
            continue;
        }
        unrolled.insert(unrolled.end(), begin, frame.pc);
    }
    return true;
}
