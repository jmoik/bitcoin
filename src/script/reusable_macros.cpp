// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/reusable_macros.h>

#include <prevector.h>
#include <script/varops.h>
#include <serialize.h>
#include <streams.h>
#include <util/overflow.h>

#include <algorithm>
#include <compare>
#include <cstddef>
#include <ios>
#include <limits>
#include <span>

namespace reusable_macros {

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

static_assert(sizeof(Program::Body) == 24);

uint32_t Narrow(uint64_t value)
{
    return static_cast<uint32_t>(std::min<uint64_t>(value, std::numeric_limits<uint32_t>::max()));
}

/**
 * Count the declarations whose headers fit in the script, so that decoding
 * can reserve their records exactly. Bodies are not decoded.
 */
size_t CountDeclarations(ScriptIterator pc, ScriptIterator end)
{
    size_t count{0};
    while (pc != end && *pc == OP_MACRO) {
        ++pc;
        uint64_t body_length;
        if (!ReadMacroCompactSize(pc, end, body_length) || body_length > static_cast<uint64_t>(end - pc)) break;
        pc += static_cast<CScript::difference_type>(body_length);
        ++count;
    }
    return count;
}

/**
 * Decode one stored sequence: a macro body or the main script. If every
 * instruction decodes, its unrolling totals are recorded in totals.
 */
DecodeResult DecodeMacroSequence(ScriptIterator pc, ScriptIterator end, const std::vector<Program::Body>& bodies,
                                 Totals& totals)
{
    while (pc < end) {
        const ScriptIterator begin{pc};
        opcodetype opcode;
        uint64_t index{0};
        if (!ReadMacroInstruction(pc, end, opcode, index)) return DecodeResult::MALFORMED;
        if (IsTapleaf0xC2OpSuccess(opcode)) return DecodeResult::OP_SUCCESS;
        // Declarations exist only in the prefix, and a body may reference only
        // earlier declarations.
        if (opcode == OP_MACRO || (opcode == OP_CALLMACRO && index >= bodies.size())) {
            return DecodeResult::MALFORMED;
        }
        if (opcode == OP_CALLMACRO) {
            const Program::Body& target{bodies[index]};
            totals.length = SaturatingAdd(totals.length, uint64_t{target.length});
            totals.instructions = SaturatingAdd(totals.instructions, uint64_t{target.instructions});
            totals.references = SaturatingAdd(totals.references, SaturatingAdd(uint64_t{1}, target.references));
            totals.substituted = SaturatingAdd(totals.substituted, uint64_t{target.instructions});
        } else {
            totals.length = SaturatingAdd(totals.length, static_cast<uint64_t>(pc - begin));
            totals.instructions = SaturatingAdd(totals.instructions, uint64_t{1});
        }
    }
    return DecodeResult::WELL_FORMED;
}

} // namespace

DecodeResult Decode(Program& program)
{
    const ScriptIterator script_begin{program.script.begin()};
    ScriptIterator pc{script_begin};
    const ScriptIterator end{program.script.end()};
    program.bodies.reserve(CountDeclarations(pc, end));
    while (pc != end && *pc == OP_MACRO) {
        ++pc;
        uint64_t body_length;
        if (!ReadMacroCompactSize(pc, end, body_length) || body_length > static_cast<uint64_t>(end - pc)) {
            return DecodeResult::MALFORMED;
        }
        const ScriptIterator body_end{pc + static_cast<CScript::difference_type>(body_length)};
        Totals totals;
        // The body's reference limit is its own index: the declarations read so far.
        if (const auto result{DecodeMacroSequence(pc, body_end, program.bodies, totals)};
            result != DecodeResult::WELL_FORMED) {
            return result;
        }
        program.bodies.push_back({static_cast<uint32_t>(pc - script_begin), static_cast<uint32_t>(body_end - script_begin),
                                  Narrow(totals.length), Narrow(totals.instructions), totals.references});
        pc = body_end;
    }
    program.main_begin = pc;
    return DecodeMacroSequence(pc, end, program.bodies, program.main_totals);
}

bool Unroll(const Program& program, varops::Budget& varops_budget, CScript& unrolled, ScriptError* serror)
{
    const Totals& totals{program.main_totals};
    if (totals.length > MAX_TAPLEAF_0XC2_UNROLLED_SIZE) return SetError(serror, SCRIPT_ERR_SCRIPT_SIZE);

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
    const ScriptIterator script_begin{program.script.begin()};
    // Byte offsets into the committed script, compact like Program::Body.
    struct Frame {
        uint32_t pc;
        uint32_t end;
    };
    // References go only to earlier declarations, so the frame stack is at most
    // one deeper than the number of declarations.
    std::vector<Frame> frames{{static_cast<uint32_t>(program.main_begin - script_begin), static_cast<uint32_t>(program.script.size())}};
    while (!frames.empty()) {
        Frame& frame{frames.back()};
        if (frame.pc == frame.end) {
            frames.pop_back();
            continue;
        }
        const ScriptIterator begin{script_begin + frame.pc};
        ScriptIterator pc{begin};
        opcodetype opcode;
        uint64_t index{0};
        // Static decoding has validated every instruction and reference.
        if (!ReadMacroInstruction(pc, script_begin + frame.end, opcode, index) ||
            (opcode == OP_CALLMACRO && index >= program.bodies.size())) {
            return SetError(serror, SCRIPT_ERR_BAD_OPCODE);
        }
        frame.pc = static_cast<uint32_t>(pc - script_begin);
        if (opcode == OP_CALLMACRO) {
            const auto& body{program.bodies[index]};
            frames.push_back({body.begin, body.end});
            continue;
        }
        unrolled.insert(unrolled.end(), begin, pc);
    }
    return true;
}

} // namespace reusable_macros
