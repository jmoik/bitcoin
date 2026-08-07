// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/op_tx.h>

#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <util/check.h>
#include <util/overflow.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace {

// Selector byte 1: output format and transaction-wide fields.
constexpr uint8_t COLLATE{0x01};
constexpr uint8_t TX_VERSION{0x02};
constexpr uint8_t TX_LOCKTIME{0x04};
constexpr uint8_t TX_WEIGHT{0x08};
constexpr uint8_t INPUT_TOTAL_COUNT{0x10};
constexpr uint8_t INPUT_TOTAL_AMOUNT{0x20};
constexpr uint8_t OUTPUT_TOTAL_COUNT{0x40};
constexpr uint8_t OUTPUT_TOTAL_AMOUNT{0x80};

// Selector byte 2: current-execution fields.
constexpr uint8_t CURRENT_INPUT_INDEX{0x01};
constexpr uint8_t CURRENT_TAPROOT_ANNEX{0x02};
constexpr uint8_t CURRENT_TAPSCRIPT{0x04};
constexpr uint8_t CURRENT_TAPLEAF_HASH{0x08};
constexpr uint8_t CURRENT_CONTROL_BLOCK{0x10};
constexpr uint8_t CURRENT_INTERNAL_KEY{0x20};
constexpr uint8_t CURRENT_TAPTREE_ROOT{0x40};
constexpr uint8_t CURRENT_CODESEPARATOR_POSITION{0x80};

// Selector byte 3: the input scope in the high nibble, the output scope in the low one.
constexpr uint8_t SCOPE_NONE{0x00};
constexpr uint8_t SCOPE_CURRENT{0x01};
constexpr uint8_t SCOPE_ALL{0x02};
constexpr uint8_t SCOPE_SINGLE{0x03};
constexpr uint8_t SCOPE_RANGE{0x04};

// Selector byte 4: input fields.
constexpr uint8_t INPUT_PREVOUT_TXID{0x01};
constexpr uint8_t INPUT_PREVOUT_INDEX{0x02};
constexpr uint8_t INPUT_PREVOUT_AMOUNT{0x04};
constexpr uint8_t INPUT_PREVOUT_SCRIPTPUBKEY{0x08};
constexpr uint8_t INPUT_SCRIPTSIG{0x10};
constexpr uint8_t INPUT_SEQUENCE{0x20};
constexpr uint8_t INPUT_WITNESS_ITEM_COUNT{0x40};
constexpr uint8_t INPUT_WITNESS_ITEMS{0x80};

// Selector byte 5: output fields.
constexpr uint8_t OUTPUT_AMOUNT{0x01};
constexpr uint8_t OUTPUT_SCRIPTPUBKEY{0x02};
constexpr uint8_t OUTPUT_FIELDS{OUTPUT_AMOUNT | OUTPUT_SCRIPTPUBKEY};

struct Scope {
    uint8_t kind;
    uint32_t start{0};
    uint32_t count{0};
};

struct Selector {
    uint8_t globals;       //!< Byte 1, including COLLATE
    uint8_t context;       //!< Byte 2
    uint8_t input_fields;  //!< Byte 4
    uint8_t output_fields; //!< Byte 5
    Scope inputs;
    Scope outputs;
};

//! How a selected value is pushed on its own, and how COLLATE encodes it.
enum class ValueEncoding : uint8_t {
    UINT32,         //!< Minimal number; uint32_le when collated.
    UINT64,         //!< Minimal number; uint64_le when collated.
    FIXED_BYTES,    //!< Raw bytes in both formats.
    VAR_BYTES,      //!< Raw bytes; CompactSize length prefix when collated.
    COLLATED_COUNT, //!< Witness item count: CompactSize when collated, never pushed on its own.
};

struct ResultValue {
    ValueEncoding encoding;
    uint64_t number{0};
    std::span<const unsigned char> bytes{};

    static ResultValue Uint32(uint32_t value) { return {ValueEncoding::UINT32, value, {}}; }
    static ResultValue Uint64(uint64_t value) { return {ValueEncoding::UINT64, value, {}}; }
    static ResultValue FixedBytes(std::span<const unsigned char> value) { return {ValueEncoding::FIXED_BYTES, 0, value}; }
    static ResultValue VarBytes(std::span<const unsigned char> value) { return {ValueEncoding::VAR_BYTES, 0, value}; }
    static ResultValue CollatedCount(uint64_t value) { return {ValueEncoding::COLLATED_COUNT, value, {}}; }

    bool IsNumeric() const { return encoding == ValueEncoding::UINT32 || encoding == ValueEncoding::UINT64; }
};

OpTxResult SetError(ScriptError* serror, ScriptError error)
{
    if (serror) *serror = error;
    return OpTxResult::SCRIPT_ERROR;
}

//! Parse a version 0 selector.
std::optional<Selector> ParseSelector(std::span<const unsigned char> bytes)
{
    if (bytes.size() != 6) return std::nullopt;
    const Selector selector{
        .globals = bytes[1],
        .context = bytes[2],
        .input_fields = bytes[4],
        .output_fields = bytes[5],
        .inputs = {.kind = static_cast<uint8_t>(bytes[3] >> 4)},
        .outputs = {.kind = static_cast<uint8_t>(bytes[3] & 0x0f)},
    };
    if (selector.inputs.kind > SCOPE_RANGE || selector.outputs.kind > SCOPE_RANGE) return std::nullopt;
    if ((selector.output_fields & ~OUTPUT_FIELDS) != 0) return std::nullopt;
    // Exactly the scopes other than NONE select fields.
    if ((selector.inputs.kind == SCOPE_NONE) != (selector.input_fields == 0)) return std::nullopt;
    if ((selector.outputs.kind == SCOPE_NONE) != (selector.output_fields == 0)) return std::nullopt;
    // At least one field must be selected; COLLATE is not a field.
    if ((selector.globals & ~COLLATE) == 0 && selector.context == 0 &&
        selector.input_fields == 0 && selector.output_fields == 0) {
        return std::nullopt;
    }
    return selector;
}

//! Read the scope operand `depth` elements below the stack top: BIP 441's
//! normalized unsigned encoding, at most four bytes.
ScriptError ReadScopeOperand(const ValtypeStack& stack, size_t depth, uint32_t& value)
{
    if (depth >= stack.size()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
    const valtype& bytes{stack.Top(depth)};
    if (bytes.size() > sizeof(value) || (!bytes.empty() && bytes.back() == 0)) return SCRIPT_ERR_TX_SELECTOR;
    value = 0;
    for (size_t i{0}; i < bytes.size(); ++i) {
        value |= uint32_t{bytes[i]} << (8 * i);
    }
    return SCRIPT_ERR_OK;
}

//! Read the operands of a SINGLE or RANGE scope, starting `depth` elements
//! below the stack top and advancing `depth` past them. A range's count lies
//! above its start.
ScriptError ReadScopeOperands(const ValtypeStack& stack, size_t& depth, Scope& scope)
{
    switch (scope.kind) {
    case SCOPE_SINGLE:
        scope.count = 1;
        return ReadScopeOperand(stack, depth++, scope.start);
    case SCOPE_RANGE:
        if (const ScriptError error{ReadScopeOperand(stack, depth++, scope.count)}; error != SCRIPT_ERR_OK) return error;
        if (const ScriptError error{ReadScopeOperand(stack, depth++, scope.start)}; error != SCRIPT_ERR_OK) return error;
        return scope.count == 0 ? SCRIPT_ERR_TX_SELECTOR : SCRIPT_ERR_OK;
    }
    return SCRIPT_ERR_OK;
}

//! Resolve CURRENT and ALL to a range, and check that the whole range exists.
bool ResolveScope(Scope& scope, uint32_t total, uint32_t current_index)
{
    switch (scope.kind) {
    case SCOPE_NONE:
        return true;
    case SCOPE_CURRENT:
        if (current_index >= total) return false;
        scope.start = current_index;
        scope.count = 1;
        return true;
    case SCOPE_ALL:
        scope.count = total;
        return true;
    case SCOPE_SINGLE:
        return scope.start < total;
    case SCOPE_RANGE:
        return scope.start < total && scope.count <= total - scope.start;
    }
    return false;
}

//! Check that the transaction is complete and that both scopes exist in it.
bool ResolveSelector(Selector& selector, const ScriptTransactionData& tx)
{
    if (tx.input_index >= tx.inputs.size() ||
        tx.spent_outputs.size() != tx.inputs.size() ||
        tx.inputs.size() > std::numeric_limits<uint32_t>::max() ||
        tx.outputs.size() > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    return ResolveScope(selector.inputs, static_cast<uint32_t>(tx.inputs.size()), tx.input_index) &&
           ResolveScope(selector.outputs, static_cast<uint32_t>(tx.outputs.size()), tx.input_index);
}

std::optional<uint64_t> SumAmounts(std::span<const CTxOut> outputs)
{
    uint64_t total{0};
    for (const CTxOut& output : outputs) {
        const std::optional<uint64_t> sum{CheckedAdd(total, static_cast<uint64_t>(output.nValue))};
        if (!sum) return std::nullopt;
        total = *sum;
    }
    return total;
}

//! BIP141 weight. Every input, output and witness item it scans is added to `scanned_records`.
uint64_t TransactionWeight(const ScriptTransactionData& tx, uint64_t& scanned_records)
{
    // `base` follows SerializeTransaction without witness data; `witnesses`
    // collects the witness stacks it appends when any input has one.
    SizeComputer base;
    SizeComputer witnesses;
    bool has_witness{false};
    base << tx.version;
    WriteCompactSize(base, tx.inputs.size());
    for (const CTxIn& input : tx.inputs) {
        base << input;
        witnesses << input.scriptWitness.stack;
        has_witness |= !input.scriptWitness.IsNull();
        scanned_records += 1 + input.scriptWitness.stack.size();
    }
    WriteCompactSize(base, tx.outputs.size());
    for (const CTxOut& output : tx.outputs) {
        base << output;
        ++scanned_records;
    }
    base << tx.lock_time;
    // The full serialization adds the marker and flag bytes before the witnesses.
    const uint64_t total_size{base.size() + (has_witness ? 2 + witnesses.size() : 0)};
    return base.size() * (WITNESS_SCALE_FACTOR - 1) + total_size;
}

//! Pass the selected values to visit in output order, and count the records
//! scanned for aggregate fields.
template <typename Visitor>
bool VisitResults(const Selector& selector, const ScriptTransactionData& tx, const OpTxScriptContext& context,
                  uint64_t& scanned_records, Visitor&& visit)
{
    if (selector.globals & TX_VERSION) visit(ResultValue::Uint32(tx.version));
    if (selector.globals & TX_LOCKTIME) visit(ResultValue::Uint32(tx.lock_time));
    if (selector.globals & TX_WEIGHT) {
        const uint64_t weight{TransactionWeight(tx, scanned_records)};
        if (weight > std::numeric_limits<uint32_t>::max()) return false;
        visit(ResultValue::Uint32(static_cast<uint32_t>(weight)));
    }
    if (selector.globals & INPUT_TOTAL_COUNT) visit(ResultValue::Uint32(static_cast<uint32_t>(tx.inputs.size())));
    if (selector.globals & INPUT_TOTAL_AMOUNT) {
        const auto total{SumAmounts(tx.spent_outputs)};
        if (!total) return false;
        visit(ResultValue::Uint64(*total));
        scanned_records += tx.spent_outputs.size();
    }

    const auto inputs{tx.inputs.subspan(selector.inputs.start, selector.inputs.count)};
    const auto spent_outputs{tx.spent_outputs.subspan(selector.inputs.start, selector.inputs.count)};
    for (size_t i{0}; i < inputs.size(); ++i) {
        const CTxIn& input{inputs[i]};
        const CTxOut& spent_output{spent_outputs[i]};
        if (selector.input_fields & INPUT_PREVOUT_TXID) visit(ResultValue::FixedBytes(MakeUCharSpan(input.prevout.hash)));
        if (selector.input_fields & INPUT_PREVOUT_INDEX) visit(ResultValue::Uint32(input.prevout.n));
        if (selector.input_fields & INPUT_PREVOUT_AMOUNT) visit(ResultValue::Uint64(static_cast<uint64_t>(spent_output.nValue)));
        if (selector.input_fields & INPUT_PREVOUT_SCRIPTPUBKEY) visit(ResultValue::VarBytes(spent_output.scriptPubKey));
        if (selector.input_fields & INPUT_SCRIPTSIG) visit(ResultValue::VarBytes(input.scriptSig));
        if (selector.input_fields & INPUT_SEQUENCE) visit(ResultValue::Uint32(input.nSequence));
        const std::vector<valtype>& witness{input.scriptWitness.stack};
        if (selector.input_fields & INPUT_WITNESS_ITEM_COUNT) {
            if (witness.size() > std::numeric_limits<uint32_t>::max()) return false;
            visit(ResultValue::Uint32(static_cast<uint32_t>(witness.size())));
        }
        if (selector.input_fields & INPUT_WITNESS_ITEMS) {
            // BIP144 witness serialization keeps collated input boundaries.
            visit(ResultValue::CollatedCount(witness.size()));
            for (const valtype& item : witness) {
                visit(ResultValue::VarBytes(item));
            }
        }
    }

    if (selector.globals & OUTPUT_TOTAL_COUNT) visit(ResultValue::Uint32(static_cast<uint32_t>(tx.outputs.size())));
    if (selector.globals & OUTPUT_TOTAL_AMOUNT) {
        const auto total{SumAmounts(tx.outputs)};
        if (!total) return false;
        visit(ResultValue::Uint64(*total));
        scanned_records += tx.outputs.size();
    }
    for (const CTxOut& output : tx.outputs.subspan(selector.outputs.start, selector.outputs.count)) {
        if (selector.output_fields & OUTPUT_AMOUNT) visit(ResultValue::Uint64(static_cast<uint64_t>(output.nValue)));
        if (selector.output_fields & OUTPUT_SCRIPTPUBKEY) visit(ResultValue::VarBytes(output.scriptPubKey));
    }

    if (selector.context & CURRENT_INPUT_INDEX) visit(ResultValue::Uint32(tx.input_index));
    if (selector.context & CURRENT_TAPROOT_ANNEX) visit(ResultValue::VarBytes(context.annex));
    if (selector.context & CURRENT_TAPSCRIPT) visit(ResultValue::VarBytes(context.tapscript));
    if (selector.context & CURRENT_TAPLEAF_HASH) visit(ResultValue::FixedBytes(MakeUCharSpan(context.tapleaf_hash)));
    if (selector.context & CURRENT_CONTROL_BLOCK) visit(ResultValue::VarBytes(context.control_block));
    if (selector.context & CURRENT_INTERNAL_KEY) {
        // The control block's leaf version byte is followed by the internal key.
        if (context.control_block.size() < 1 + 32) return false;
        visit(ResultValue::FixedBytes(context.control_block.subspan(1, 32)));
    }
    if (selector.context & CURRENT_TAPTREE_ROOT) visit(ResultValue::FixedBytes(MakeUCharSpan(context.taptree_root)));
    if (selector.context & CURRENT_CODESEPARATOR_POSITION) visit(ResultValue::Uint32(context.codeseparator_pos));
    return true;
}

//! Size of the stack element that pushes `value` on its own.
size_t ElementSize(const ResultValue& value)
{
    return value.IsNumeric() ? MinimalEncodingSize(value.number) : value.bytes.size();
}

//! The stack element that pushes `value` on its own: a BIP 441 minimal number, or the raw bytes.
valtype MakeElement(const ResultValue& value)
{
    return value.IsNumeric() ? ScalarValue(value.number) : WordPaddedValue(value.bytes);
}

//! Serialize `value` as COLLATE encodes it.
template <typename Stream>
void SerializeCollated(Stream& stream, const ResultValue& value)
{
    // An empty span may have a null data pointer, which memcpy must not receive.
    const auto write_bytes{[&] { if (!value.bytes.empty()) stream << value.bytes; }};
    switch (value.encoding) {
    case ValueEncoding::UINT32:
        stream << static_cast<uint32_t>(value.number);
        return;
    case ValueEncoding::UINT64:
        stream << value.number;
        return;
    case ValueEncoding::FIXED_BYTES:
        write_bytes();
        return;
    case ValueEncoding::VAR_BYTES:
        WriteCompactSize(stream, value.bytes.size());
        write_bytes();
        return;
    case ValueEncoding::COLLATED_COUNT:
        WriteCompactSize(stream, value.number);
        return;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

} // namespace

OpTxResult EvalOpTx(ValtypeStack& stack, const ValtypeStack& altstack,
                    const std::optional<ScriptTransactionData>& tx, const std::optional<OpTxScriptContext>& context,
                    varops::Meter& meter, varops::Budget& varops_budget, ScriptError* serror)
{
    if (stack.size() == 0) return SetError(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    const valtype selector_bytes{stack.PopValue()};
    if (selector_bytes.empty()) return SetError(serror, SCRIPT_ERR_TX_SELECTOR);
    // Reserved selector versions succeed at no cost.
    if (selector_bytes[0] != 0) return OpTxResult::IMMEDIATE_SUCCESS;
    meter.Add(varops::BaseCost());

    std::optional<Selector> selector{ParseSelector(selector_bytes)};
    if (!selector) return SetError(serror, SCRIPT_ERR_TX_SELECTOR);
    // The output scope's operands lie above the input scope's. None are
    // consumed unless all are valid.
    size_t operand_count{0};
    ScriptError operand_error{ReadScopeOperands(stack, operand_count, selector->outputs)};
    if (operand_error == SCRIPT_ERR_OK) operand_error = ReadScopeOperands(stack, operand_count, selector->inputs);
    if (operand_error != SCRIPT_ERR_OK) return SetError(serror, operand_error);
    for (size_t i{0}; i < operand_count; ++i) stack.pop_back();

    if (!tx || !context || !ResolveSelector(*selector, *tx)) return SetError(serror, SCRIPT_ERR_TX_CONTEXT);

    // Size the results in a first pass, and produce them in a second once they
    // are paid for, so that nothing is held per selected value.
    const bool collate{(selector->globals & COLLATE) != 0};
    uint64_t value_count{0};
    uint64_t scanned_records{0};
    size_t result_count{0};
    uint64_t result_size{0};
    size_t max_element_size{0};
    uint64_t write_cost{0};
    SizeComputer collated;
    const bool resolved{VisitResults(*selector, *tx, *context, scanned_records, [&](const ResultValue& value) {
        ++value_count;
        if (collate) {
            SerializeCollated(collated, value);
        } else if (value.encoding != ValueEncoding::COLLATED_COUNT) {
            const size_t size{ElementSize(value)};
            max_element_size = std::max(max_element_size, size);
            ++result_count;
            result_size += size;
            write_cost += value.IsNumeric() ? varops::WriteCost(8) : varops::WriteCost(size);
        }
    })};
    if (!resolved) return SetError(serror, SCRIPT_ERR_TX_CONTEXT);
    if (collate) {
        max_element_size = collated.size();
        result_count = 1;
        result_size = collated.size();
        write_cost = varops::WriteCost(collated.size());
    }
    // k counts every selected value, including each witness item count, and
    // every record scanned for an aggregate field.
    meter.Add(varops::TxSelectCost(value_count + scanned_records));
    meter.Add(write_cost);
    if (max_element_size > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) return SetError(serror, SCRIPT_ERR_STACK_ELEMENT_SIZE);
    if (stack.size() + altstack.size() + result_count > MAX_TAPSCRIPT_V2_STACK_SIZE) {
        return SetError(serror, SCRIPT_ERR_STACK_SIZE);
    }
    if (stack.GetTotalSize() + altstack.GetTotalSize() + result_size > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE) {
        return SetError(serror, SCRIPT_ERR_TOTAL_STACK_SIZE);
    }
    if (!meter.Prepay(varops_budget)) return SetError(serror, SCRIPT_ERR_VAROP_COUNT);

    uint64_t rescanned_records{0};
    if (collate) {
        valtype result;
        result.reserve(WordPaddedCapacity(static_cast<size_t>(result_size)));
        result.resize(static_cast<size_t>(result_size));
        SpanWriter writer{MakeWritableByteSpan(result)};
        Assume(VisitResults(*selector, *tx, *context, rescanned_records, [&](const ResultValue& value) {
            SerializeCollated(writer, value);
        }));
        stack.push_back(std::move(result));
    } else {
        Assume(VisitResults(*selector, *tx, *context, rescanned_records, [&](const ResultValue& value) {
            if (value.encoding != ValueEncoding::COLLATED_COUNT) stack.push_back(MakeElement(value));
        }));
    }
    return OpTxResult::NORMAL;
}

OpTxResult EvalOpTx(ValtypeStack& stack, const ValtypeStack& altstack,
                    const std::optional<ScriptTransactionData>& tx, const std::optional<OpTxScriptContext>& context,
                    varops::Budget& varops_budget, ScriptError* serror)
{
    varops::Meter meter;
    return EvalOpTx(stack, altstack, tx, context, meter, varops_budget, serror);
}
