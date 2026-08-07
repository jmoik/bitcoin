// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/op_tx.h>

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <serialize.h>
#include <span.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

constexpr uint8_t COLLATE{0x01};
constexpr uint8_t TX_VERSION{0x02};
constexpr uint8_t TX_LOCKTIME{0x04};
constexpr uint8_t TX_WEIGHT{0x08};
constexpr uint8_t INPUT_TOTAL_COUNT{0x10};
constexpr uint8_t INPUT_TOTAL_AMOUNT{0x20};
constexpr uint8_t OUTPUT_TOTAL_COUNT{0x40};
constexpr uint8_t OUTPUT_TOTAL_AMOUNT{0x80};

constexpr uint8_t CURRENT_INPUT_INDEX{0x01};
constexpr uint8_t CURRENT_TAPROOT_ANNEX{0x02};
constexpr uint8_t CURRENT_TAPSCRIPT{0x04};
constexpr uint8_t CURRENT_TAPLEAF_HASH{0x08};
constexpr uint8_t CURRENT_CONTROL_BLOCK{0x10};
constexpr uint8_t CURRENT_INTERNAL_KEY{0x20};
constexpr uint8_t CURRENT_TAPTREE_ROOT{0x40};
constexpr uint8_t CURRENT_CODESEPARATOR_POSITION{0x80};

constexpr uint8_t INPUT_PREVOUT_TXID{0x01};
constexpr uint8_t INPUT_PREVOUT_INDEX{0x02};
constexpr uint8_t INPUT_PREVOUT_AMOUNT{0x04};
constexpr uint8_t INPUT_PREVOUT_SCRIPTPUBKEY{0x08};
constexpr uint8_t INPUT_SCRIPTSIG{0x10};
constexpr uint8_t INPUT_SEQUENCE{0x20};
constexpr uint8_t INPUT_WITNESS_ITEM_COUNT{0x40};
constexpr uint8_t INPUT_WITNESS_ITEMS{0x80};
constexpr uint8_t OUTPUT_AMOUNT{0x01};
constexpr uint8_t OUTPUT_SCRIPTPUBKEY{0x02};
constexpr uint8_t OUTPUT_FIELDS{OUTPUT_AMOUNT | OUTPUT_SCRIPTPUBKEY};

constexpr uint8_t SCOPE_NONE{0x00};
constexpr uint8_t SCOPE_CURRENT{0x01};
constexpr uint8_t SCOPE_ALL{0x02};
constexpr uint8_t SCOPE_SINGLE{0x03};
constexpr uint8_t SCOPE_RANGE{0x04};
constexpr uint64_t TOTAL_AMOUNT_COST_PER_ITEM{sizeof(uint64_t) * varops::COST_ARITH};

struct Scope {
    uint8_t kind{SCOPE_NONE};
    uint32_t start{0};
    uint32_t count{0};
};

struct Selector {
    bool collate{false};
    uint8_t globals{0};
    uint8_t context{0};
    uint8_t input_fields{0};
    uint8_t output_fields{0};
    bool input_total_count{false};
    bool input_total_amount{false};
    bool output_total_count{false};
    bool output_total_amount{false};
    bool tx_weight{false};
    Scope inputs;
    Scope outputs;
};

enum class ValueEncoding : uint8_t {
    UINT32,
    UINT64,
    FIXED_BYTES,
    VAR_BYTES,
};

struct ResultValue {
    ValueEncoding encoding;
    uint64_t number{0};
    std::span<const unsigned char> bytes{};

    static ResultValue Uint32(uint32_t value) { return {ValueEncoding::UINT32, value, {}}; }
    static ResultValue Uint64(uint64_t value) { return {ValueEncoding::UINT64, value, {}}; }
    static ResultValue FixedBytes(std::span<const unsigned char> value) { return {ValueEncoding::FIXED_BYTES, 0, value}; }
    static ResultValue VarBytes(std::span<const unsigned char> value) { return {ValueEncoding::VAR_BYTES, 0, value}; }
};

OpTxResult SetError(ScriptError* ret, ScriptError error)
{
    if (ret) *ret = error;
    return OpTxResult::ERROR;
}

bool ReadScopeOperand(const valtype& bytes, uint32_t& result)
{
    if (bytes.size() > sizeof(uint32_t) || (!bytes.empty() && bytes.back() == 0)) return false;
    result = 0;
    for (size_t i{0}; i < bytes.size(); ++i) {
        result |= static_cast<uint32_t>(bytes[i]) << (8 * i);
    }
    return true;
}

enum class ScopeOperandResult {
    VALID,
    MISSING,
    INVALID,
};

ScopeOperandResult ParseScopeOperands(const ValtypeStack& stack, Scope& scope, size_t& depth)
{
    const auto read_operand{[&](uint32_t& value) {
        if (depth >= stack.size()) return ScopeOperandResult::MISSING;
        if (!ReadScopeOperand(stack.at(stack.size() - 1 - depth), value)) {
            return ScopeOperandResult::INVALID;
        }
        ++depth;
        return ScopeOperandResult::VALID;
    }};

    switch (scope.kind) {
    case SCOPE_NONE:
    case SCOPE_CURRENT:
    case SCOPE_ALL:
        return ScopeOperandResult::VALID;
    case SCOPE_SINGLE: {
        const ScopeOperandResult status{read_operand(scope.start)};
        if (status != ScopeOperandResult::VALID) return status;
        scope.count = 1;
        return ScopeOperandResult::VALID;
    }
    case SCOPE_RANGE: {
        ScopeOperandResult status{read_operand(scope.count)};
        if (status != ScopeOperandResult::VALID) return status;
        status = read_operand(scope.start);
        if (status != ScopeOperandResult::VALID) return status;
        if (scope.count == 0) return ScopeOperandResult::INVALID;
        return ScopeOperandResult::VALID;
    }
    }
    return ScopeOperandResult::INVALID;
}

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

bool ParseSelector(std::span<const unsigned char> bytes, Selector& result)
{
    if (bytes.size() != 6 || bytes[0] != 0) return false;

    const uint8_t globals{bytes[1]};
    const uint8_t context{bytes[2]};
    const uint8_t input_scope{static_cast<uint8_t>(bytes[3] >> 4)};
    const uint8_t output_scope{static_cast<uint8_t>(bytes[3] & 0x0f)};
    if (input_scope > SCOPE_RANGE || output_scope > SCOPE_RANGE) return false;

    result.collate = (globals & COLLATE) != 0;
    result.globals = static_cast<uint8_t>(globals & (TX_VERSION | TX_LOCKTIME));
    result.context = context;
    result.input_total_count = (globals & INPUT_TOTAL_COUNT) != 0;
    result.input_total_amount = (globals & INPUT_TOTAL_AMOUNT) != 0;
    result.output_total_count = (globals & OUTPUT_TOTAL_COUNT) != 0;
    result.output_total_amount = (globals & OUTPUT_TOTAL_AMOUNT) != 0;
    result.tx_weight = (globals & TX_WEIGHT) != 0;

    result.inputs.kind = input_scope;
    result.outputs.kind = output_scope;
    result.input_fields = bytes[4];
    result.output_fields = bytes[5];
    if ((result.output_fields & ~OUTPUT_FIELDS) != 0) return false;
    if ((input_scope == SCOPE_NONE) != (result.input_fields == 0)) return false;
    if ((output_scope == SCOPE_NONE) != (result.output_fields == 0)) return false;

    if (result.globals == 0 && result.context == 0 && result.input_fields == 0 &&
        result.output_fields == 0 && !result.input_total_count &&
        !result.input_total_amount && !result.output_total_count &&
        !result.output_total_amount && !result.tx_weight) {
        return false;
    }
    return true;
}

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
        const uint64_t amount{static_cast<uint64_t>(output.nValue)};
        if (amount > std::numeric_limits<uint64_t>::max() - total) return std::nullopt;
        total += amount;
    }
    return total;
}

std::pair<uint64_t, uint64_t> GetTransactionSizes(const ScriptTransactionData& tx)
{
    uint64_t stripped_size{sizeof(uint32_t) + GetSizeOfCompactSize(tx.inputs.size()) +
                           GetSizeOfCompactSize(tx.outputs.size()) + sizeof(uint32_t)};
    bool has_witness{false};
    uint64_t witness_size{0};
    for (const CTxIn& input : tx.inputs) {
        stripped_size += GetSerializeSize(input);
        has_witness |= !input.scriptWitness.IsNull();
        witness_size += GetSerializeSize(input.scriptWitness.stack);
    }
    for (const CTxOut& output : tx.outputs) {
        stripped_size += GetSerializeSize(output);
    }
    const uint64_t total_size{stripped_size + (has_witness ? 2 + witness_size : 0)};
    return {stripped_size, total_size};
}

size_t MinimalUintSize(uint64_t value)
{
    size_t size{0};
    while (value != 0) {
        ++size;
        value >>= 8;
    }
    return size;
}

size_t SemanticSize(const ResultValue& value)
{
    switch (value.encoding) {
    case ValueEncoding::UINT32:
    case ValueEncoding::UINT64:
        return MinimalUintSize(value.number);
    case ValueEncoding::FIXED_BYTES:
    case ValueEncoding::VAR_BYTES:
        return value.bytes.size();
    }
    return 0;
}

size_t CollatedSize(const ResultValue& value)
{
    switch (value.encoding) {
    case ValueEncoding::UINT32:
        return 4;
    case ValueEncoding::UINT64:
        return 8;
    case ValueEncoding::FIXED_BYTES:
        return value.bytes.size();
    case ValueEncoding::VAR_BYTES:
        return GetSizeOfCompactSize(value.bytes.size()) + value.bytes.size();
    }
    return 0;
}

void AppendLE(valtype& output, uint64_t value, size_t width)
{
    for (size_t i{0}; i < width; ++i) {
        output.push_back(static_cast<unsigned char>(value));
        value >>= 8;
    }
}

void AppendCompactSize(valtype& output, uint64_t value)
{
    if (value < 253) {
        output.push_back(static_cast<unsigned char>(value));
    } else if (value <= std::numeric_limits<uint16_t>::max()) {
        output.push_back(253);
        AppendLE(output, value, 2);
    } else if (value <= std::numeric_limits<uint32_t>::max()) {
        output.push_back(254);
        AppendLE(output, value, 4);
    } else {
        output.push_back(255);
        AppendLE(output, value, 8);
    }
}

void AppendSemantic(valtype& output, const ResultValue& value)
{
    switch (value.encoding) {
    case ValueEncoding::UINT32:
    case ValueEncoding::UINT64:
        AppendLE(output, value.number, MinimalUintSize(value.number));
        return;
    case ValueEncoding::FIXED_BYTES:
    case ValueEncoding::VAR_BYTES:
        output.insert(output.end(), value.bytes.begin(), value.bytes.end());
        return;
    }
}

void AppendCollated(valtype& output, const ResultValue& value)
{
    switch (value.encoding) {
    case ValueEncoding::UINT32:
        AppendLE(output, value.number, 4);
        return;
    case ValueEncoding::UINT64:
        AppendLE(output, value.number, 8);
        return;
    case ValueEncoding::FIXED_BYTES:
        output.insert(output.end(), value.bytes.begin(), value.bytes.end());
        return;
    case ValueEncoding::VAR_BYTES:
        AppendCompactSize(output, value.bytes.size());
        output.insert(output.end(), value.bytes.begin(), value.bytes.end());
        return;
    }
}

bool PlanResults(std::vector<ResultValue>& values, uint64_t& additional_cost,
                 const Selector& selector, const ScriptTransactionData& tx,
                 const ScriptExecutionData& execdata)
{
    if (selector.globals & TX_VERSION) values.push_back(ResultValue::Uint32(static_cast<uint32_t>(tx.version)));
    if (selector.globals & TX_LOCKTIME) values.push_back(ResultValue::Uint32(tx.lock_time));
    if (selector.tx_weight) {
        const auto [stripped_size, total_size]{GetTransactionSizes(tx)};
        const uint64_t weight{stripped_size * 3 + total_size};
        if (weight > std::numeric_limits<uint32_t>::max()) return false;
        values.push_back(ResultValue::Uint32(weight));
        additional_cost += varops::COST_COPYING * (stripped_size + total_size);
    }
    if (selector.input_total_count) values.push_back(ResultValue::Uint32(tx.inputs.size()));
    if (selector.input_total_amount) {
        if (tx.spent_outputs.size() < tx.inputs.size()) return false;
        const auto total{SumAmounts(tx.spent_outputs.first(tx.inputs.size()))};
        if (!total) return false;
        values.push_back(ResultValue::Uint64(*total));
        additional_cost += TOTAL_AMOUNT_COST_PER_ITEM * tx.inputs.size();
    }

    for (uint32_t offset{0}; offset < selector.inputs.count; ++offset) {
        const uint32_t index{selector.inputs.start + offset};
        const CTxIn& input{tx.inputs[index]};
        if (selector.input_fields & INPUT_PREVOUT_TXID) {
            values.push_back(ResultValue::FixedBytes(MakeUCharSpan(input.prevout.hash)));
        }
        if (selector.input_fields & INPUT_PREVOUT_INDEX) values.push_back(ResultValue::Uint32(input.prevout.n));
        if (selector.input_fields & (INPUT_PREVOUT_AMOUNT | INPUT_PREVOUT_SCRIPTPUBKEY)) {
            if (index >= tx.spent_outputs.size()) return false;
            const CTxOut& spent_output{tx.spent_outputs[index]};
            if (selector.input_fields & INPUT_PREVOUT_AMOUNT) values.push_back(ResultValue::Uint64(static_cast<uint64_t>(spent_output.nValue)));
            if (selector.input_fields & INPUT_PREVOUT_SCRIPTPUBKEY) values.push_back(ResultValue::VarBytes(spent_output.scriptPubKey));
        }
        if (selector.input_fields & INPUT_SCRIPTSIG) values.push_back(ResultValue::VarBytes(input.scriptSig));
        if (selector.input_fields & INPUT_SEQUENCE) values.push_back(ResultValue::Uint32(input.nSequence));
        if (selector.input_fields & INPUT_WITNESS_ITEM_COUNT) {
            if (input.scriptWitness.stack.size() > std::numeric_limits<uint32_t>::max()) return false;
            values.push_back(ResultValue::Uint32(input.scriptWitness.stack.size()));
        }
        if (selector.input_fields & INPUT_WITNESS_ITEMS) {
            for (const valtype& item : input.scriptWitness.stack) {
                values.push_back(ResultValue::VarBytes(item));
            }
        }
    }

    if (selector.output_total_count) values.push_back(ResultValue::Uint32(tx.outputs.size()));
    if (selector.output_total_amount) {
        const auto total{SumAmounts(tx.outputs)};
        if (!total) return false;
        values.push_back(ResultValue::Uint64(*total));
        additional_cost += TOTAL_AMOUNT_COST_PER_ITEM * tx.outputs.size();
    }
    for (uint32_t offset{0}; offset < selector.outputs.count; ++offset) {
        const CTxOut& output{tx.outputs[selector.outputs.start + offset]};
        if (selector.output_fields & OUTPUT_AMOUNT) values.push_back(ResultValue::Uint64(static_cast<uint64_t>(output.nValue)));
        if (selector.output_fields & OUTPUT_SCRIPTPUBKEY) values.push_back(ResultValue::VarBytes(output.scriptPubKey));
    }

    if (selector.context & CURRENT_INPUT_INDEX) values.push_back(ResultValue::Uint32(tx.input_index));
    if (selector.context & CURRENT_TAPROOT_ANNEX) {
        if (!execdata.m_annex_init) return false;
        values.push_back(ResultValue::VarBytes(execdata.m_annex_present ? execdata.m_annex : std::span<const unsigned char>{}));
    }
    if (selector.context & CURRENT_TAPSCRIPT) {
        if (!execdata.m_tapscript_init) return false;
        values.push_back(ResultValue::VarBytes(execdata.m_tapscript));
    }
    if (selector.context & CURRENT_TAPLEAF_HASH) {
        if (!execdata.m_tapleaf_hash_init) return false;
        values.push_back(ResultValue::FixedBytes(MakeUCharSpan(execdata.m_tapleaf_hash)));
    }
    if (selector.context & CURRENT_CONTROL_BLOCK) {
        if (!execdata.m_control_block_init) return false;
        values.push_back(ResultValue::VarBytes(execdata.m_control_block));
    }
    if (selector.context & CURRENT_INTERNAL_KEY) {
        if (!execdata.m_control_block_init || execdata.m_control_block.size() < TAPROOT_CONTROL_BASE_SIZE) return false;
        values.push_back(ResultValue::FixedBytes(execdata.m_control_block.subspan(1, 32)));
    }
    if (selector.context & CURRENT_TAPTREE_ROOT) {
        if (!execdata.m_taptree_root_init) return false;
        values.push_back(ResultValue::FixedBytes(MakeUCharSpan(execdata.m_taptree_root)));
    }
    if (selector.context & CURRENT_CODESEPARATOR_POSITION) {
        if (!execdata.m_codeseparator_pos_init) return false;
        values.push_back(ResultValue::Uint32(execdata.m_codeseparator_pos));
    }
    return true;
}

} // namespace

OpTxResult EvalOpTx(ValtypeStack& stack, const ValtypeStack& altstack,
                    const BaseSignatureChecker& checker, const ScriptExecutionData& execdata,
                    varops::Budget& varops_budget, ScriptError* serror)
{
    if (stack.size() < 1) return SetError(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    const valtype selector_bytes{stack.PopBackValue()};
    if (selector_bytes.empty()) return SetError(serror, SCRIPT_ERR_TX_SELECTOR);
    if (selector_bytes[0] != 0) return OpTxResult::IMMEDIATE_SUCCESS;

    Selector selector;
    if (!ParseSelector(selector_bytes, selector)) return SetError(serror, SCRIPT_ERR_TX_SELECTOR);

    size_t scope_operand_count{0};
    ScopeOperandResult operand_result{ParseScopeOperands(stack, selector.outputs, scope_operand_count)};
    if (operand_result == ScopeOperandResult::VALID) {
        operand_result = ParseScopeOperands(stack, selector.inputs, scope_operand_count);
    }
    if (operand_result == ScopeOperandResult::MISSING) {
        return SetError(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    if (operand_result == ScopeOperandResult::INVALID) {
        return SetError(serror, SCRIPT_ERR_TX_SELECTOR);
    }
    for (size_t i{0}; i < scope_operand_count; ++i) stack.pop_back();

    const auto tx{checker.GetTransactionData()};
    if (!tx) return SetError(serror, SCRIPT_ERR_TX_CONTEXT);
    if (!ResolveSelector(selector, *tx)) return SetError(serror, SCRIPT_ERR_TX_CONTEXT);
    if (!execdata.m_annex_init || !execdata.m_tapscript_init ||
        !execdata.m_tapleaf_hash_init || !execdata.m_control_block_init ||
        !execdata.m_taptree_root_init || !execdata.m_codeseparator_pos_init) {
        return SetError(serror, SCRIPT_ERR_TX_CONTEXT);
    }

    std::vector<ResultValue> values;
    uint64_t additional_cost{0};
    if (!PlanResults(values, additional_cost, selector, *tx, execdata)) return SetError(serror, SCRIPT_ERR_TX_CONTEXT);
    const size_t output_count{selector.collate ? 1 : values.size()};
    size_t total_output_size{0};
    for (const ResultValue& value : values) {
        const size_t value_size{selector.collate ? CollatedSize(value) : SemanticSize(value)};
        if (!selector.collate && value_size > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) {
            return SetError(serror, SCRIPT_ERR_STACK_ELEMENT_SIZE);
        }
        if (value_size > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - total_output_size) {
            return SetError(serror, SCRIPT_ERR_TOTAL_STACK_SIZE);
        }
        total_output_size += value_size;
    }
    if (selector.collate && total_output_size > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) {
        return SetError(serror, SCRIPT_ERR_STACK_ELEMENT_SIZE);
    }
    const uint64_t cost{varops::ExecutionCost(OP_TX) +
                        static_cast<uint64_t>(total_output_size) * varops::COST_COPYING +
                        additional_cost};

    if (stack.size() > MAX_TAPSCRIPT_V2_STACK_SIZE ||
        altstack.size() > MAX_TAPSCRIPT_V2_STACK_SIZE - stack.size()) {
        return SetError(serror, SCRIPT_ERR_STACK_SIZE);
    }
    const size_t base_items{stack.size() + altstack.size()};
    if (output_count > MAX_TAPSCRIPT_V2_STACK_SIZE - base_items) return SetError(serror, SCRIPT_ERR_STACK_SIZE);

    if (stack.GetTotalSize() > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE ||
        altstack.GetTotalSize() > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - stack.GetTotalSize()) {
        return SetError(serror, SCRIPT_ERR_TOTAL_STACK_SIZE);
    }
    const size_t base_bytes{stack.GetTotalSize() + altstack.GetTotalSize()};
    if (total_output_size > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - base_bytes) return SetError(serror, SCRIPT_ERR_TOTAL_STACK_SIZE);
    if (!varops_budget.Spend(cost)) return SetError(serror, SCRIPT_ERR_VAROP_COUNT);

    std::vector<valtype> outputs;
    outputs.reserve(output_count);
    if (selector.collate) {
        valtype output;
        output.reserve(total_output_size);
        for (const ResultValue& value : values)
            AppendCollated(output, value);
        outputs.push_back(std::move(output));
    } else {
        for (const ResultValue& value : values) {
            valtype output;
            output.reserve(SemanticSize(value));
            AppendSemantic(output, value);
            outputs.push_back(std::move(output));
        }
    }

    stack.reserve(stack.size() + outputs.size());
    for (valtype& output : outputs)
        stack.push_back(std::move(output));
    return OpTxResult::NORMAL;
}
