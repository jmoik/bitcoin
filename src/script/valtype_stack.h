// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VALTYPE_STACK_H
#define BITCOIN_SCRIPT_VALTYPE_STACK_H

#include <script/val64.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using valtype = std::vector<unsigned char>;

/** A copy of bytes with capacity for its word padding. */
inline valtype WordPaddedValue(std::span<const unsigned char> bytes)
{
    valtype value;
    value.reserve(WordPaddedCapacity(bytes.size()));
    value.assign(bytes.begin(), bytes.end());
    return value;
}

/** A value holding the minimal little-endian bytes of number, the encoding of a
 *  numeric result, with capacity for its word padding. Zero is the empty value. */
inline valtype ScalarValue(uint64_t number)
{
    valtype value;
    if (number != 0) value.reserve(WordPaddedCapacity(sizeof(number)));
    for (; number != 0; number >>= 8) value.push_back(static_cast<unsigned char>(number));
    return value;
}

/**
 * Script stack that tracks the total size of its values and the largest value
 * size it has held.
 *
 * Values are addressed by depth, where 0 is the top. Addressing a value that is
 * not there throws std::out_of_range. Callers check the stack depth first, so
 * this only turns a caller bug into a script failure.
 */
class ValtypeStack
{
public:
    ValtypeStack() = default;
    explicit ValtypeStack(std::span<const valtype> values);

    ValtypeStack(const ValtypeStack&) = delete;
    ValtypeStack& operator=(const ValtypeStack&) = delete;

    // A moved-from stack is empty.
    ValtypeStack(ValtypeStack&& other) noexcept;
    ValtypeStack& operator=(ValtypeStack&& other) noexcept;

    size_t size() const { return m_stack.size(); }
    // Values are read-only so size tracking cannot be bypassed.
    const valtype& Top(size_t depth = 0) const { return m_stack[Index(depth)]; }

    const std::vector<valtype>& GetStack() const { return m_stack; }
    size_t GetTotalSize() const { return m_total_size; }
    size_t GetMaxElementSize() const { return m_max_element_size; }

    // Push a copy of value, which may be a value on this stack.
    void push_back(const valtype& value);
    void push_back(valtype&& value);
    void pop_back()
    {
        m_total_size -= Top().size();
        m_stack.pop_back();
    }
    valtype PopValue();
    Val64 PopVal64();

    void Erase(size_t depth);
    // Move the count values from depth up to the top, keeping their order.
    void Roll(size_t depth, size_t count = 1);
    void Swap(size_t depth_a, size_t depth_b) { std::swap(m_stack[Index(depth_a)], m_stack[Index(depth_b)]); }

private:
    std::vector<valtype> m_stack;
    size_t m_total_size{0};
    // High-water mark; deliberately not reduced when values are removed.
    size_t m_max_element_size{0};

    size_t Index(size_t depth) const
    {
        if (depth >= m_stack.size()) ThrowNoValue();
        return m_stack.size() - 1 - depth;
    }
    [[noreturn]] static void ThrowNoValue();
    void Append(valtype&& value);
};

#endif // BITCOIN_SCRIPT_VALTYPE_STACK_H
