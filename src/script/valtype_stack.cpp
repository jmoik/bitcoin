// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/valtype_stack.h>

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <utility>

ValtypeStack::ValtypeStack(std::span<const valtype> values)
{
    // Copy through push_back so initial values also get word-padding capacity.
    m_stack.reserve(values.size());
    for (const valtype& value : values) push_back(value);
}

void ValtypeStack::push_back(const valtype& value)
{
    // Copy before the stack grows, which would move value if it were ours.
    Append(biguint::WordPaddedValue(value));
}

void ValtypeStack::push_back(valtype&& value)
{
    const size_t padded{biguint::WordPaddedCapacity(value.size())};
    if (value.capacity() > 2 * padded) {
        // Stack limits count logical bytes, so copy shortened values out of
        // large buffers. This releases the old value's unused storage, which its
        // WRITE paid for; the copies from one buffer total at most its size.
        value = biguint::WordPaddedValue(value);
    } else if (value.capacity() < padded) {
        // Producers reserve the word padding; this guards values that did not.
        value.reserve(padded);
    }
    Append(std::move(value));
}

void ValtypeStack::Append(valtype&& value)
{
    m_stack.push_back(std::move(value));
    m_total_size += m_stack.back().size();
    m_max_element_size = std::max(m_max_element_size, m_stack.back().size());
}

valtype ValtypeStack::PopValue()
{
    valtype value{std::move(m_stack[Index(0)])};
    m_stack.pop_back();
    m_total_size -= value.size();
    return value;
}

BigUint ValtypeStack::PopBigUint()
{
    return BigUint{PopValue()};
}

void ValtypeStack::Erase(size_t depth)
{
    const auto it{m_stack.begin() + Index(depth)};
    m_total_size -= it->size();
    m_stack.erase(it);
}

void ValtypeStack::Roll(size_t depth, size_t count)
{
    const auto first{m_stack.begin() + Index(depth)};
    if (count > depth + 1) ThrowNoValue();
    if (count == 1) {
        // Move each value above it down once, which is twice as fast as
        // std::rotate swapping them when the value is deep.
        valtype value{std::move(*first)};
        std::move(first + 1, m_stack.end(), first);
        m_stack.back() = std::move(value);
    } else {
        std::rotate(first, first + count, m_stack.end());
    }
}

void ValtypeStack::ThrowNoValue()
{
    throw std::out_of_range{"ValtypeStack: no value at that depth"};
}
