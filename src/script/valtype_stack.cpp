// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <cstdint>
#include <script/valtype_stack.h>
#include <stdexcept>
#include <utility>

namespace {

valtype CopyWithVal64Capacity(const valtype& element)
{
    constexpr size_t WORD_BYTES{sizeof(uint64_t)};
    const size_t capacity{element.size() + (WORD_BYTES - element.size() % WORD_BYTES) % WORD_BYTES};
    if (capacity == element.size()) return element;

    // Leave room for Val64's zero padding so converting this copy does not reallocate it.
    valtype copy;
    copy.reserve(capacity);
    copy.insert(copy.end(), element.begin(), element.end());
    return copy;
}

} // namespace

ValtypeStack::ValtypeStack(const std::vector<std::vector<unsigned char>>& plain_stack) : stack(plain_stack)
{
    recalculate_size_tracking();
}

ValtypeStack::ValtypeStack(Span<const valtype> plain_stack) : stack(plain_stack.begin(), plain_stack.end())
{
    recalculate_size_tracking();
}

ValtypeStack::ValtypeStack(ValtypeStack&& other) noexcept
    : stack{std::move(other.stack)},
      total_size{other.total_size},
      max_element_size{other.max_element_size}
{
    other.stack.clear();
    other.total_size = 0;
    other.max_element_size = 0;
}

ValtypeStack& ValtypeStack::operator=(ValtypeStack&& other) noexcept
{
    if (this == &other) return *this;

    stack = std::move(other.stack);
    total_size = other.total_size;
    max_element_size = other.max_element_size;

    other.stack.clear();
    other.total_size = 0;
    other.max_element_size = 0;
    return *this;
}

void ValtypeStack::push_back(const std::vector<unsigned char>& element)
{
    valtype copy{CopyWithVal64Capacity(element)};
    stack.push_back(std::move(copy));
    update_size_tracking(stack.back(), true);
}

void ValtypeStack::push_back(std::vector<unsigned char>&& element)
{
    stack.push_back(std::move(element));
    update_size_tracking(stack.back(), true);
}

void ValtypeStack::pop_back()
{
    if (stack.empty()) {
        throw std::runtime_error("pop_back(): stack empty");
    }
    update_size_tracking(stack.back(), false);
    stack.pop_back();
}

std::vector<unsigned char> ValtypeStack::pop_back_valtype()
{
    if (stack.empty()) {
        throw std::runtime_error("pop_back_valtype(): stack empty");
    }
    update_size_tracking(stack.back(), false);
    std::vector<unsigned char> result = std::move(stack.back());
    stack.pop_back();
    return result;
}

bool ValtypeStack::pop64(Val64& v)
{
    if (stack.empty())
        return false;

    update_size_tracking(stack.back(), false);
    v.move_from_valtype(std::move(stack.back()));
    stack.pop_back();
    return true;
}

void ValtypeStack::erase(size_t n)
{
    assert(n < stack.size());
    update_size_tracking(stack[n], false);
    stack.erase(stack.begin() + n);
}

void ValtypeStack::reserve(size_t n)
{
    stack.reserve(n);
}

void ValtypeStack::rotate(int a, int b)
{
    std::rotate(stack.end() + a, stack.end() + b, stack.end());
}

// more efficient than std::rotate
void ValtypeStack::roll(size_t n)
{
    // rotate start, newstart, end.
    valtype element = std::move(stack[stack.size() - n - 1]);
    stack.erase(stack.begin() + stack.size() - n - 1);
    stack.push_back(std::move(element));
}

void ValtypeStack::swap(int a, int b)
{
    std::swap(stack.at(static_cast<size_t>(static_cast<ptrdiff_t>(stack.size()) + a)),
              stack.at(static_cast<size_t>(static_cast<ptrdiff_t>(stack.size()) + b)));
}

size_t ValtypeStack::get_total_size() const
{
    return total_size;
}

size_t ValtypeStack::get_max_element_size() const
{
    return max_element_size;
}

void ValtypeStack::update_size_tracking(const std::vector<unsigned char>& element, bool add)
{
    if (add) {
        total_size += element.size();
        max_element_size = std::max(max_element_size, element.size());
    } else {
        total_size -= element.size();
    }
}

void ValtypeStack::recalculate_size_tracking()
{
    total_size = 0;
    max_element_size = 0;
    for (const valtype& element : stack) {
        total_size += element.size();
        max_element_size = std::max(max_element_size, element.size());
    }
}
