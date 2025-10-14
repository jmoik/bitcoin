// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/valtype_stack.h>
#include <stdexcept>

ValtypeStack::ValtypeStack(const ValtypeStack& other) : stack(other.stack) {
    recalculate_size_tracking();
}

ValtypeStack::ValtypeStack(ValtypeStack&& other) noexcept : stack(std::move(other.stack)) {
    recalculate_size_tracking();
}

ValtypeStack::ValtypeStack(const std::vector<std::vector<unsigned char>>& plain_stack) : stack(plain_stack) {
    recalculate_size_tracking();
}

ValtypeStack& ValtypeStack::operator=(const ValtypeStack& other) {
    if (this != &other) {
        stack = other.stack;
        recalculate_size_tracking();
    }
    return *this;
}

ValtypeStack& ValtypeStack::operator=(ValtypeStack&& other) noexcept {
    if (this != &other) {
        stack = std::move(other.stack);
        recalculate_size_tracking();
    }
    return *this;
}

ValtypeStack& ValtypeStack::operator=(const std::vector<std::vector<unsigned char> >& plain_stack) {
    stack = plain_stack;
    recalculate_size_tracking();
    return *this;
}

void ValtypeStack::push_back(const std::vector<unsigned char>& element) {
    update_size_tracking(element, true);
    stack.push_back(element);
}

void ValtypeStack::push_back(std::vector<unsigned char>&& element) {
    update_size_tracking(element, true);
    stack.push_back(std::move(element));
}

void ValtypeStack::pop_back() {
    if (!stack.empty()) {
        update_size_tracking(stack.back(), false);
        stack.pop_back();
    }
}

std::vector<unsigned char> ValtypeStack::pop_back_valtype() {
    if (stack.empty()) {
        throw std::runtime_error("pop_back_valtype(): stack empty");
    }
    update_size_tracking(stack.back(), false);
    std::vector<unsigned char> result = std::move(stack.back());
    stack.pop_back();
    return result;
}

bool ValtypeStack::pop64(Val64 &v, int index /* = -1 */) {
    if (stack.empty())
        return false;

    update_size_tracking(stack.at(stack.size() + index), false);
    v.move_from_valtype(stack.at(stack.size() + index));
    stack.erase(stack.begin() + stack.size() + index);
    return true;
}

void ValtypeStack::clear() {
    stack.clear();
    total_size = 0;
    max_element_size = 0;
}

void ValtypeStack::erase(size_t n) {
    if (n > stack.size()) {
        n = stack.size();
    }
    update_size_tracking(stack[n], false);
    stack.erase(stack.begin() + n);
}

void ValtypeStack::erase(size_t first, size_t last) {
    if (first >= last || last > stack.size()) {
        throw std::invalid_argument("Invalid range");
    }
    
    for (size_t i = first; i < last; ++i) {
        update_size_tracking(stack[i], false);
    }
    stack.erase(stack.begin() + first, stack.begin() + last);
}

void ValtypeStack::insert(size_t index, const std::vector<unsigned char>& element) {
    if (index > stack.size()) {
        throw std::invalid_argument("Invalid index");
    }
    
    update_size_tracking(element, true);
    stack.insert(stack.begin() + index, element);
}

void ValtypeStack::reserve(size_t n) {
    stack.reserve(n);
}

void ValtypeStack::resize(size_t n) {
    while (stack.size() > n) {
        pop_back();
    }
    while (stack.size() < n) {
        stack.emplace_back();
    }
}

void ValtypeStack::rotate(int a, int b, int c) {
    std::rotate(stack.end() + a, stack.end() + b, stack.end() + c);        
}

// more efficient than std::rotate
void ValtypeStack::roll(size_t n) {
    // rotate start, newstart, end.
    auto element = std::move(stack[stack.size() - n - 1]);
    stack.erase(stack.begin() + stack.size() - n - 1); 
    stack.push_back(std::move(element)); 
}

void ValtypeStack::swap(int a, int b) {
    std::swap(stack.at(stack.size() + a), stack.at(stack.size() + b));
}

size_t ValtypeStack::get_total_size() const {
    return total_size;
}

size_t ValtypeStack::get_max_element_size() const {
    return max_element_size;
}

size_t ValtypeStack::total_stack_size(size_t &max_size) const {
    max_size = std::max(max_size, get_max_element_size());
    return get_total_size();
}

void ValtypeStack::update_size_tracking(const std::vector<unsigned char>& element, bool add) {
    if (add) {
        total_size += element.size();
        max_element_size = std::max(max_element_size, element.size());
    } else {
        total_size -= element.size();
    }
}

void ValtypeStack::recalculate_size_tracking() {
    total_size = 0;
    max_element_size = 0;
    for (const auto& element : stack) {
        total_size += element.size();
        max_element_size = std::max(max_element_size, element.size());
    }
}
