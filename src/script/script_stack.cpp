// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script_stack.h>

ScriptStack::ScriptStack(const ScriptStack& other) : stack(other.stack) {
    recalculate_size_tracking();
}

ScriptStack::ScriptStack(ScriptStack&& other) noexcept : stack(std::move(other.stack)) {
    recalculate_size_tracking();
}

ScriptStack::ScriptStack(const std::vector<std::vector<unsigned char>>& plain_stack) : stack(plain_stack) {
    recalculate_size_tracking();
}

ScriptStack& ScriptStack::operator=(const ScriptStack& other) {
    if (this != &other) {
        stack = other.stack;
        recalculate_size_tracking();
    }
    return *this;
}

ScriptStack& ScriptStack::operator=(ScriptStack&& other) noexcept {
    if (this != &other) {
        stack = std::move(other.stack);
        recalculate_size_tracking();
    }
    return *this;
}

ScriptStack& ScriptStack::operator=(const std::vector<std::vector<unsigned char> >& plain_stack) {
    stack = plain_stack;
    recalculate_size_tracking();
    return *this;
}

void ScriptStack::push_back(const std::vector<unsigned char>& element) {
    update_size_tracking(element, SizeOperation::Add);
    stack.push_back(element);
}

void ScriptStack::push_back(std::vector<unsigned char>&& element) {
    update_size_tracking(element, SizeOperation::Add);
    stack.push_back(std::move(element));
}

void ScriptStack::pop_back() {
    if (!stack.empty()) {
        update_size_tracking(stack.back(), SizeOperation::Remove);
        stack.pop_back();
    }
}

std::vector<unsigned char> ScriptStack::pop_back_valtype() {
    if (stack.empty()) {
        throw std::runtime_error("pop_back_valtype(): stack empty");
    }
    update_size_tracking(stack.back(), SizeOperation::Remove);
    std::vector<unsigned char> result = std::move(stack.back());
    stack.pop_back();
    return result;
}

bool ScriptStack::pop64(Val64 &v, int index /* = -1 */) {
    if (stack.empty())
        return false;

    update_size_tracking(stack.at(stack.size() + index), SizeOperation::Remove);
    v.move_from_valtype(stack.at(stack.size() + index));
    stack.erase(stack.begin() + stack.size() + index);
    return true;
}

void ScriptStack::clear() {
    stack.clear();
    m_size_counts.clear();
}

void ScriptStack::erase(size_t n) {
    if (n > stack.size()) {
        n = stack.size();
    }
    update_size_tracking(stack[n], SizeOperation::Remove);
    stack.erase(stack.begin() + n);
}

void ScriptStack::erase(size_t first, size_t last) {
    if (first >= last || last > stack.size()) {
        throw std::invalid_argument("Invalid range");
    }
    
    for (size_t i = first; i < last; ++i) {
        update_size_tracking(stack[i], SizeOperation::Remove);
    }
    stack.erase(stack.begin() + first, stack.begin() + last);
}

void ScriptStack::insert(size_t index, const std::vector<unsigned char>& element) {
    if (index > stack.size()) {
        throw std::invalid_argument("Invalid index");
    }
    
    update_size_tracking(element, SizeOperation::Add);
    stack.insert(stack.begin() + index, element);
}

void ScriptStack::reserve(size_t n) {
    stack.reserve(n);
}

void ScriptStack::resize(size_t n) {
    while (stack.size() > n) {
        pop_back();
    }
    while (stack.size() < n) {
        stack.emplace_back();
    }
}

void ScriptStack::rotate(int a, int b, int c) {
    std::rotate(stack.end() + a, stack.end() + b, stack.end() + c);        
}

// more efficient than std::rotate
void ScriptStack::roll(size_t n) {
    // rotate start, newstart, end.
    auto element = std::move(stack[stack.size() - n - 1]);
    stack.erase(stack.begin() + stack.size() - n - 1); 
    stack.push_back(std::move(element)); 
}

void ScriptStack::swap(int a, int b) {
    std::swap(stack.at(stack.size() + a), stack.at(stack.size() + b));
}

size_t ScriptStack::get_total_size() const {
    size_t total = 0;
    for (const auto& [size, count] : m_size_counts) {
        total += size * count;
    }
    return total;
}

size_t ScriptStack::get_max_element_size() const {
    return m_size_counts.empty() ? 0 : m_size_counts.rbegin()->first;
}

size_t ScriptStack::total_stack_size(size_t &max_size) const {
    max_size = std::max(max_size, get_max_element_size());
    return get_total_size();
}

void ScriptStack::update_size_tracking(const std::vector<unsigned char>& element, SizeOperation operation) {
    if (operation == SizeOperation::Add) {
        m_size_counts[element.size()]++;
    } else  if (operation == SizeOperation::Remove) {
        // Decrement count for this size
        auto it = m_size_counts.find(element.size());
        assert(it != m_size_counts.end() && it->second > 0);
        it->second--;
        
        // If count reaches zero, remove the entry
        if (it->second == 0) {
            m_size_counts.erase(it);
        }
    }
    else {
        throw std::invalid_argument("Invalid size operation");
    }
}

void ScriptStack::recalculate_size_tracking() {
    m_size_counts.clear();
    for (const auto& element : stack) {
        m_size_counts[element.size()]++;
    }
}
