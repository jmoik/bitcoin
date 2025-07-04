// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_SCRIPT_STACK_H
#define BITCOIN_SCRIPT_SCRIPT_STACK_H

#include <script/val64.h>
#include <vector>
#include <algorithm>
#include <cassert>
#include <map>

typedef std::vector<unsigned char> valtype;

/**
 * Enum class to specify whether we're adding or removing elements for size tracking
 */
enum class SizeOperation {
    Add,
    Remove
};

/**
 * Script stack wrapper that internally tracks element size counts for efficient
 * calculation of total stack size and maximum element size. This avoids the need
 * to iterate through all elements during script execution.
 */
class ScriptStack {
public:
    // Constructors and assignment operators
    ScriptStack() = default;
    ScriptStack(const ScriptStack& other);
    ScriptStack(ScriptStack&& other) noexcept;
    ScriptStack(const std::vector<std::vector<unsigned char>>& plain_stack);
    
    ScriptStack& operator=(const ScriptStack& other);
    ScriptStack& operator=(ScriptStack&& other) noexcept;
    ScriptStack& operator=(const std::vector<std::vector<unsigned char>>& plain_stack);

    const valtype& at(size_t n) const { return stack.at(n); }
    
    // Const iterator support
    typename std::vector<std::vector<unsigned char>>::const_iterator begin() { return stack.begin(); }
    typename std::vector<std::vector<unsigned char>>::const_iterator begin() const { return stack.begin(); }
    typename std::vector<std::vector<unsigned char>>::const_iterator end() { return stack.end(); }    
    typename std::vector<std::vector<unsigned char>>::const_iterator end() const { return stack.end(); }
    
    const std::vector<std::vector<unsigned char>>& get_stack() const { return stack; }

    // Stack interface methods that need size tracking
    void push_back(const std::vector<unsigned char>& element);
    void push_back(std::vector<unsigned char>&& element);
    void pop_back();
    std::vector<unsigned char> pop_back_valtype();  // Returns the popped element by value
    bool pop64(Val64 &v, int index = -1);
    void clear();
    
    void erase(size_t n);  // Erase the element at position n
    void erase(size_t first, size_t last);  // Erase the range of elements [first, last)
    void insert(size_t index, const std::vector<unsigned char>& element);  // Insert element at index position

    void reserve(size_t n);
    void resize(size_t n);
    
    void rotate(int a, int b, int c);
    void roll(size_t n);
    void swap(int a, int b);

    size_t get_total_size() const;
    size_t get_max_element_size() const;
    size_t total_stack_size(size_t &max_size) const;
    
    size_t size() const { return stack.size(); }
    bool empty() const { return stack.empty(); }
    const std::vector<unsigned char>& back() const { return stack.back(); }
    const std::vector<unsigned char>& front() const { return stack.front(); }

private:
    std::vector<std::vector<unsigned char>> stack;
    // Map to track element sizes and their counts for efficient max size tracking
    std::map<size_t, size_t> m_size_counts;

    void update_size_tracking(const std::vector<unsigned char>& element, SizeOperation operation);
    void recalculate_size_tracking();
};

#endif // BITCOIN_SCRIPT_SCRIPT_STACK_H 
