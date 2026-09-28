// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Generates short stack-manipulation programs and compares their evaluation
// against an independently maintained expected stack and budget.

#include <script/script.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/tapscript_v2_fuzz_util.h>

#include <algorithm>
#include <cstdint>
#include <utility>

namespace {
using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

void RunStackProgram(FuzzedDataProvider& provider)
{
    Stack initial_stack;
    const size_t initial_size{provider.ConsumeIntegralInRange<size_t>(0, 8)};
    for (size_t i{0}; i < initial_size; ++i)
        initial_stack.push_back(ConsumeElement(provider, 64));

    Stack stack{initial_stack};
    Stack altstack;
    CScript script;
    uint64_t cost{InitialStackCost(initial_stack)};
    const size_t steps{provider.ConsumeIntegralInRange<size_t>(1, 64)};

    for (size_t step{0}; step < steps && stack.size() + altstack.size() <= 128; ++step) {
        const uint8_t choice{provider.ConsumeIntegralInRange<uint8_t>(0, 22)};
        switch (choice) {
        case 0: {
            const Bytes value{ConsumeElement(provider, 64)};
            script << value;
            cost += CopyingCost({value.size()});
            stack.push_back(value);
            break;
        }
        case 1:
            if (!stack.empty()) {
                script << OP_DROP;
                cost += F();
                stack.pop_back();
            }
            break;
        case 2:
            if (stack.size() >= 2) {
                script << OP_2DROP;
                cost += F();
                stack.resize(stack.size() - 2);
            }
            break;
        case 3:
            if (!stack.empty()) {
                script << OP_DUP;
                cost += CopyingCost({stack.back().size()});
                stack.push_back(stack.back());
            }
            break;
        case 4:
            if (stack.size() >= 2) {
                script << OP_OVER;
                const Bytes value{stack[stack.size() - 2]};
                cost += CopyingCost({value.size()});
                stack.push_back(value);
            }
            break;
        case 5:
            if (stack.size() >= 2) {
                script << OP_TUCK;
                const Bytes a{stack[stack.size() - 2]};
                const Bytes b{stack.back()};
                cost += CopyingCost({b.size()});
                stack.resize(stack.size() - 2);
                stack.insert(stack.end(), {b, a, b});
            }
            break;
        case 6:
            if (stack.size() >= 2) {
                script << OP_2DUP;
                const Bytes a{stack[stack.size() - 2]};
                const Bytes b{stack.back()};
                cost += CopyingCost({a.size(), b.size()});
                stack.insert(stack.end(), {a, b});
            }
            break;
        case 7:
            if (stack.size() >= 3) {
                script << OP_3DUP;
                const Bytes a{stack[stack.size() - 3]};
                const Bytes b{stack[stack.size() - 2]};
                const Bytes c{stack.back()};
                cost += CopyingCost({a.size(), b.size(), c.size()});
                stack.insert(stack.end(), {a, b, c});
            }
            break;
        case 8:
            if (stack.size() >= 4) {
                script << OP_2OVER;
                const Bytes a{stack[stack.size() - 4]};
                const Bytes b{stack[stack.size() - 3]};
                cost += CopyingCost({a.size(), b.size()});
                stack.insert(stack.end(), {a, b});
            }
            break;
        case 9:
            if (stack.size() >= 2) {
                script << OP_NIP;
                cost += F();
                stack.erase(stack.end() - 2);
            }
            break;
        case 10:
            if (stack.size() >= 3) {
                script << OP_ROT;
                cost += MovingCost(3);
                std::rotate(stack.end() - 3, stack.end() - 2, stack.end());
            }
            break;
        case 11:
            if (stack.size() >= 2) {
                script << OP_SWAP;
                cost += MovingCost(2);
                std::swap(stack[stack.size() - 2], stack.back());
            }
            break;
        case 12:
            if (stack.size() >= 6) {
                script << OP_2ROT;
                cost += MovingCost(6);
                std::rotate(stack.end() - 6, stack.end() - 4, stack.end());
            }
            break;
        case 13:
            if (stack.size() >= 4) {
                script << OP_2SWAP;
                cost += MovingCost(4);
                std::rotate(stack.end() - 4, stack.end() - 2, stack.end());
            }
            break;
        case 14:
            if (!stack.empty()) {
                script << OP_TOALTSTACK;
                cost += MovingCost(1);
                altstack.push_back(std::move(stack.back()));
                stack.pop_back();
            }
            break;
        case 15:
            if (!altstack.empty()) {
                script << OP_FROMALTSTACK;
                cost += MovingCost(1);
                stack.push_back(std::move(altstack.back()));
                altstack.pop_back();
            }
            break;
        case 16:
            if (!stack.empty()) {
                script << OP_SIZE;
                cost += F() + ScalarCost();
                stack.push_back(ToLittleEndian(stack.back().size()));
            }
            break;
        case 17:
            script << OP_DEPTH;
            cost += F() + ScalarCost();
            stack.push_back(ToLittleEndian(stack.size()));
            break;
        case 18:
            if (stack.size() >= 2) {
                script << OP_EQUAL;
                const Bytes b{std::move(stack.back())};
                stack.pop_back();
                const Bytes a{std::move(stack.back())};
                stack.pop_back();
                cost += EqualCost(a.size(), b.size());
                stack.push_back(a == b ? Bytes{1} : Bytes{});
            }
            break;
        case 19:
            if (!stack.empty()) {
                const opcodetype opcode{provider.ConsumeBool() ? OP_NOT : OP_0NOTEQUAL};
                script << opcode;
                const bool nonzero{ContainsNonZero(stack.back())};
                cost += ZeroTestCost(stack.back().size());
                stack.back() = (opcode == OP_NOT ? !nonzero : nonzero) ? Bytes{1} : Bytes{};
            }
            break;
        case 20:
            if (!stack.empty()) {
                script << OP_IFDUP;
                const Bytes value{stack.back()};
                cost += IfdupCost(value.size(), ContainsNonZero(value));
                if (ContainsNonZero(value)) stack.push_back(value);
            }
            break;
        case 21:
        case 22:
            if (!stack.empty()) {
                const size_t depth{provider.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(stack.size() - 1, 16))};
                Bytes encoded{ToLittleEndian(depth)};
                if (provider.ConsumeBool()) {
                    encoded.resize(provider.ConsumeIntegralInRange<size_t>(encoded.size(), encoded.size() + 8));
                }
                const opcodetype opcode{choice == 21 ? OP_PICK : OP_ROLL};
                script << encoded << opcode;
                const size_t index{stack.size() - 1 - depth};
                const Bytes value{stack[index]};
                cost += CopyingCost({encoded.size()});
                if (opcode == OP_PICK) {
                    cost += PickCost(encoded.size(), value.size());
                    stack.push_back(value);
                } else {
                    cost += RollCost(encoded.size(), depth);
                    stack.erase(stack.begin() + index);
                    stack.push_back(value);
                }
            }
            break;
        }
    }

    while (!altstack.empty()) {
        script << OP_FROMALTSTACK;
        cost += MovingCost(1);
        stack.push_back(std::move(altstack.back()));
        altstack.pop_back();
    }
    CheckExactEval(script, initial_stack, stack, cost);
}
} // namespace

FUZZ_TARGET(tapscript_v2_stack_programs)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    RunStackProgram(provider);
}
