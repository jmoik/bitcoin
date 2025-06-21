// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/varops.h>

#include <script/script.h>

#include <algorithm>

int64_t Varops::GetCost(opcodetype op, const std::vector<std::vector<unsigned char>>& stack)
{
    switch (op) {

    // SIG OPS
    case OP_CHECKSIG:
    case OP_CHECKSIGVERIFY:
    case OP_CHECKMULTISIG:
    case OP_CHECKMULTISIGVERIFY:
        return VAROPS_COST_SIGOP;

    // COMPARINGZERO
    case OP_VERIFY:
    case OP_NOT:
    case OP_0NOTEQUAL:
        if (stack.empty()) return 0;
        return stack.back().size();

    // COMPARING
    case OP_EQUAL:
    case OP_EQUALVERIFY:
        if (stack.size() < 2) return 0;
        if (stack.back().size() != stack[stack.size() - 2].size()) return 0;
        return stack.back().size();

    // COPYING
    case OP_2DUP:
        if (stack.size() < 2) return 0;
        return stack.back().size() + stack[stack.size() - 2].size();
    case OP_3DUP:
        if (stack.size() < 3) return 0;
        return stack.back().size() + stack[stack.size() - 2].size() + stack[stack.size() - 3].size();
    case OP_2OVER:
        if (stack.size() < 4) return 0;
        return stack[stack.size() - 3].size() + stack[stack.size() - 4].size();
    case OP_IFDUP:
        if (stack.empty()) return 0;
        return stack.back().size() * 2;
    case OP_DUP:
        if (stack.empty()) return 0;
        return stack.back().size();
    case OP_OVER:
        if (stack.size() < 2) return 0;
        return stack[stack.size() - 2].size();
    case OP_PICK:
        // |Length of top stack entry + Length of N-th-from-top stack entry (before) (LENGTHCONV + COPYING)
        {
            if (stack.size() < 2) return 0;
            auto n = stack[stack.size() - 2];
            return stack.back().size() + n.size();
        }
    case OP_ROLL:
        if (stack.size() < 2) return 0;
        return stack.back().size();
    case OP_TUCK:
        if (stack.empty()) return 0;
        return stack.back().size();

    // COMPARINGZERO + COMPARING
    case OP_BOOLAND:
    case OP_BOOLOR:
        if (stack.size() < 2) return 0;
        return stack.back().size() + stack[stack.size() - 2].size();
    case OP_NUMEQUAL:
    case OP_NUMEQUALVERIFY:
    case OP_NUMNOTEQUAL:
    case OP_LESSTHAN:
    case OP_GREATERTHAN:
    case OP_LESSTHANOREQUAL:
    case OP_GREATERTHANOREQUAL:
    case OP_MIN:
    case OP_MAX:
        if (stack.size() < 2) return 0;
        return std::max(stack.back().size(), stack[stack.size() - 2].size());
    case OP_WITHIN:
        if (stack.size() < 3) return 0;
        return std::max(stack[stack.size() - 3].size(), stack[stack.size() - 2].size()) +
               std::max(stack[stack.size() - 3].size(), stack.back().size());

    // HASH
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256:
        if (stack.empty()) return 0;
        return stack.back().size() * VAROPS_COST_PER_BYTE_HASHED;

    default:
        return 0;
    }
} 