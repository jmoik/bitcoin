// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/varops.h>

#include <script/script.h>

#include <algorithm>

#define stacktop(i) (stack.at(size_t(int64_t(stack.size()) + int64_t{i})))

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
        return stacktop(-1).size();

    // COMPARING
    case OP_EQUAL:
    case OP_EQUALVERIFY:
        if (stack.size() < 2) return 0;
        if (stacktop(-1).size() != stacktop(-2).size()) return 0;
        return stacktop(-1).size();

    // COPYING
    case OP_2DUP:
        if (stack.size() < 2) return 0;
        return stacktop(-1).size() + stacktop(-2).size();
    case OP_3DUP:
        if (stack.size() < 3) return 0;
        return stacktop(-1).size() + stacktop(-2).size() + stacktop(-3).size();
    case OP_2OVER:
        if (stack.size() < 4) return 0;
        return stacktop(-3).size() + stacktop(-4).size();
    case OP_IFDUP:
        if (stack.empty()) return 0;
        return stacktop(-1).size() * 2;
    case OP_DUP:
        if (stack.empty()) return 0;
        return stacktop(-1).size();
    case OP_OVER:
        if (stack.size() < 2) return 0;
        return stacktop(-2).size();
    case OP_PICK:
        // |Length of top stack entry + Length of N-th-from-top stack entry (before) (LENGTHCONV + COPYING)
        {
            if (stack.size() < 2) return 0;

            int n = 0;
            try {
                n = CScriptNum(stacktop(-1), false, 4).getint();
            } catch (const scriptnum_error&) {
                return 0;
            }

            if (n < 0 || static_cast<size_t>(n) + 2 > stack.size()) {
                return 0;
            }

            return stacktop(-1).size() + stacktop(-2 - n).size();
        }
    case OP_ROLL:
        if (stack.size() < 2) return 0;
        return stacktop(-1).size();
    case OP_TUCK:
        if (stack.empty()) return 0;
        return stacktop(-1).size();

    // COMPARINGZERO + COMPARING
    case OP_BOOLAND:
    case OP_BOOLOR:
        if (stack.size() < 2) return 0;
        return stacktop(-1).size() + stacktop(-2).size();
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
        return std::max(stacktop(-1).size(), stacktop(-2).size());
    case OP_WITHIN:
        if (stack.size() < 3) return 0;
        return std::max(stacktop(-3).size(), stacktop(-2).size()) +
               std::max(stacktop(-3).size(), stacktop(-1).size());

    // HASH
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256:
        if (stack.empty()) return 0;
        return stacktop(-1).size() * VAROPS_COST_PER_BYTE_HASHED;

    default:
        return 0;
    }
} 