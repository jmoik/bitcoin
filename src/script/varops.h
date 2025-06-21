// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_VAROPS_H
#define BITCOIN_SCRIPT_VAROPS_H

#include <script/script.h>

#include <vector>

class Varops
{
public:
    static int64_t GetCost(opcodetype op, const std::vector<std::vector<unsigned char>>& stack);
};

#endif // BITCOIN_SCRIPT_VAROPS_H 