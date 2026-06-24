// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_TAPSCRIPT_V2_H
#define BITCOIN_TEST_UTIL_TAPSCRIPT_V2_H

#include <addresstype.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>

#include <vector>

namespace test::tapscript_v2 {

using Stack = std::vector<std::vector<unsigned char>>;

inline constexpr script_verify_flags TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                                                                   SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_SCRIPT_RESTORATION};

inline CScriptWitness BuildTapscriptV2Witness(const CScript& leaf_script, const Stack& initial_stack, CScript& script_pub_key)
{
    TaprootBuilder builder;
    builder.Add(0, leaf_script, TAPROOT_LEAF_TAPSCRIPT_V2, /*track=*/true);
    builder.Finalize(XOnlyPubKey::NUMS_H);

    CScriptWitness witness;
    witness.stack = initial_stack;
    const std::vector<unsigned char> serialized_script{leaf_script.begin(), leaf_script.end()};
    witness.stack.push_back(serialized_script);
    const auto control_blocks{builder.GetSpendData().scripts.at({serialized_script, TAPROOT_LEAF_TAPSCRIPT_V2})};
    witness.stack.push_back(*control_blocks.begin());

    script_pub_key = GetScriptForDestination(builder.GetOutput());
    return witness;
}

} // namespace test::tapscript_v2

#endif // BITCOIN_TEST_UTIL_TAPSCRIPT_V2_H
