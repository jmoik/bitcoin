// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/script_tests.json.h>
#include <test/data/bip341_wallet_vectors.json.h>

#include <common/system.h>
#include <core_io.h>
#include <key.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/fs.h>
#include <util/strencodings.h>


#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>
#include <script/val64.h>

// Uncomment if you want to output updated JSON tests.
// #define UPDATE_JSON_TESTS

using namespace util::hex_literals;

static const unsigned int gFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

unsigned int ParseScriptFlags(std::string strFlags);
std::string FormatScriptFlags(unsigned int flags);

struct ScriptErrorDesc
{
    ScriptError_t err;
    const char *name;
};

static ScriptErrorDesc script_errors[]={
    {SCRIPT_ERR_OK, "OK"},
    {SCRIPT_ERR_UNKNOWN_ERROR, "UNKNOWN_ERROR"},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"},
    {SCRIPT_ERR_VERIFY, "VERIFY"},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"},
    {SCRIPT_ERR_WITNESS_PUBKEYTYPE, "WITNESS_PUBKEYTYPE"},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"},
};

static std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors)
        if (se.err == err)
            return se.name;
    BOOST_ERROR("Unknown scripterror enumeration value, update script_errors in script_tests.cpp.");
    return "";
}

static ScriptError_t ParseScriptError(const std::string& name)
{
    for (const auto& se : script_errors)
        if (se.name == name)
            return se.err;
    BOOST_ERROR("Unknown scripterror \"" << name << "\" in test description");
    return SCRIPT_ERR_UNKNOWN_ERROR;
}

struct ScriptTest : BasicTestingSetup {
void DoTest(const CScript& scriptPubKey, const CScript& scriptSig, const CScriptWitness& scriptWitness, uint32_t flags, const std::string& message, int scriptError, CAmount nValue = 0)
{
    bool expect = (scriptError == SCRIPT_ERR_OK);
    if (flags & SCRIPT_VERIFY_CLEANSTACK) {
        flags |= SCRIPT_VERIFY_P2SH;
        flags |= SCRIPT_VERIFY_WITNESS;
    }
    ScriptError err;
    const CTransaction txCredit{BuildCreditingTransaction(scriptPubKey, nValue)};
    CMutableTransaction tx = BuildSpendingTransaction(scriptSig, scriptWitness, txCredit);
    BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message);
    BOOST_CHECK_MESSAGE(err == scriptError, FormatScriptError(err) + " where " + FormatScriptError((ScriptError_t)scriptError) + " expected: " + message);

    // Verify that removing flags from a passing test or adding flags to a failing test does not change the result.
    for (int i = 0; i < 16; ++i) {
        uint32_t extra_flags(m_rng.randbits(16));
        uint32_t combined_flags{expect ? (flags & ~extra_flags) : (flags | extra_flags)};
        // Weed out some invalid flag combinations.
        if (combined_flags & SCRIPT_VERIFY_CLEANSTACK && ~combined_flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) continue;
        if (combined_flags & SCRIPT_VERIFY_WITNESS && ~combined_flags & SCRIPT_VERIFY_P2SH) continue;
        BOOST_CHECK_MESSAGE(VerifyScript(scriptSig, scriptPubKey, &scriptWitness, combined_flags, MutableTransactionSignatureChecker(&tx, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err) == expect, message + strprintf(" (with flags %x)", combined_flags));
    }
}
}; // struct ScriptTest

void static NegateSignatureS(std::vector<unsigned char>& vchSig) {
    // Parse the signature.
    std::vector<unsigned char> r, s;
    r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
    s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);

    // Really ugly to implement mod-n negation here, but it would be feature creep to expose such functionality from libsecp256k1.
    static const unsigned char order[33] = {
        0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };
    while (s.size() < 33) {
        s.insert(s.begin(), 0x00);
    }
    int carry = 0;
    for (int p = 32; p >= 1; p--) {
        int n = (int)order[p] - s[p] - carry;
        s[p] = (n + 256) & 0xFF;
        carry = (n < 0);
    }
    assert(carry == 0);
    if (s.size() > 1 && s[0] == 0 && s[1] < 0x80) {
        s.erase(s.begin());
    }

    // Reconstruct the signature.
    vchSig.clear();
    vchSig.push_back(0x30);
    vchSig.push_back(4 + r.size() + s.size());
    vchSig.push_back(0x02);
    vchSig.push_back(r.size());
    vchSig.insert(vchSig.end(), r.begin(), r.end());
    vchSig.push_back(0x02);
    vchSig.push_back(s.size());
    vchSig.insert(vchSig.end(), s.begin(), s.end());
}

namespace
{
const unsigned char vchKey0[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
const unsigned char vchKey1[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0};
const unsigned char vchKey2[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0};

struct KeyData
{
    CKey key0, key0C, key1, key1C, key2, key2C;
    CPubKey pubkey0, pubkey0C, pubkey0H;
    CPubKey pubkey1, pubkey1C;
    CPubKey pubkey2, pubkey2C;

    KeyData()
    {
        key0.Set(vchKey0, vchKey0 + 32, false);
        key0C.Set(vchKey0, vchKey0 + 32, true);
        pubkey0 = key0.GetPubKey();
        pubkey0H = key0.GetPubKey();
        pubkey0C = key0C.GetPubKey();
        *const_cast<unsigned char*>(pubkey0H.data()) = 0x06 | (pubkey0H[64] & 1);

        key1.Set(vchKey1, vchKey1 + 32, false);
        key1C.Set(vchKey1, vchKey1 + 32, true);
        pubkey1 = key1.GetPubKey();
        pubkey1C = key1C.GetPubKey();

        key2.Set(vchKey2, vchKey2 + 32, false);
        key2C.Set(vchKey2, vchKey2 + 32, true);
        pubkey2 = key2.GetPubKey();
        pubkey2C = key2C.GetPubKey();
    }
};

enum class WitnessMode {
    NONE,
    PKH,
    SH
};

class TestBuilder
{
private:
    //! Actually executed script
    CScript script;
    //! The P2SH redeemscript
    CScript redeemscript;
    //! The Witness embedded script
    CScript witscript;
    CScriptWitness scriptWitness;
    CTransactionRef creditTx;
    CMutableTransaction spendTx;
    bool havePush{false};
    std::vector<unsigned char> push;
    std::string comment;
    uint32_t flags;
    int scriptError{SCRIPT_ERR_OK};
    CAmount nValue;

    void DoPush()
    {
        if (havePush) {
            spendTx.vin[0].scriptSig << push;
            havePush = false;
        }
    }

    void DoPush(const std::vector<unsigned char>& data)
    {
        DoPush();
        push = data;
        havePush = true;
    }

public:
    TestBuilder(const CScript& script_, const std::string& comment_, uint32_t flags_, bool P2SH = false, WitnessMode wm = WitnessMode::NONE, int witnessversion = 0, CAmount nValue_ = 0) : script(script_), comment(comment_), flags(flags_), nValue(nValue_)
    {
        CScript scriptPubKey = script;
        if (wm == WitnessMode::PKH) {
            uint160 hash;
            CHash160().Write(Span{script}.subspan(1)).Finalize(hash);
            script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(hash) << OP_EQUALVERIFY << OP_CHECKSIG;
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        } else if (wm == WitnessMode::SH) {
            witscript = scriptPubKey;
            uint256 hash;
            CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        }
        if (P2SH) {
            redeemscript = scriptPubKey;
            scriptPubKey = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeemscript)) << OP_EQUAL;
        }
        creditTx = MakeTransactionRef(BuildCreditingTransaction(scriptPubKey, nValue));
        spendTx = BuildSpendingTransaction(CScript(), CScriptWitness(), *creditTx);
    }

    TestBuilder& ScriptError(ScriptError_t err)
    {
        scriptError = err;
        return *this;
    }

    TestBuilder& Opcode(const opcodetype& _op)
    {
        DoPush();
        spendTx.vin[0].scriptSig << _op;
        return *this;
    }

    TestBuilder& Num(int num)
    {
        DoPush();
        spendTx.vin[0].scriptSig << num;
        return *this;
    }

    TestBuilder& Push(const std::string& hex)
    {
        DoPush(ParseHex(hex));
        return *this;
    }

    TestBuilder& Push(const CScript& _script)
    {
        DoPush(std::vector<unsigned char>(_script.begin(), _script.end()));
        return *this;
    }

    TestBuilder& PushSig(const CKey& key, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::BASE, CAmount amount = 0)
    {
        uint256 hash = SignatureHash(script, spendTx, 0, nHashType, amount, sigversion);
        std::vector<unsigned char> vchSig, r, s;
        uint32_t iter = 0;
        do {
            key.Sign(hash, vchSig, false, iter++);
            if ((lenS == 33) != (vchSig[5 + vchSig[3]] == 33)) {
                NegateSignatureS(vchSig);
            }
            r = std::vector<unsigned char>(vchSig.begin() + 4, vchSig.begin() + 4 + vchSig[3]);
            s = std::vector<unsigned char>(vchSig.begin() + 6 + vchSig[3], vchSig.begin() + 6 + vchSig[3] + vchSig[5 + vchSig[3]]);
        } while (lenR != r.size() || lenS != s.size());
        vchSig.push_back(static_cast<unsigned char>(nHashType));
        DoPush(vchSig);
        return *this;
    }

    TestBuilder& PushWitSig(const CKey& key, CAmount amount = -1, int nHashType = SIGHASH_ALL, unsigned int lenR = 32, unsigned int lenS = 32, SigVersion sigversion = SigVersion::WITNESS_V0)
    {
        if (amount == -1)
            amount = nValue;
        return PushSig(key, nHashType, lenR, lenS, sigversion, amount).AsWit();
    }

    TestBuilder& Push(const CPubKey& pubkey)
    {
        DoPush(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));
        return *this;
    }

    TestBuilder& PushRedeem()
    {
        DoPush(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        return *this;
    }

    TestBuilder& PushWitRedeem()
    {
        DoPush(std::vector<unsigned char>(witscript.begin(), witscript.end()));
        return AsWit();
    }

    TestBuilder& EditPush(unsigned int pos, const std::string& hexin, const std::string& hexout)
    {
        assert(havePush);
        std::vector<unsigned char> datain = ParseHex(hexin);
        std::vector<unsigned char> dataout = ParseHex(hexout);
        assert(pos + datain.size() <= push.size());
        BOOST_CHECK_MESSAGE(std::vector<unsigned char>(push.begin() + pos, push.begin() + pos + datain.size()) == datain, comment);
        push.erase(push.begin() + pos, push.begin() + pos + datain.size());
        push.insert(push.begin() + pos, dataout.begin(), dataout.end());
        return *this;
    }

    TestBuilder& DamagePush(unsigned int pos)
    {
        assert(havePush);
        assert(pos < push.size());
        push[pos] ^= 1;
        return *this;
    }

    TestBuilder& Test(ScriptTest& test)
    {
        TestBuilder copy = *this; // Make a copy so we can rollback the push.
        DoPush();
        test.DoTest(creditTx->vout[0].scriptPubKey, spendTx.vin[0].scriptSig, scriptWitness, flags, comment, scriptError, nValue);
        *this = copy;
        return *this;
    }

    TestBuilder& AsWit()
    {
        assert(havePush);
        scriptWitness.stack.push_back(push);
        havePush = false;
        return *this;
    }

    UniValue GetJSON()
    {
        DoPush();
        UniValue array(UniValue::VARR);
        if (!scriptWitness.stack.empty()) {
            UniValue wit(UniValue::VARR);
            for (unsigned i = 0; i < scriptWitness.stack.size(); i++) {
                wit.push_back(HexStr(scriptWitness.stack[i]));
            }
            wit.push_back(ValueFromAmount(nValue));
            array.push_back(std::move(wit));
        }
        array.push_back(FormatScript(spendTx.vin[0].scriptSig));
        array.push_back(FormatScript(creditTx->vout[0].scriptPubKey));
        array.push_back(FormatScriptFlags(flags));
        array.push_back(FormatScriptError((ScriptError_t)scriptError));
        array.push_back(comment);
        return array;
    }

    std::string GetComment() const
    {
        return comment;
    }
};

std::string JSONPrettyPrint(const UniValue& univalue)
{
    std::string ret = univalue.write(4);
    // Workaround for libunivalue pretty printer, which puts a space between commas and newlines
    size_t pos = 0;
    while ((pos = ret.find(" \n", pos)) != std::string::npos) {
        ret.replace(pos, 2, "\n");
        pos++;
    }
    return ret;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, ScriptTest)

BOOST_AUTO_TEST_CASE(script_build)
{
    const KeyData keys;

    std::vector<TestBuilder> tests;

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK", 0
                               ).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK, bad sig", 0
                               ).PushSig(keys.key0).DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH", 0
                               ).PushSig(keys.key1).Push(keys.pubkey1C));
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey2C.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2PKH, bad pubkey", 0
                               ).PushSig(keys.key2).Push(keys.pubkey2C).DamagePush(5).ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK anyonecanpay marked with normal hashtype", 0
                               ).PushSig(keys.key1, SIGHASH_ALL | SIGHASH_ANYONECANPAY).EditPush(70, "81", "01").ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "P2SH(P2PK), bad redeemscript", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem().DamagePush(10).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey0.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH)", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).Push(keys.pubkey0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig but no VERIFY_P2SH", 0, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_DUP << OP_HASH160 << ToByteVector(keys.pubkey1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG,
                                "P2SH(P2PKH), bad sig", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).DamagePush(10).PushRedeem().ScriptError(SCRIPT_ERR_EQUALVERIFY));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3, 2 sigs", 0
                               ).Num(0).PushSig(keys.key0).PushSig(keys.key1).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3)", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key2).PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "P2SH(2-of-3), 1 sig", SCRIPT_VERIFY_P2SH, true
                               ).Num(0).PushSig(keys.key1).Num(0).PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too much S padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL).EditPush(1, "44", "45").EditPush(37, "20", "2100").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding but no DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "P2PK with too little R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with bad sig with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").DamagePush(10).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding but no DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with too much R padding", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL, 31, 32).EditPush(1, "43021F", "44022000").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 1, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, without DERSIG", 0
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 2, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, without DERSIG", 0
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 3, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, without DERSIG", 0
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 4, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, without DERSIG", 0
                               ).Num(1).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG,
                                "BIP66 example 5, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, without DERSIG", 0
                               ).Num(1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1C) << OP_CHECKSIG << OP_NOT,
                                "BIP66 example 6, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(1).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 7, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 8, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 9, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, without DERSIG", 0
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220"));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 10, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).Num(0).PushSig(keys.key2, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").ScriptError(SCRIPT_ERR_SIG_DER));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG,
                                "BIP66 example 11, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, without DERSIG", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_2 << OP_CHECKMULTISIG << OP_NOT,
                                "BIP66 example 12, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL, 33, 32).EditPush(1, "45022100", "440220").Num(0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, without DERSIG", 0
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101"));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with multi-byte hashtype, with DERSIG", SCRIPT_VERIFY_DERSIG
                               ).PushSig(keys.key2, SIGHASH_ALL).EditPush(70, "01", "0101").ScriptError(SCRIPT_ERR_SIG_DER));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S but no LOW_S", 0
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with high S", SCRIPT_VERIFY_LOW_S
                               ).PushSig(keys.key2, SIGHASH_ALL, 32, 33).ScriptError(SCRIPT_ERR_SIG_HIGH_S));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG,
                                "P2PK with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey but no STRICTENC", 0
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0H) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key0, SIGHASH_ALL).DamagePush(10).ScriptError(SCRIPT_ERR_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey and no STRICTENC", 0
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey0H) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the second 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0H) << OP_2 << OP_CHECKMULTISIG,
                                "1-of-2 with the first 1 hybrid pubkey", SCRIPT_VERIFY_STRICTENC
                               ).Num(0).PushSig(keys.key1, SIGHASH_ALL).ScriptError(SCRIPT_ERR_PUBKEYTYPE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "P2PK with undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype but no STRICTENC", 0
                               ).PushSig(keys.key1, 5).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG << OP_NOT,
                                "P2PK NOT with invalid sig and undefined hashtype", SCRIPT_VERIFY_STRICTENC
                               ).PushSig(keys.key1, 5).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_HASHTYPE));

    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG,
                                "3-of-3 with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig and nonzero dummy but no NULLDUMMY", 0
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10));
    tests.push_back(TestBuilder(CScript() << OP_3 << ToByteVector(keys.pubkey0C) << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey2C) << OP_3 << OP_CHECKMULTISIG << OP_NOT,
                                "3-of-3 NOT with invalid sig with nonzero dummy", SCRIPT_VERIFY_NULLDUMMY
                               ).Num(1).PushSig(keys.key0).PushSig(keys.key1).PushSig(keys.key2).DamagePush(10).ScriptError(SCRIPT_ERR_SIG_NULLDUMMY));

    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP but no SIGPUSHONLY", 0
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed using OP_DUP", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).Opcode(OP_DUP).ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no P2SH or SIGPUSHONLY", 0, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2PK with non-push scriptSig but with P2SH validation", 0
                               ).PushSig(keys.key2).Opcode(OP_NOP8));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but no SIGPUSHONLY", SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey2C) << OP_CHECKSIG,
                                "P2SH(P2PK) with non-push scriptSig but not P2SH", SCRIPT_VERIFY_SIGPUSHONLY, true
                               ).PushSig(keys.key2).Opcode(OP_NOP8).PushRedeem().ScriptError(SCRIPT_ERR_SIG_PUSHONLY));
    tests.push_back(TestBuilder(CScript() << OP_2 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey1C) << OP_2 << OP_CHECKMULTISIG,
                                "2-of-2 with two identical keys and sigs pushed", SCRIPT_VERIFY_SIGPUSHONLY
                               ).Num(0).PushSig(keys.key1).PushSig(keys.key1));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH
                               ).Num(11).PushSig(keys.key0).ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input but no CLEANSTACK", SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with unnecessary input", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).Num(11).PushSig(keys.key0).PushRedeem().ScriptError(SCRIPT_ERR_CLEANSTACK));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2SH with CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_P2SH, true
                               ).PushSig(keys.key0).PushRedeem());

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2WSH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2WPKH with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::SH
                               ).PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "Basic P2SH(P2WPKH) with the wrong key but no WITNESS", SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 0).PushWitSig(keys.key0, 1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH) with wrong value", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH,
                                0, 0).PushWitSig(keys.key0, 1).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_EVAL_FALSE));

    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with future witness version", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH |
                                SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, false, WitnessMode::PKH, 1
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0);
        uint256 hash;
        CSHA256().Write(witscript.data(), witscript.size()).Finalize(hash.begin());
        std::vector<unsigned char> hashBytes = ToByteVector(hash);
        hashBytes.pop_back();
        tests.push_back(TestBuilder(CScript() << OP_0 << hashBytes,
                                    "P2WPKH with wrong witness program length", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false
                                   ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2WSH with empty witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                               ).ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY));
    {
        CScript witscript = CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG;
        tests.push_back(TestBuilder(witscript,
                                    "P2WSH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH
                                   ).PushWitSig(keys.key0).Push(witscript).DamagePush(0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    }
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with witness program mismatch", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "P2WPKH with non-empty scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().Num(11).ScriptError(SCRIPT_ERR_WITNESS_MALLEATED));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey1),
                                "P2SH(P2WPKH) with superfluous push in scriptSig", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::PKH
                               ).PushWitSig(keys.key0).Push(keys.pubkey1).AsWit().Num(11).PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_MALLEATED_P2SH));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "P2PK with witness", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH
                               ).PushSig(keys.key0).Push("0").AsWit().ScriptError(SCRIPT_ERR_WITNESS_UNEXPECTED));

    // Compressed keys should pass SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2WSH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2WPKH with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0C),
                                "Basic P2SH(P2WPKH) with compressed key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0C).Push(keys.pubkey0C).AsWit().PushRedeem());

    // Testing uncompressed key in witness with SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2WSH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2WPKH", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0) << OP_CHECKSIG,
                                "Basic P2SH(P2WSH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << ToByteVector(keys.pubkey0),
                                "Basic P2SH(P2WPKH)", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::PKH,
                                0, 1).PushWitSig(keys.key0).Push(keys.pubkey0).AsWit().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    // P2WSH 1-of-2 multisig with compressed keys
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with compressed keys", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());

    // P2WSH 1-of-2 multisig with first key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1C) << ToByteVector(keys.pubkey0) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with first key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1C).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    // P2WSH 1-of-2 multisig with second key uncompressed
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG second key uncompressed and signing with the first key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the first key should pass as the uncompressed key is not used", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key0C).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem());
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2WSH CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, false, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));
    tests.push_back(TestBuilder(CScript() << OP_1 << ToByteVector(keys.pubkey1) << ToByteVector(keys.pubkey0C) << OP_2 << OP_CHECKMULTISIG,
                                "P2SH(P2WSH) CHECKMULTISIG with second key uncompressed and signing with the second key", SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE, true, WitnessMode::SH,
                                0, 1).Push(CScript()).AsWit().PushWitSig(keys.key1).PushWitRedeem().PushRedeem().ScriptError(SCRIPT_ERR_WITNESS_PUBKEYTYPE));

    std::set<std::string> tests_set;

    {
        UniValue json_tests = read_json(json_tests::script_tests);

        for (unsigned int idx = 0; idx < json_tests.size(); idx++) {
            const UniValue& tv = json_tests[idx];
            tests_set.insert(JSONPrettyPrint(tv.get_array()));
        }
    }

#ifdef UPDATE_JSON_TESTS
    std::string strGen;
#endif
    for (TestBuilder& test : tests) {
        test.Test(*this);
        std::string str = JSONPrettyPrint(test.GetJSON());
#ifdef UPDATE_JSON_TESTS
        strGen += str + ",\n";
#else
        if (tests_set.count(str) == 0) {
            BOOST_CHECK_MESSAGE(false, "Missing auto script_valid test: " + test.GetComment());
        }
#endif
    }

#ifdef UPDATE_JSON_TESTS
    FILE* file = fsbridge::fopen("script_tests.json.gen", "w");
    fputs(strGen.c_str(), file);
    fclose(file);
#endif
}

BOOST_AUTO_TEST_CASE(script_json_test)
{
    // Read tests from test/data/script_tests.json
    // Format is an array of arrays
    // Inner arrays are [ ["wit"..., nValue]?, "scriptSig", "scriptPubKey", "flags", "expected_scripterror" ]
    // ... where scriptSig and scriptPubKey are stringified
    // scripts.
    // If a witness is given, then the last value in the array should be the
    // amount (nValue) to use in the crediting tx
    UniValue tests = read_json(json_tests::script_tests);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        CScriptWitness witness;
        CAmount nValue = 0;
        unsigned int pos = 0;
        if (test.size() > 0 && test[pos].isArray()) {
            unsigned int i=0;
            for (i = 0; i < test[pos].size()-1; i++) {
                witness.stack.push_back(ParseHex(test[pos][i].get_str()));
            }
            nValue = AmountFromValue(test[pos][i]);
            pos++;
        }
        if (test.size() < 4 + pos) // Allow size > 3; extra stuff ignored (useful for comments)
        {
            if (test.size() != 1) {
                BOOST_ERROR("Bad test: " << strTest);
            }
            continue;
        }
        std::string scriptSigString = test[pos++].get_str();
        CScript scriptSig = ParseScript(scriptSigString);
        std::string scriptPubKeyString = test[pos++].get_str();
        CScript scriptPubKey = ParseScript(scriptPubKeyString);
        unsigned int scriptflags = ParseScriptFlags(test[pos++].get_str());
        int scriptError = ParseScriptError(test[pos++].get_str());

        DoTest(scriptPubKey, scriptSig, witness, scriptflags, strTest, scriptError, nValue);
    }
}

BOOST_AUTO_TEST_CASE(script_PushData)
{
    // Check that PUSHDATA1, PUSHDATA2, and PUSHDATA4 create the same value on
    // the stack as the 1-75 opcodes do.
    static const unsigned char direct[] = { 1, 0x5a };
    static const unsigned char pushdata1[] = { OP_PUSHDATA1, 1, 0x5a };
    static const unsigned char pushdata2[] = { OP_PUSHDATA2, 1, 0, 0x5a };
    static const unsigned char pushdata4[] = { OP_PUSHDATA4, 1, 0, 0, 0, 0x5a };

    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack;
    BOOST_CHECK(EvalScript(directStack, CScript(direct, direct + sizeof(direct)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata1Stack;
    BOOST_CHECK(EvalScript(pushdata1Stack, CScript(pushdata1, pushdata1 + sizeof(pushdata1)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata1Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata2Stack;
    BOOST_CHECK(EvalScript(pushdata2Stack, CScript(pushdata2, pushdata2 + sizeof(pushdata2)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata2Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    std::vector<std::vector<unsigned char> > pushdata4Stack;
    BOOST_CHECK(EvalScript(pushdata4Stack, CScript(pushdata4, pushdata4 + sizeof(pushdata4)), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK(pushdata4Stack == directStack);
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    const std::vector<unsigned char> pushdata1_trunc{OP_PUSHDATA1, 1};
    const std::vector<unsigned char> pushdata2_trunc{OP_PUSHDATA2, 1, 0};
    const std::vector<unsigned char> pushdata4_trunc{OP_PUSHDATA4, 1, 0, 0, 0};

    std::vector<std::vector<unsigned char>> stack_ignore;
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata1_trunc.begin(), pushdata1_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata2_trunc.begin(), pushdata2_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!EvalScript(stack_ignore, CScript(pushdata4_trunc.begin(), pushdata4_trunc.end()), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(script_cltv_truncated)
{
    const auto script_cltv_trunc = CScript() << OP_CHECKLOCKTIMEVERIFY;

    std::vector<std::vector<unsigned char>> stack_ignore;
    ScriptError err;
    BOOST_CHECK(!EvalScript(stack_ignore, script_cltv_trunc, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, BaseSignatureChecker(), SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

static CScript
sign_multisig(const CScript& scriptPubKey, const std::vector<CKey>& keys, const CTransaction& transaction)
{
    uint256 hash = SignatureHash(scriptPubKey, transaction, 0, SIGHASH_ALL, 0, SigVersion::BASE);

    CScript result;
    //
    // NOTE: CHECKMULTISIG has an unfortunate bug; it requires
    // one extra item on the stack, before the signatures.
    // Putting OP_0 on the stack is the workaround;
    // fixing the bug would mean splitting the block chain (old
    // clients would not accept new CHECKMULTISIG transactions,
    // and vice-versa)
    //
    result << OP_0;
    for (const CKey &key : keys)
    {
        std::vector<unsigned char> vchSig;
        BOOST_CHECK(key.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        result << vchSig;
    }
    return result;
}
static CScript
sign_multisig(const CScript& scriptPubKey, const CKey& key, const CTransaction& transaction)
{
    std::vector<CKey> keys;
    keys.push_back(key);
    return sign_multisig(scriptPubKey, keys, transaction);
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG12)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();

    CScript scriptPubKey12;
    scriptPubKey12 << OP_1 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    const CTransaction txFrom12{BuildCreditingTransaction(scriptPubKey12)};
    CMutableTransaction txTo12 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom12);

    CScript goodsig1 = sign_multisig(scriptPubKey12, key1, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    txTo12.vout[0].nValue = 2;
    BOOST_CHECK(!VerifyScript(goodsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    CScript goodsig2 = sign_multisig(scriptPubKey12, key2, CTransaction(txTo12));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    CScript badsig1 = sign_multisig(scriptPubKey12, key3, CTransaction(txTo12));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey12, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo12, 0, txFrom12.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));
}

BOOST_AUTO_TEST_CASE(script_CHECKMULTISIG23)
{
    ScriptError err;
    CKey key1 = GenerateRandomKey();
    CKey key2 = GenerateRandomKey(/*compressed=*/false);
    CKey key3 = GenerateRandomKey();
    CKey key4 = GenerateRandomKey(/*compressed=*/false);

    CScript scriptPubKey23;
    scriptPubKey23 << OP_2 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << ToByteVector(key3.GetPubKey()) << OP_3 << OP_CHECKMULTISIG;

    const CTransaction txFrom23{BuildCreditingTransaction(scriptPubKey23)};
    CMutableTransaction txTo23 = BuildSpendingTransaction(CScript(), CScriptWitness(), txFrom23);

    std::vector<CKey> keys;
    keys.push_back(key1); keys.push_back(key2);
    CScript goodsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key3);
    CScript goodsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key3);
    CScript goodsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(VerifyScript(goodsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key2); // Can't reuse sig
    CScript badsig1 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig1, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key2); keys.push_back(key1); // sigs must be in correct order
    CScript badsig2 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig2, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key3); keys.push_back(key2); // sigs must be in correct order
    CScript badsig3 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig3, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key4); keys.push_back(key2); // sigs must match pubkeys
    CScript badsig4 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig4, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear();
    keys.push_back(key1); keys.push_back(key4); // sigs must match pubkeys
    CScript badsig5 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig5, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_EVAL_FALSE, ScriptErrorString(err));

    keys.clear(); // Must have signatures
    CScript badsig6 = sign_multisig(scriptPubKey23, keys, CTransaction(txTo23));
    BOOST_CHECK(!VerifyScript(badsig6, scriptPubKey23, nullptr, gFlags, MutableTransactionSignatureChecker(&txTo23, 0, txFrom23.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL), &err));
    BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_INVALID_STACK_OPERATION, ScriptErrorString(err));
}

/* Wrapper around ProduceSignature to combine two scriptsigs */
SignatureData CombineSignatures(const CTxOut& txout, const CMutableTransaction& tx, const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    SignatureData data;
    data.MergeSignatureData(scriptSig1);
    data.MergeSignatureData(scriptSig2);
    ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(tx, 0, txout.nValue, SIGHASH_DEFAULT), txout.scriptPubKey, data);
    return data;
}

BOOST_AUTO_TEST_CASE(script_combineSigs)
{
    // Test the ProduceSignature's ability to combine signatures function
    FillableSigningProvider keystore;
    std::vector<CKey> keys;
    std::vector<CPubKey> pubkeys;
    for (int i = 0; i < 3; i++)
    {
        CKey key = GenerateRandomKey(/*compressed=*/i%2 == 1);
        keys.push_back(key);
        pubkeys.push_back(key.GetPubKey());
        BOOST_CHECK(keystore.AddKey(key));
    }

    CMutableTransaction txFrom = BuildCreditingTransaction(GetScriptForDestination(PKHash(keys[0].GetPubKey())));
    CMutableTransaction txTo = BuildSpendingTransaction(CScript(), CScriptWitness(), CTransaction(txFrom));
    CScript& scriptPubKey = txFrom.vout[0].scriptPubKey;
    SignatureData scriptSig;

    SignatureData empty;
    SignatureData combined = CombineSignatures(txFrom.vout[0], txTo, empty, empty);
    BOOST_CHECK(combined.scriptSig.empty());

    // Single signature case:
    SignatureData dummy;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy)); // changes scriptSig
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    SignatureData scriptSigCopy = scriptSig;
    // Signing again will give a different, valid signature:
    SignatureData dummy_b;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_b));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // P2SH, single-signature case:
    CScript pkSingle; pkSingle << ToByteVector(keys[0].GetPubKey()) << OP_CHECKSIG;
    BOOST_CHECK(keystore.AddCScript(pkSingle));
    scriptPubKey = GetScriptForDestination(ScriptHash(pkSingle));
    SignatureData dummy_c;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_c));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    scriptSigCopy = scriptSig;
    SignatureData dummy_d;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_d));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSigCopy, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSigCopy.scriptSig || combined.scriptSig == scriptSig.scriptSig);

    // Hardest case:  Multisig 2-of-3
    scriptPubKey = GetScriptForMultisig(2, pubkeys);
    BOOST_CHECK(keystore.AddCScript(scriptPubKey));
    SignatureData dummy_e;
    BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0, SIGHASH_ALL, dummy_e));
    scriptSig = DataFromTransaction(txTo, 0, txFrom.vout[0]);
    combined = CombineSignatures(txFrom.vout[0], txTo, scriptSig, empty);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);
    combined = CombineSignatures(txFrom.vout[0], txTo, empty, scriptSig);
    BOOST_CHECK(combined.scriptSig == scriptSig.scriptSig);

    // A couple of partially-signed versions:
    std::vector<unsigned char> sig1;
    uint256 hash1 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_ALL, 0, SigVersion::BASE);
    BOOST_CHECK(keys[0].Sign(hash1, sig1));
    sig1.push_back(SIGHASH_ALL);
    std::vector<unsigned char> sig2;
    uint256 hash2 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_NONE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[1].Sign(hash2, sig2));
    sig2.push_back(SIGHASH_NONE);
    std::vector<unsigned char> sig3;
    uint256 hash3 = SignatureHash(scriptPubKey, txTo, 0, SIGHASH_SINGLE, 0, SigVersion::BASE);
    BOOST_CHECK(keys[2].Sign(hash3, sig3));
    sig3.push_back(SIGHASH_SINGLE);

    // Not fussy about order (or even existence) of placeholders or signatures:
    CScript partial1a = CScript() << OP_0 << sig1 << OP_0;
    CScript partial1b = CScript() << OP_0 << OP_0 << sig1;
    CScript partial2a = CScript() << OP_0 << sig2;
    CScript partial2b = CScript() << sig2 << OP_0;
    CScript partial3a = CScript() << sig3;
    CScript partial3b = CScript() << OP_0 << OP_0 << sig3;
    CScript partial3c = CScript() << OP_0 << sig3 << OP_0;
    CScript complete12 = CScript() << OP_0 << sig1 << sig2;
    CScript complete13 = CScript() << OP_0 << sig1 << sig3;
    CScript complete23 = CScript() << OP_0 << sig2 << sig3;
    SignatureData partial1_sigs;
    partial1_sigs.signatures.emplace(keys[0].GetPubKey().GetID(), SigPair(keys[0].GetPubKey(), sig1));
    SignatureData partial2_sigs;
    partial2_sigs.signatures.emplace(keys[1].GetPubKey().GetID(), SigPair(keys[1].GetPubKey(), sig2));
    SignatureData partial3_sigs;
    partial3_sigs.signatures.emplace(keys[2].GetPubKey().GetID(), SigPair(keys[2].GetPubKey(), sig3));

    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == partial1a);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial1_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete12);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial1_sigs);
    BOOST_CHECK(combined.scriptSig == complete13);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial2_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial2_sigs);
    BOOST_CHECK(combined.scriptSig == complete23);
    combined = CombineSignatures(txFrom.vout[0], txTo, partial3_sigs, partial3_sigs);
    BOOST_CHECK(combined.scriptSig == partial3c);
}

/**
 * Reproduction of an exception incorrectly raised when parsing a public key inside a TapMiniscript.
 */
BOOST_AUTO_TEST_CASE(sign_invalid_miniscript)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;

    // Create a Taproot output which contains a leaf in which a non-32 bytes push is used where a public key is expected
    // by the Miniscript parser. This offending Script was found by the RPC fuzzer.
    const auto invalid_pubkey{"173d36c8c9c9c9ffffffffffff0200000000021e1e37373721361818181818181e1e1e1e19000000000000000000b19292929292926b006c9b9b9292"_hex_u8};
    TaprootBuilder builder;
    builder.Add(0, {invalid_pubkey}, 0xc0);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    prev.vout.emplace_back(0, GetScriptForDestination(builder.GetOutput()));
    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});
    sig_data.tr_spenddata = builder.GetSpendData();

    // SignSignature can fail but it shouldn't raise an exception (nor crash).
    BOOST_CHECK(!SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

/* P2A input should be considered signed. */
BOOST_AUTO_TEST_CASE(sign_paytoanchor)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;
    prev.vout.emplace_back(0, GetScriptForDestination(PayToAnchor{}));

    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});

    BOOST_CHECK(SignSignature(keystore, CTransaction(prev), curr, 0, SIGHASH_ALL, sig_data));
}

BOOST_AUTO_TEST_CASE(script_standard_push)
{
    ScriptError err;
    for (int i=0; i<67000; i++) {
        CScript script;
        script << i;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Number " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Number " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }

    for (unsigned int i=0; i<=MAX_SCRIPT_ELEMENT_SIZE; i++) {
        std::vector<unsigned char> data(i, '\111');
        CScript script;
        script << data;
        BOOST_CHECK_MESSAGE(script.IsPushOnly(), "Length " << i << " is not pure push.");
        BOOST_CHECK_MESSAGE(VerifyScript(script, CScript() << OP_1, nullptr, SCRIPT_VERIFY_MINIMALDATA, BaseSignatureChecker(), &err), "Length " << i << " push is not minimal data.");
        BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(script_IsPushOnly_on_invalid_scripts)
{
    // IsPushOnly returns false when given a script containing only pushes that
    // are invalid due to truncation. IsPushOnly() is consensus critical
    // because P2SH evaluation uses it, although this specific behavior should
    // not be consensus critical as the P2SH evaluation would fail first due to
    // the invalid push. Still, it doesn't hurt to test it explicitly.
    static const unsigned char direct[] = { 1 };
    BOOST_CHECK(!CScript(direct, direct+sizeof(direct)).IsPushOnly());
}

BOOST_AUTO_TEST_CASE(script_GetScriptAsm)
{
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY, true));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_NOP2));
    BOOST_CHECK_EQUAL("OP_CHECKLOCKTIMEVERIFY", ScriptToAsmStr(CScript() << OP_CHECKLOCKTIMEVERIFY));

    std::string derSig("304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090");
    std::string pubKey("03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2");
    std::vector<unsigned char> vchPubKey = ToByteVector(ParseHex(pubKey));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[ALL|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[NONE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey, true));
    BOOST_CHECK_EQUAL(derSig + "[SINGLE|ANYONECANPAY] " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey, true));

    BOOST_CHECK_EQUAL(derSig + "00 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "00")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "80 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "80")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "01 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "01")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "02 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "02")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "03 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "03")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "81 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "81")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "82 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "82")) << vchPubKey));
    BOOST_CHECK_EQUAL(derSig + "83 " + pubKey, ScriptToAsmStr(CScript() << ToByteVector(ParseHex(derSig + "83")) << vchPubKey));
}

template <typename T>
CScript ToScript(const T& byte_container)
{
    auto span{MakeUCharSpan(byte_container)};
    return {span.begin(), span.end()};
}

static CScript ScriptFromHex(const std::string& str)
{
    return ToScript(*Assert(TryParseHex(str)));
}

BOOST_AUTO_TEST_CASE(script_byte_array_u8_vector_equivalence)
{
    const CScript scriptPubKey1 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex_v_u8 << OP_CHECKSIG;
    const CScript scriptPubKey2 = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    BOOST_CHECK(scriptPubKey1 == scriptPubKey2);
}

BOOST_AUTO_TEST_CASE(script_FindAndDelete)
{
    // Exercise the FindAndDelete functionality
    CScript s;
    CScript d;
    CScript expect;

    s = CScript() << OP_1 << OP_2;
    d = CScript(); // delete nothing should be a no-op
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_1 << OP_2 << OP_3;
    d = CScript() << OP_2;
    expect = CScript() << OP_1 << OP_3;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3;
    d = CScript() << OP_3;
    expect = CScript() << OP_1 << OP_4;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 4);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff03"_hex); // PUSH 0x02ff03 onto stack
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex); // PUSH 0x02ff03 PUSH 0x02ff03
    d = ToScript("0302ff03"_hex);
    expect = CScript();
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("02"_hex);
    expect = s; // FindAndDelete matches entire opcodes
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("ff"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    // This is an odd edge case: strip of the push-three-bytes
    // prefix, leaving 02ff03 which is push-two-bytes:
    s = ToScript("0302ff030302ff03"_hex);
    d = ToScript("03"_hex);
    expect = CScript() << "ff03"_hex << "ff03"_hex;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Byte sequence that spans multiple opcodes:
    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0); // doesn't match 'inside' opcodes
    BOOST_CHECK(s == expect);

    s = ToScript("02feed5169"_hex); // PUSH(0xfeed) OP_1 OP_VERIFY
    d = ToScript("02feed51"_hex);
    expect = ToScript("69"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("feed51"_hex);
    expect = s;
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 0);
    BOOST_CHECK(s == expect);

    s = ToScript("516902feed5169"_hex);
    d = ToScript("02feed51"_hex);
    expect = ToScript("516969"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = CScript() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1;
    d = CScript() << OP_0 << OP_1;
    expect = CScript() << OP_0 << OP_1; // FindAndDelete is single-pass
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 2);
    BOOST_CHECK(s == expect);

    // Another weird edge case:
    // End with invalid push (not enough data)...
    s = ToScript("0003feed"_hex);
    d = ToScript("03feed"_hex); // ... can remove the invalid push
    expect = ToScript("00"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);

    s = ToScript("0003feed"_hex);
    d = ToScript("00"_hex);
    expect = ToScript("03feed"_hex);
    BOOST_CHECK_EQUAL(FindAndDelete(s, d), 1);
    BOOST_CHECK(s == expect);
}

BOOST_AUTO_TEST_CASE(script_HasValidOps)
{
    // Exercise the HasValidOps functionality
    CScript script;
    script = ToScript("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex); // Normal script
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("76a914ff34567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac"_hex);
    BOOST_CHECK(script.HasValidOps());
    script = ToScript("ff88ac"_hex); // Script with OP_INVALIDOPCODE explicit
    BOOST_CHECK(!script.HasValidOps());
    script = ToScript("88acc0"_hex); // Script with undefined opcode
    BOOST_CHECK(!script.HasValidOps());
}

static CMutableTransaction TxFromHex(const std::string& str)
{
    CMutableTransaction tx;
    SpanReader{ParseHex(str)} >> TX_NO_WITNESS(tx);
    return tx;
}

static std::vector<CTxOut> TxOutsFromJSON(const UniValue& univalue)
{
    assert(univalue.isArray());
    std::vector<CTxOut> prevouts;
    for (size_t i = 0; i < univalue.size(); ++i) {
        CTxOut txout;
        SpanReader{ParseHex(univalue[i].get_str())} >> txout;
        prevouts.push_back(std::move(txout));
    }
    return prevouts;
}

static CScriptWitness ScriptWitnessFromJSON(const UniValue& univalue)
{
    assert(univalue.isArray());
    CScriptWitness scriptwitness;
    for (size_t i = 0; i < univalue.size(); ++i) {
        auto bytes = ParseHex(univalue[i].get_str());
        scriptwitness.stack.push_back(std::move(bytes));
    }
    return scriptwitness;
}

static std::vector<unsigned int> AllConsensusFlags()
{
    std::vector<unsigned int> ret;

    for (unsigned int i = 0; i < 128; ++i) {
        unsigned int flag = 0;
        if (i & 1) flag |= SCRIPT_VERIFY_P2SH;
        if (i & 2) flag |= SCRIPT_VERIFY_DERSIG;
        if (i & 4) flag |= SCRIPT_VERIFY_NULLDUMMY;
        if (i & 8) flag |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        if (i & 16) flag |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        if (i & 32) flag |= SCRIPT_VERIFY_WITNESS;
        if (i & 64) flag |= SCRIPT_VERIFY_TAPROOT;

        // SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH
        if (flag & SCRIPT_VERIFY_WITNESS && !(flag & SCRIPT_VERIFY_P2SH)) continue;
        // SCRIPT_VERIFY_TAPROOT requires SCRIPT_VERIFY_WITNESS
        if (flag & SCRIPT_VERIFY_TAPROOT && !(flag & SCRIPT_VERIFY_WITNESS)) continue;

        ret.push_back(flag);
    }

    return ret;
}

/** Precomputed list of all valid combinations of consensus-relevant script validation flags. */
static const std::vector<unsigned int> ALL_CONSENSUS_FLAGS = AllConsensusFlags();

static void AssetTest(const UniValue& test, SignatureCache& signature_cache)
{
    BOOST_CHECK(test.isObject());

    CMutableTransaction mtx = TxFromHex(test["tx"].get_str());
    const std::vector<CTxOut> prevouts = TxOutsFromJSON(test["prevouts"]);
    BOOST_CHECK(prevouts.size() == mtx.vin.size());
    size_t idx = test["index"].getInt<int64_t>();
    uint32_t test_flags{ParseScriptFlags(test["flags"].get_str())};
    bool fin = test.exists("final") && test["final"].get_bool();

    if (test.exists("success")) {
        mtx.vin[idx].scriptSig = ScriptFromHex(test["success"]["scriptSig"].get_str());
        mtx.vin[idx].scriptWitness = ScriptWitnessFromJSON(test["success"]["witness"]);
        CTransaction tx(mtx);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(prevouts));
        CachingTransactionSignatureChecker txcheck(&tx, idx, prevouts[idx].nValue, true, signature_cache, txdata);

        for (const auto flags : ALL_CONSENSUS_FLAGS) {
            // "final": true tests are valid for all flags. Others are only valid with flags that are
            // a subset of test_flags.
            if (fin || ((flags & test_flags) == flags)) {
                bool ret = VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags, txcheck, nullptr);
                BOOST_CHECK(ret);
            }
        }
    }

    if (test.exists("failure")) {
        mtx.vin[idx].scriptSig = ScriptFromHex(test["failure"]["scriptSig"].get_str());
        mtx.vin[idx].scriptWitness = ScriptWitnessFromJSON(test["failure"]["witness"]);
        CTransaction tx(mtx);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(prevouts));
        CachingTransactionSignatureChecker txcheck(&tx, idx, prevouts[idx].nValue, true, signature_cache, txdata);

        for (const auto flags : ALL_CONSENSUS_FLAGS) {
            // If a test is supposed to fail with test_flags, it should also fail with any superset thereof.
            if ((flags & test_flags) == test_flags) {
                bool ret = VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags, txcheck, nullptr);
                BOOST_CHECK(!ret);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(script_assets_test)
{
    // See src/test/fuzz/script_assets_test_minimizer.cpp for information on how to generate
    // the script_assets_test.json file used by this test.
    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    const char* dir = std::getenv("DIR_UNIT_TEST_DATA");
    BOOST_WARN_MESSAGE(dir != nullptr, "Variable DIR_UNIT_TEST_DATA unset, skipping script_assets_test");
    if (dir == nullptr) return;
    auto path = fs::path(dir) / "script_assets_test.json";
    bool exists = fs::exists(path);
    BOOST_WARN_MESSAGE(exists, "File $DIR_UNIT_TEST_DATA/script_assets_test.json not found, skipping script_assets_test");
    if (!exists) return;
    std::ifstream file{path};
    BOOST_CHECK(file.is_open());
    file.seekg(0, std::ios::end);
    size_t length = file.tellg();
    file.seekg(0, std::ios::beg);
    std::string data(length, '\0');
    file.read(data.data(), data.size());
    UniValue tests = read_json(data);
    BOOST_CHECK(tests.isArray());
    BOOST_CHECK(tests.size() > 0);

    for (size_t i = 0; i < tests.size(); i++) {
        AssetTest(tests[i], signature_cache);
    }
    file.close();
}

BOOST_AUTO_TEST_CASE(bip341_keypath_test_vectors)
{
    UniValue tests;
    tests.read(json_tests::bip341_wallet_vectors);

    const auto& vectors = tests["keyPathSpending"];

    for (const auto& vec : vectors.getValues()) {
        auto txhex = ParseHex(vec["given"]["rawUnsignedTx"].get_str());
        CMutableTransaction tx;
        SpanReader{txhex} >> TX_WITH_WITNESS(tx);
        std::vector<CTxOut> utxos;
        for (const auto& utxo_spent : vec["given"]["utxosSpent"].getValues()) {
            auto script_bytes = ParseHex(utxo_spent["scriptPubKey"].get_str());
            CScript script{script_bytes.begin(), script_bytes.end()};
            CAmount amount{utxo_spent["amountSats"].getInt<int>()};
            utxos.emplace_back(amount, script);
        }

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{utxos}, true);

        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_amounts_single_hash), vec["intermediary"]["hashAmounts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_outputs_single_hash), vec["intermediary"]["hashOutputs"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_prevouts_single_hash), vec["intermediary"]["hashPrevouts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_scripts_single_hash), vec["intermediary"]["hashScriptPubkeys"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_sequences_single_hash), vec["intermediary"]["hashSequences"].get_str());

        for (const auto& input : vec["inputSpending"].getValues()) {
            int txinpos = input["given"]["txinIndex"].getInt<int>();
            int hashtype = input["given"]["hashType"].getInt<int>();

            // Load key.
            auto privkey = ParseHex(input["given"]["internalPrivkey"].get_str());
            CKey key;
            key.Set(privkey.begin(), privkey.end(), true);

            // Load Merkle root.
            uint256 merkle_root;
            if (!input["given"]["merkleRoot"].isNull()) {
                merkle_root = uint256{ParseHex(input["given"]["merkleRoot"].get_str())};
            }

            // Compute and verify (internal) public key.
            XOnlyPubKey pubkey{key.GetPubKey()};
            BOOST_CHECK_EQUAL(HexStr(pubkey), input["intermediary"]["internalPubkey"].get_str());

            // Sign and verify signature.
            FlatSigningProvider provider;
            provider.keys[key.GetPubKey().GetID()] = key;
            MutableTransactionSignatureCreator creator(tx, txinpos, utxos[txinpos].nValue, &txdata, hashtype);
            std::vector<unsigned char> signature;
            BOOST_CHECK(creator.CreateSchnorrSig(provider, signature, pubkey, nullptr, &merkle_root, SigVersion::TAPROOT));
            BOOST_CHECK_EQUAL(HexStr(signature), input["expected"]["witness"][0].get_str());

            // We can't observe the tweak used inside the signing logic, so verify by recomputing it.
            BOOST_CHECK_EQUAL(HexStr(pubkey.ComputeTapTweakHash(merkle_root.IsNull() ? nullptr : &merkle_root)), input["intermediary"]["tweak"].get_str());

            // We can't observe the sighash used inside the signing logic, so verify by recomputing it.
            ScriptExecutionData sed;
            sed.m_annex_init = true;
            sed.m_annex_present = false;
            uint256 sighash;
            BOOST_CHECK(SignatureHashSchnorr(sighash, sed, tx, txinpos, hashtype, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
            BOOST_CHECK_EQUAL(HexStr(sighash), input["intermediary"]["sigHash"].get_str());

            // To verify the sigmsg, hash the expected sigmsg, and compare it with the (expected) sighash.
            BOOST_CHECK_EQUAL(HexStr((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{ParseHex(input["intermediary"]["sigMsg"].get_str())}).GetSHA256()), input["intermediary"]["sigHash"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(compute_tapbranch)
{
    constexpr uint256 hash1{"8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7"};
    constexpr uint256 hash2{"f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a"};
    constexpr uint256 result{"a64c5b7b943315f9b805d7a7296bedfcfd08919270a1f7a1466e98f8693d8cd9"};
    BOOST_CHECK_EQUAL(ComputeTapbranchHash(hash1, hash2), result);
}

BOOST_AUTO_TEST_CASE(compute_tapleaf)
{
    constexpr uint8_t script[6] = {'f','o','o','b','a','r'};
    constexpr uint256 tlc0{"edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06"};
    constexpr uint256 tlc2{"8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a"};

    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc0, Span(script)), tlc0);
    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc2, Span(script)), tlc2);
}

static size_t get_val(size_t default_val, const char *var)
{
	const char *env = getenv(var);
	if (!env || atol(env) == 0)
		return default_val;
	return atol(env);
}

static void BenchEvalScript(const CScript &script,
                            const std::vector<unsigned char> &op1,
                            const std::vector<unsigned char> &op2,
                            const char *name)
{
	BaseSignatureChecker checker;
	ScriptExecutionData sdata;
	ScriptError serror;
	size_t cooling = get_val(0, "EVALSCRIPT_COOLING_BYTES");

	std::vector<unsigned char> cool1(cooling/2, cooling/7), cool2(cooling/2, cooling/15);
    if (cooling/2)
        std::cerr << "Cooling using " << cooling << "bytes!" << std::endl;

    using namespace std::chrono;

	// auto start = high_resolution_clock::now();
	for (int i = 0; i < 10; ++i) {
		std::vector<std::vector<unsigned char> > stack(2);

		stack[0] = op2;
        for (size_t i = 0; i < stack[0].size(); i++)
            stack[0][i] += cooling++;

		// In case we want to clear cache.
        for (size_t i = 0; i < cool1.size(); i++) {
            cool1[i] += cooling; 
            cool2[i] += cooling;
        }

		// Set up stack: this does a copy, so these won't be cold.
		stack[1] = op1;
        for (size_t i = 0; i < stack[1].size(); i++)
            stack[1][i] += cooling++;

        uint64_t* varops_budget = new uint64_t(1e10);
        if (!EvalScript(stack, script, 0, checker,
						SigVersion::TAPSCRIPT_V2, sdata, &serror, varops_budget)) {
			std::cerr << "EvalScript error " << ScriptErrorString(serror) << std::endl;
			assert(0);
		}
	}
	// auto stop = high_resolution_clock::now();
	// auto msec = duration_cast<milliseconds>(stop - start).count();

    assert(cooling);
	// std::cerr << "Time elapsed for: " << name << "(10x) is " << msec << " ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(invert_cold)
{
	std::vector<unsigned char> op1(4000000), op2(4000000);
	CScript script;

	script << OP_DROP << OP_INVERT;

	BenchEvalScript(script, op1, op2, "invert_cold");
}

BOOST_AUTO_TEST_CASE(invert_hot)
{
	std::vector<unsigned char> op1(4000000), op2(4000000);
	CScript script;

	script << OP_INVERT;

	BenchEvalScript(script, op1, op2, "invert_hot");
}

BOOST_AUTO_TEST_CASE(valtype_stack_size_tracking)
{
    // Test ValtypeStack size tracking during Val64 operations
    
    // Define stacktop macro like in interpreter.cpp
    #define stacktop(i) (stack.at(size_t(int64_t(stack.size()) + int64_t{i})))
    
    // Test 1: Basic size tracking with OP_ADD
    {
        ValtypeStack stack;
        
        // Add two 8-byte numbers
        Val64 v1(0x123456789ABCDEF0ULL);
        Val64 v2(0x1111111111111111ULL);
        
        auto vec1 = v1.move_to_valtype();
        auto vec2 = v2.move_to_valtype();
        
        size_t initial_size1 = vec1.size();
        size_t initial_size2 = vec2.size();
        
        stack.push_back(vec1);
        stack.push_back(vec2);
        
        // Verify initial tracking
        BOOST_CHECK_EQUAL(stack.get_total_size(), initial_size1 + initial_size2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max(initial_size1, initial_size2));
        
        // Perform addition that modifies top element in place
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        CScript script;
        script << OP_ADD;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        // Update stack with result and verify size tracking
        stack = ValtypeStack(plain_stack);
        
        BOOST_CHECK_EQUAL(stack.size(), 1);
        size_t result_size = stacktop(-1).size();
        BOOST_CHECK_EQUAL(stack.get_total_size(), result_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), result_size);
    }
    
    // Test 2: Size tracking with OP_MUL producing larger result
    {
        ValtypeStack stack;
        
        // Multiply two numbers to get a larger result
        Val64 v1(0xFFFFFFFFFFFFFFFFULL);  // Large number
        Val64 v2(0xFFFFFFFFFFFFFFFFULL);  // Large number
        
        auto vec1 = v1.move_to_valtype();
        auto vec2 = v2.move_to_valtype();
        
        stack.push_back(vec1);
        stack.push_back(vec2);
        
        // Perform multiplication
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        CScript script;
        script << OP_MUL;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        // Update stack with result
        stack = ValtypeStack(plain_stack);
        
        BOOST_CHECK_EQUAL(stack.size(), 1);
        size_t result_size = stacktop(-1).size();
        
        // Result should be larger than either input (8 bytes each)
        BOOST_CHECK(result_size >= 8);
        BOOST_CHECK_EQUAL(stack.get_total_size(), result_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), result_size);
    }
    
    // Test 3: Multiple operations tracking max element size correctly
    {
        ValtypeStack stack;
        
        // Add elements of different sizes
        std::vector<unsigned char> small_elem(10, 0x42);  // 10 bytes
        std::vector<unsigned char> medium_elem(50, 0x43); // 50 bytes  
        std::vector<unsigned char> large_elem(100, 0x44); // 100 bytes
        
        stack.push_back(small_elem);
        stack.push_back(medium_elem);
        stack.push_back(large_elem);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        
        // Remove the largest element
        stack.pop_back();
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
        
        // Remove medium element
        stack.pop_back();
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
    }
    
    // Test 5: Complex sequence with multiple Val64 operations
    {
        ValtypeStack stack;
        
        // Start with small numbers
        for (int i = 1; i <= 5; i++) {
            Val64 v(i);
            auto vec = v.move_to_valtype();
            stack.push_back(vec);
        }
        
        // Perform series of operations that will change sizes
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        // Add all numbers: 1+2+3+4+5 = 15
        CScript add_script;
        add_script << OP_ADD << OP_ADD << OP_ADD << OP_ADD;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, add_script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(plain_stack.size(), 1);
        
        // Update stack and verify result
        stack = ValtypeStack(plain_stack);
        Val64 result;
        stack.pop64(result);

        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 15);
        
        // Verify size tracking
        stack.push_back(result.move_to_valtype());
        BOOST_CHECK_EQUAL(stack.get_total_size(), 1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 1);
        
        // Now multiply by itself to create larger number: 15 * 15 = 225
        auto top_element = stacktop(-1);  // Get copy of top element
        stack.push_back(top_element);  // Duplicate
        
        CScript mul_script;
        mul_script << OP_MUL;
        
        plain_stack = stack.get_stack();
        varops_budget = 1000000;
        BOOST_CHECK(EvalScript(plain_stack, mul_script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        stack = ValtypeStack(plain_stack);
        
        Val64 mul_result;
        stack.pop64(mul_result);
        cost = 0;
        // BOOST_CHECK_EQUAL(mul_result.to_u64_ceil(UINT64_MAX, cost), 225);
        
        // Final size verification
        auto valtype = mul_result.move_to_valtype();
        stack.push_back(valtype);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 1);
    }
    
    // Test 6: Very large numbers testing size limits
    {
        ValtypeStack stack;
        
        // Create large Val64 numbers
        Val64 large1(0xFFFFFFFFFFFFFFFFULL);
        Val64 large2(0xFFFFFFFFFFFFFFFFULL);
        
        auto vec1 = large1.move_to_valtype();
        auto vec2 = large2.move_to_valtype();
        
        stack.push_back(vec1);
        stack.push_back(vec2);
        
        // Multiplication of large numbers should produce very large result
        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;
        
        CScript script;
        script << OP_MUL;
        
        std::vector<std::vector<unsigned char>> plain_stack = stack.get_stack();
        BOOST_CHECK(EvalScript(plain_stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        
        stack = ValtypeStack(plain_stack);
        
        // Result should be much larger than inputs
        size_t result_size = stacktop(-1).size();
        BOOST_CHECK(result_size > 8);  // Should be larger than 8 bytes
        BOOST_CHECK_EQUAL(stack.get_total_size(), result_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), result_size);
    }
    
    // Test 7: Mixed operations with size changes
    {
        ValtypeStack stack;
        
        // Add elements of various sizes
        for (size_t i = 1; i <= 3; i++) {
            std::vector<unsigned char> elem(i * 10, static_cast<unsigned char>(0x40 + i));
            stack.push_back(elem);
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 20 + 30);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 30);
        
        // Modify elements through various operations
        stack.erase(1);  // Remove middle element (20 bytes)
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 30);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 30);
        
        // Insert new element
        std::vector<unsigned char> new_elem(50, 0x99);
        stack.insert(1, new_elem);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 30);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
        
        // Clear and verify
        stack.clear();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
    }
    
    // Test 8: Mixed Val64 and CScriptNum operations
    {
        ValtypeStack stack;
        
        // Add various number types of different sizes
        Val64 small_val64(42);
        Val64 large_val64(0x123456789ABCDEF0ULL);
        CScriptNum small_scriptnum(123);
        CScriptNum large_scriptnum(0x7FFFFFFFFFFFFFFF);  // Large but within CScriptNum range
        
        auto vec1 = small_val64.move_to_valtype();
        auto vec2 = large_val64.move_to_valtype();
        auto vec3 = small_scriptnum.getvch();
        auto vec4 = large_scriptnum.getvch();
        
        size_t size1 = vec1.size();
        size_t size2 = vec2.size();
        size_t size3 = vec3.size();
        size_t size4 = vec4.size();
        
        stack.push_back(vec1);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), size1);
        
        stack.push_back(vec2);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max(size1, size2));
        
        stack.push_back(vec3);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max({size1, size2, size3}));
        
        stack.push_back(vec4);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3 + size4);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max({size1, size2, size3, size4}));
        
        // Remove elements in specific order - max should remain unchanged (high water mark)
        size_t max_size_before = stack.get_max_element_size();
        stack.pop_back();  // Remove vec4
        
        // Max should always remain the same (high water mark behavior)
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size_before);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3);
    }
    
    // Test 9: Large numbers and precise size tracking
    {
        ValtypeStack stack;
        
        // Create progressively larger numbers
        std::vector<Val64> numbers;
        std::vector<size_t> expected_sizes;
        
        for (int i = 1; i <= 10; i++) {
            uint64_t value = 1;
            for (int j = 0; j < i; j++) {
                value *= 10;  // 10, 100, 1000, etc.
            }
            numbers.emplace_back(value);
            auto vec = numbers.back().move_to_valtype();
            expected_sizes.push_back(vec.size());
            stack.push_back(vec);
        }
        
        // Verify total size
        size_t expected_total = 0;
        for (size_t s : expected_sizes) {
            expected_total += s;
        }
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        
        // Verify max element size
        size_t expected_max = *std::max_element(expected_sizes.begin(), expected_sizes.end());
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), expected_max);
        
        // Remove elements from middle - max should remain unchanged (high water mark)
        size_t max_before_erase = stack.get_max_element_size();
        stack.erase(5);  // Remove 6th element
        expected_total -= expected_sizes[5];
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        // Max should remain the same (high water mark behavior)
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_before_erase);
    }
    
    // Test 10: Edge cases with empty and single element stacks
    {
        ValtypeStack stack;
        
        // Empty stack
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
        
        // Single element
        CScriptNum num(999);
        auto vec = num.getvch();
        size_t vec_size = vec.size();
        
        stack.push_back(vec);
        BOOST_CHECK_EQUAL(stack.get_total_size(), vec_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), vec_size);
        
        // Remove single element
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), vec_size);  // Should still be vec_size (max ever seen)
    }
    
    // Test 11: Stress test with many small elements
    {
        ValtypeStack stack;
        
        const size_t num_elements = 1000;
        size_t expected_total = 0;
        size_t expected_max = 0;
        
        // Add many small CScriptNum elements
        for (size_t i = 0; i < num_elements; i++) {
            CScriptNum num(static_cast<int64_t>(i));
            auto vec = num.getvch();
            size_t vec_size = vec.size();
            
            expected_total += vec_size;
            expected_max = std::max(expected_max, vec_size);
            
            stack.push_back(vec);
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), expected_max);
        
        // Remove half the elements (from the end)
        for (size_t i = 0; i < num_elements / 2; i++) {
            size_t actual_index = num_elements - 1 - i;  // Index of element being removed
            CScriptNum num(static_cast<int64_t>(actual_index));
            auto vec = num.getvch();
            expected_total -= vec.size();
            stack.pop_back();
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), expected_total);
        // Max should still be the same since we removed from the end
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), expected_max);
        
        // Clear all
        stack.clear();
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
    }
    
    // Test 12: Mixed operations with precise size verification
    {
        ValtypeStack stack;
        
        // Create elements with known sizes
        Val64 val1(1);                           // Small number
        Val64 val2(0xFFFFFFFFFFFFFFFFULL);       // Large number  
        CScriptNum scriptnum1(42);               // Small CScriptNum
        CScriptNum scriptnum2(-123456789);       // Negative CScriptNum
        
        auto vec1 = val1.move_to_valtype();
        auto vec2 = val2.move_to_valtype();
        auto vec3 = scriptnum1.getvch();
        auto vec4 = scriptnum2.getvch();
        
        size_t size1 = vec1.size();
        size_t size2 = vec2.size();
        size_t size3 = vec3.size();
        size_t size4 = vec4.size();
        
        // Add elements in specific order
        stack.push_back(vec1);
        stack.push_back(vec2);
        stack.push_back(vec3);
        stack.push_back(vec4);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3 + size4);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max({size1, size2, size3, size4}));
        
        // Insert in middle
        Val64 val_insert(0x123456789ABCDEF0ULL);
        auto vec_insert = val_insert.move_to_valtype();
        size_t size_insert = vec_insert.size();
        
        stack.insert(2, vec_insert);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3 + size4 + size_insert);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), std::max({size1, size2, size3, size4, size_insert}));
        
        // Remove from middle - max should remain unchanged (high water mark)
        size_t max_before_remove = stack.get_max_element_size();
        stack.erase(2);
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2 + size3 + size4);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_before_remove);  // Should remain unchanged
        
        // Resize stack - max should remain unchanged (high water mark)
        stack.resize(2);
        BOOST_CHECK_EQUAL(stack.size(), 2);
        BOOST_CHECK_EQUAL(stack.get_total_size(), size1 + size2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_before_remove);  // Should remain unchanged
    }
    
    // Test 13: Proxy modification with different number types
    {
        ValtypeStack stack;
        
        // Start with a CScriptNum
        CScriptNum initial_num(123);
        auto initial_vec = initial_num.getvch();
        stack.push_back(initial_vec);
        
        size_t initial_size = stack.get_total_size();
        BOOST_CHECK_EQUAL(initial_size, initial_vec.size());
        
        // Verify size tracking updated correctly
        BOOST_CHECK_EQUAL(stack.get_total_size(), stacktop(-1).size());
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), stacktop(-1).size());
    }
    
    // Test 14: Range operations with size tracking
    {
        ValtypeStack stack1, stack2;
        
        // Fill first stack with Val64 numbers
        size_t total_size1 = 0;
        size_t max_size1 = 0;
        for (int i = 1; i <= 5; i++) {
            Val64 val(i * 1000);
            auto vec = val.move_to_valtype();
            total_size1 += vec.size();
            max_size1 = std::max(max_size1, vec.size());
            stack1.push_back(vec);
        }
        
        // Fill second stack with CScriptNum numbers
        size_t total_size2 = 0;
        size_t max_size2 = 0;
        for (int i = 10; i <= 15; i++) {
            CScriptNum num(i * 100);
            auto vec = num.getvch();
            total_size2 += vec.size();
            max_size2 = std::max(max_size2, vec.size());
            stack2.push_back(vec);
        }
        
        BOOST_CHECK_EQUAL(stack1.get_total_size(), total_size1);
        BOOST_CHECK_EQUAL(stack1.get_max_element_size(), max_size1);
        BOOST_CHECK_EQUAL(stack2.get_total_size(), total_size2);
        BOOST_CHECK_EQUAL(stack2.get_max_element_size(), max_size2);
        
    }
    
    // Test 15: Roll operation with size tracking
    {
        ValtypeStack stack;
        
        // Add elements of different sizes
        std::vector<size_t> sizes;
        size_t total_size = 0;
        size_t max_size = 0;
        
        for (int i = 1; i <= 5; i++) {
            if (i % 2 == 1) {
                // Odd: use Val64
                Val64 val(i * 1000000);  // Large numbers
                auto vec = val.move_to_valtype();
                sizes.push_back(vec.size());
                total_size += vec.size();
                max_size = std::max(max_size, vec.size());
                stack.push_back(vec);
            } else {
                // Even: use CScriptNum
                CScriptNum num(i * 10);  // Small numbers
                auto vec = num.getvch();
                sizes.push_back(vec.size());
                total_size += vec.size();
                max_size = std::max(max_size, vec.size());
                stack.push_back(vec);
            }
        }
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), total_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
        
        // Perform roll operation (move 3rd from top to top)
        stack.rotate(-3, -2, -1);
        
        // Size tracking should remain the same (just rearranging)
        BOOST_CHECK_EQUAL(stack.get_total_size(), total_size);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
        BOOST_CHECK_EQUAL(stack.size(), 5);
    }

    // Test 16: OP_CAT operation with size tracking
    {
        ValtypeStack stack;
        stack.push_back({'a', 'b', 'c'});
        stack.push_back({'d', 'e', 'f'});
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 6);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 3); 

        CScript script;
        script << OP_CAT;

        BaseSignatureChecker checker;
        ScriptExecutionData sdata;
        ScriptError serror;
        uint64_t varops_budget = 1000000;

        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);

        BOOST_CHECK_EQUAL(stack.get_total_size(), 6);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 6);
    }
    
    // Test 17: Specific max_element_size tracking with multiple elements of same size
    {
        ValtypeStack stack;
        
        // Add multiple elements of the same maximum size
        std::vector<unsigned char> large_elem1(100, 0x11);  // 100 bytes
        std::vector<unsigned char> large_elem2(100, 0x22);  // 100 bytes
        std::vector<unsigned char> large_elem3(100, 0x33);  // 100 bytes
        std::vector<unsigned char> medium_elem(50, 0x44);   // 50 bytes
        std::vector<unsigned char> small_elem(10, 0x55);    // 10 bytes
        
        stack.push_back(small_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 10);
        
        stack.push_back(medium_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
        
        stack.push_back(large_elem1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        
        stack.push_back(large_elem2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Still 100, multiple elements
        
        stack.push_back(large_elem3);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Still 100, three elements of max size
        
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100 + 100 + 100);
        
        // Remove one large element - max should still be 100 (2 remaining)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100 + 100);
        
        // Remove another large element - max should still be 100 (1 remaining)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50 + 100);
        
        // Remove the last large element - max should still be 100 (max ever seen)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10 + 50);
        
        // Remove medium element - max should still be 100 (max ever seen)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 10);
        
        // Remove last element - max should still be 100 (max ever seen)
        stack.pop_back();
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 0);
    }
    
    // Test 18: Max size tracking with erase operations (not just pop_back)
    {
        ValtypeStack stack;
        
        // Create elements with carefully chosen sizes
        std::vector<unsigned char> elem_80(80, 0xAA);   // 80 bytes
        std::vector<unsigned char> elem_90(90, 0xBB);   // 90 bytes
        std::vector<unsigned char> elem_100a(100, 0xCC); // 100 bytes
        std::vector<unsigned char> elem_100b(100, 0xDD); // 100 bytes (duplicate size)
        std::vector<unsigned char> elem_110(110, 0xEE);  // 110 bytes (largest)
        
        stack.push_back(elem_80);
        stack.push_back(elem_90);
        stack.push_back(elem_100a);
        stack.push_back(elem_100b);
        stack.push_back(elem_110);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90 + 100 + 100 + 110);
        
        // Remove the largest element using erase (from middle)
        stack.erase(4);  // Remove elem_110
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);  // Should still be 110 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90 + 100 + 100);
        
        // Remove one of the 100-byte elements
        stack.erase(2);  // Remove elem_100a
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);  // Still 110 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90 + 100);
        
        // Remove the last 100-byte element
        stack.erase(2);  // Remove elem_100b
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 110);  // Still 110 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 90);
    }
    
    // Test 19: Range erase with max size recalculation
    {
        ValtypeStack stack;
        
        // Add elements in pattern: small, large, large, large, medium
        std::vector<unsigned char> small(20, 0x11);     // 20 bytes
        std::vector<unsigned char> large1(100, 0x22);   // 100 bytes
        std::vector<unsigned char> large2(100, 0x33);   // 100 bytes
        std::vector<unsigned char> large3(100, 0x44);   // 100 bytes
        std::vector<unsigned char> medium(60, 0x55);    // 60 bytes
        
        stack.push_back(small);
        stack.push_back(large1);
        stack.push_back(large2);
        stack.push_back(large3);
        stack.push_back(medium);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 20 + 100 + 100 + 100 + 60);
        
        // Remove all large elements at once using range erase
        stack.erase(1, 4);  // Remove large1, large2, large3
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
        BOOST_CHECK_EQUAL(stack.get_total_size(), 20 + 60);
        BOOST_CHECK_EQUAL(stack.size(), 2);
    }
    
    // Test 20: Insert operations with max size tracking
    {
        ValtypeStack stack;
        
        // Start with medium-sized elements
        std::vector<unsigned char> elem50(50, 0xAA);
        std::vector<unsigned char> elem60(60, 0xBB);
        
        stack.push_back(elem50);
        stack.push_back(elem60);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 60);
        
        // Insert larger element in middle
        std::vector<unsigned char> elem80(80, 0xCC);
        stack.insert(1, elem80);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 80);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 50 + 80 + 60);
        
        // Insert another element of same max size
        std::vector<unsigned char> elem80_dup(80, 0xDD);
        stack.insert(0, elem80_dup);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 80);  // Still 80, now with 2 elements
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 50 + 80 + 60);
        
        // Insert even larger element
        std::vector<unsigned char> elem120(120, 0xEE);
        stack.insert(stack.size() - 1, elem120);
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 120);
        BOOST_CHECK_EQUAL(stack.get_total_size(), 80 + 50 + 80 + 60 + 120);
    }
    
    // Test 21: Resize operations with max size tracking
    {
        ValtypeStack stack;
        
        // Fill with elements of increasing size
        for (int i = 1; i <= 10; i++) {
            std::vector<unsigned char> elem(i * 10, static_cast<unsigned char>(i));
            stack.push_back(elem);
        }
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // 10 * 10
        
        // Resize down - should remove largest elements first
        stack.resize(7);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
        BOOST_CHECK_EQUAL(stack.size(), 7);
        
        // Resize down further
        stack.resize(3);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
        BOOST_CHECK_EQUAL(stack.size(), 3);
        
        // Resize up - should add empty elements
        stack.resize(5);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 100);  // Should still be 100 (max ever seen)
        BOOST_CHECK_EQUAL(stack.size(), 5);
        
        // Add a large element to verify tracking still works
        std::vector<unsigned char> large_elem(200, 0xFF);
        stack.push_back(large_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 200);
    }
    
    // Test 22: Copy and move operations preserve max size tracking
    {
        ValtypeStack original;
        
        // Fill with various sized elements
        std::vector<unsigned char> small(25, 0x11);
        std::vector<unsigned char> medium(75, 0x22);
        std::vector<unsigned char> large(125, 0x33);
        
        original.push_back(small);
        original.push_back(medium);
        original.push_back(large);
        
        BOOST_CHECK_EQUAL(original.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(original.get_total_size(), 25 + 75 + 125);
        
        // Test copy constructor
        ValtypeStack copied(original);
        BOOST_CHECK_EQUAL(copied.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(copied.get_total_size(), 25 + 75 + 125);
        
        // Test copy assignment
        ValtypeStack assigned;
        assigned = original;
        BOOST_CHECK_EQUAL(assigned.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(assigned.get_total_size(), 25 + 75 + 125);
        
        // Test move constructor
        ValtypeStack moved(std::move(original));
        BOOST_CHECK_EQUAL(moved.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(moved.get_total_size(), 25 + 75 + 125);
        
        // Test move assignment
        ValtypeStack move_assigned;
        move_assigned = std::move(copied);
        BOOST_CHECK_EQUAL(move_assigned.get_max_element_size(), 125);
        BOOST_CHECK_EQUAL(move_assigned.get_total_size(), 25 + 75 + 125);
    }
    
    // Test 23: Stress test for max size tracking efficiency
    {
        ValtypeStack stack;
        
        // Add many elements of the same maximum size
        const size_t max_size = 500;
        const size_t num_max_elements = 100;
        
        // Add smaller elements first
        for (size_t i = 1; i < max_size; i += 50) {
            std::vector<unsigned char> elem(i, static_cast<unsigned char>(i % 256));
            stack.push_back(elem);
        }
        
        // Add many elements of maximum size
        for (size_t i = 0; i < num_max_elements; i++) {
            std::vector<unsigned char> elem(max_size, static_cast<unsigned char>(i % 256));
            stack.push_back(elem);
        }
        
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
        
        // Remove maximum elements one by one - this tests the efficiency of our optimization
        for (size_t i = 0; i < num_max_elements; i++) {
            stack.pop_back();
            if (i < num_max_elements - 1) {
                // Should still be max_size while there are more max elements
                BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
            } else {
                // After removing all max elements, should still be max_size (max ever seen)
                BOOST_CHECK_EQUAL(stack.get_max_element_size(), max_size);
            }
        }
    }
    
    // Test 24: Edge case - elements with size 0
    {
        ValtypeStack stack;
        
        // Add empty elements and non-empty elements
        std::vector<unsigned char> empty_elem;           // 0 bytes
        std::vector<unsigned char> small_elem(1, 0x42);  // 1 byte
        std::vector<unsigned char> large_elem(50, 0x43); // 50 bytes
        
        stack.push_back(empty_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 0);
        
        stack.push_back(small_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 1);
        
        stack.push_back(large_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);
        
        // Add another empty element
        stack.push_back(empty_elem);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);  // Should still be 50
        
        // Remove large element
        stack.erase(2);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);  // Should still be 50 (max ever seen)
        
        // Remove small element
        stack.erase(1);
        BOOST_CHECK_EQUAL(stack.get_max_element_size(), 50);  // Should still be 50 (max ever seen)
    }
    
    #undef stacktop
}

BOOST_AUTO_TEST_CASE(op_multi)
{
    // Test OP_MULTI (OP_NOP4) basic functionality in TAPSCRIPT_V2
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;
    uint64_t varops_budget = 1000000;
    #define OP_MULTI OP_NOP4

    // Test 1: OP_MULTI with OP_CAT - concatenate 10 elements
    // Stack: "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" 10 OP_MULTI OP_CAT -> "9876543210"
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push 10 single-digit strings onto the stack
        for (int i = 0; i < 10; i++) {
            stack.push_back({static_cast<unsigned char>('0' + i)});
        }
        
        CScript script;
        script << CScriptNum(10) << OP_MULTI << OP_CAT;  // Concatenate 10 elements
        
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &varops_budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "9876543210" (concatenated in reverse order from top of stack)
        std::vector<unsigned char> expected = {'9', '8', '7', '6', '5', '4', '3', '2', '1', '0'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 2: OP_MULTI with OP_DROP - drop 5 elements
    // Stack: "a" "b" "c" "d" "e" "f" "g" 5 OP_MULTI OP_DROP -> "a" "b" (only first 2 remain)
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push 7 elements
        for (char c = 'a'; c <= 'g'; c++) {
            stack.push_back({static_cast<unsigned char>(c)});
        }
        
        CScript script;
        script << CScriptNum(5) << OP_MULTI << OP_DROP;  // Drop top 5 elements
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 2);
        
        // Should have "a" and "b" remaining (bottom 2 elements)
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{'a'});
        BOOST_CHECK(stack[1] == std::vector<unsigned char>{'b'});
    }

    // Test 3: OP_MULTI with OP_ADD - sum multiple numbers
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push numbers 1, 2, 3, 4, 5 (sum = 15)
        for (int i = 1; i <= 5; i++) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(5) << OP_MULTI << OP_ADD;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be 15 (1+2+3+4+5)
        Val64 result(stack[0]);
        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 15);
    }

    // Test 4: OP_MULTI with OP_SHA256 - hash multiple inputs
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'a', 'b', 'c'});
        stack.push_back({'d', 'e', 'f'});
        stack.push_back({'g', 'h', 'i'});
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_SHA256;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be SHA256 hash of "ghidefabc" (concatenated in reverse order then hashed)
        BOOST_CHECK_EQUAL(stack[0].size(), 32);  // SHA256 produces 32 bytes
    }

    // Test 5: OP_MULTI with OP_DUP - duplicate multiple elements
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'x'});
        stack.push_back({'y'});
        stack.push_back({'z'});
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_DUP;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 6);  // Original 3 + duplicated 3
        
        // Should have: x, y, z, x, y, z
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{'x'});
        BOOST_CHECK(stack[1] == std::vector<unsigned char>{'y'});
        BOOST_CHECK(stack[2] == std::vector<unsigned char>{'z'});
        BOOST_CHECK(stack[3] == std::vector<unsigned char>{'x'});
        BOOST_CHECK(stack[4] == std::vector<unsigned char>{'y'});
        BOOST_CHECK(stack[5] == std::vector<unsigned char>{'z'});
    }

    // Test 6: OP_MULTI with OP_EQUAL - check if multiple elements are equal
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push 4 identical elements
        for (int i = 0; i < 4; i++) {
            stack.push_back({'s', 'a', 'm', 'e'});
        }
        
        CScript script;
        script << CScriptNum(4) << OP_MULTI << OP_EQUAL;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be true (1) since all elements are equal
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{1});
    }

    // Test 7: OP_MULTI with OP_EQUAL - different elements should return false
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'a'});
        stack.push_back({'b'});
        stack.push_back({'c'});
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_EQUAL;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be false (empty vector) since elements are different
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{});
    }

    // Test 8: OP_MULTI with insufficient stack elements should fail
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push only 3 elements
        stack.push_back({'a'});
        stack.push_back({'b'});
        stack.push_back({'c'});
        
        CScript script;
        script << CScriptNum(10) << OP_MULTI << OP_CAT;  // Try to multi-operate on 10 elements but only 3 on stack
        
        uint64_t budget = 1000000;
        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // Test 9: OP_MULTI with OP_MIN - find minimum value
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push numbers 10, 3, 7, 1, 5 - minimum should be 1
        for (int i : {10, 3, 7, 1, 5}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(5) << OP_MULTI << OP_MIN;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be 1 (minimum value)
        Val64 result(stack[0]);
        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 1);
    }

    // Test 10: OP_MULTI with OP_MAX - find maximum value
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push numbers 10, 3, 7, 1, 5 - maximum should be 10
        for (int i : {10, 3, 7, 1, 5}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(5) << OP_MULTI << OP_MAX;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be 10 (maximum value)
        Val64 result(stack[0]);
        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 10);
    }

    // Test 11: OP_MULTI with OP_AND - bitwise AND operation
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push numbers with specific bit patterns
        // 15 (1111), 7 (0111), 3 (0011) -> AND result should be 3 (0011)
        for (int i : {15, 7, 3}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_AND;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be 3 (15 & 7 & 3 = 3)
        Val64 result(stack[0]);
        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 3);
    }

    // Test 12: OP_MULTI with OP_OR - bitwise OR operation
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push numbers with specific bit patterns
        // 1 (0001), 2 (0010), 4 (0100) -> OR result should be 7 (0111)
        for (int i : {1, 2, 4}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_OR;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be 7 (1 | 2 | 4 = 7)
        Val64 result(stack[0]);
        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 7);
    }

    // Test 13: OP_MULTI with OP_BOOLAND - boolean AND operation
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push non-zero values (all should be true)
        for (int i : {5, 10, 1}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_BOOLAND;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be true (1) since all values are non-zero
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{1});
    }

    // Test 14: OP_MULTI with OP_BOOLAND with zero - should return false
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push mix of non-zero and zero values
        for (int i : {5, 0, 1}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_BOOLAND;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be false (empty) since one value is zero
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{});
    }

    // Test 15: OP_MULTI with OP_BOOLOR - boolean OR operation
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push mix of zero and non-zero values
        for (int i : {0, 0, 5}) {
            Val64 v(i);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_BOOLOR;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be true (1) since at least one value is non-zero
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{1});
    }

    // Test 16: OP_MULTI with OP_BOOLOR with all zeros - should return false
    {
        std::vector<std::vector<unsigned char>> stack;
        // Push all zero values
        for (int i = 0; i < 3; i++) {
            Val64 v(0);
            stack.push_back(v.move_to_valtype());
        }
        
        CScript script;
        script << CScriptNum(3) << OP_MULTI << OP_BOOLOR;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be false (empty) since all values are zero
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{});
    }

    // Test 17: OP_MULTI with 0 elements - test neutral element behavior
    {
        std::vector<std::vector<unsigned char>> stack;
        // No elements on stack
        
        CScript script;
        script << CScriptNum(0) << OP_MULTI << OP_MIN;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be 0 (neutral element for MIN)
        Val64 result(stack[0]);
        size_t cost = 0;
        BOOST_CHECK_EQUAL(result.to_u64_ceil(UINT64_MAX, cost), 0);
    }

    // Test 18: OP_MULTI with unknown opcode should succeed
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'a'});
        stack.push_back({'b'});
        
        CScript script;
        script << CScriptNum(2) << OP_MULTI << OP_RESERVED;  // Unknown opcode in multi context
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        // Stack should remain unchanged since unknown opcode does nothing
        BOOST_CHECK_EQUAL(stack.size(), 2);
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{'a'});
        BOOST_CHECK(stack[1] == std::vector<unsigned char>{'b'});
    }
}

BOOST_AUTO_TEST_CASE(op_left_right)
{
    // Test OP_LEFT and OP_RIGHT functionality in TAPSCRIPT_V2
    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;

    // Test 1: OP_LEFT - basic functionality
    // Stack: "hello" 3 -> "hel"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'h', 'e', 'l', 'l', 'o'});
        
        // Push offset 3 using Val64
        Val64 offset(3);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "hel"
        std::vector<unsigned char> expected = {'h', 'e', 'l'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 2: OP_RIGHT - basic functionality
    // Stack: "hello" 2 -> "llo"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'h', 'e', 'l', 'l', 'o'});
        
        // Push offset 2 using Val64
        Val64 offset(2);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "llo"
        std::vector<unsigned char> expected = {'l', 'l', 'o'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 3: OP_LEFT with zero offset
    // Stack: "test" 0 -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'t', 'e', 's', 't'});
        
        Val64 offset(0);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 4: OP_RIGHT with zero offset
    // Stack: "test" 0 -> "test"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'t', 'e', 's', 't'});
        
        Val64 offset(0);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "test"
        std::vector<unsigned char> expected = {'t', 'e', 's', 't'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 5: OP_LEFT with offset equal to string length
    // Stack: "abc" 3 -> "abc"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'a', 'b', 'c'});
        
        Val64 offset(3);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "abc"
        std::vector<unsigned char> expected = {'a', 'b', 'c'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 6: OP_RIGHT with offset equal to string length
    // Stack: "abc" 3 -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'a', 'b', 'c'});
        
        Val64 offset(3);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 7: OP_LEFT with offset greater than string length
    // Stack: "hi" 10 -> "hi"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'h', 'i'});
        
        Val64 offset(10);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "hi" (entire string)
        std::vector<unsigned char> expected = {'h', 'i'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 8: OP_RIGHT with offset greater than string length
    // Stack: "hi" 10 -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'h', 'i'});
        
        Val64 offset(10);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 9: OP_LEFT with empty string
    // Stack: "" 1 -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>{}); // Empty string
        
        Val64 offset(1);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 10: OP_RIGHT with empty string
    // Stack: "" 1 -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(std::vector<unsigned char>{}); // Empty string
        
        Val64 offset(1);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 11: OP_LEFT with binary data
    // Stack: [0x01, 0x02, 0x03, 0x04, 0x05] 3 -> [0x01, 0x02, 0x03]
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({0x01, 0x02, 0x03, 0x04, 0x05});
        
        Val64 offset(3);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be [0x01, 0x02, 0x03]
        std::vector<unsigned char> expected = {0x01, 0x02, 0x03};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 12: OP_RIGHT with binary data
    // Stack: [0x01, 0x02, 0x03, 0x04, 0x05] 2 -> [0x03, 0x04, 0x05]
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({0x01, 0x02, 0x03, 0x04, 0x05});
        
        Val64 offset(2);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be [0x03, 0x04, 0x05]
        std::vector<unsigned char> expected = {0x03, 0x04, 0x05};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 13: OP_LEFT with insufficient stack elements should fail
    {
        std::vector<std::vector<unsigned char>> stack;
        // Only push the data, not the offset
        stack.push_back({'a', 'b', 'c'});
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // Test 14: OP_RIGHT with insufficient stack elements should fail
    {
        std::vector<std::vector<unsigned char>> stack;
        // Only push the offset, not the data
        Val64 offset(1);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(!EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // Test 15: OP_LEFT and OP_RIGHT combination
    // Stack: "programming" 4 -> "prog", then 2 -> "og"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'p', 'r', 'o', 'g', 'r', 'a', 'm', 'm', 'i', 'n', 'g'});
        
        Val64 offset1(4);
        stack.push_back(offset1.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // After OP_LEFT, stack should contain "prog"
        std::vector<unsigned char> expected1 = {'p', 'r', 'o', 'g'};
        BOOST_CHECK(stack[0] == expected1);
        
        // Now apply OP_RIGHT with offset 2
        Val64 offset2(2);
        stack.push_back(offset2.move_to_valtype());
        
        CScript script2;
        script2 << OP_RIGHT;
        
        budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script2, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Final result should be "og"
        std::vector<unsigned char> expected2 = {'o', 'g'};
        BOOST_CHECK(stack[0] == expected2);
    }

    // Test 16: OP_LEFT with large offset (test boundary conditions)
    // Stack: "test" UINT64_MAX -> "test"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'t', 'e', 's', 't'});
        
        Val64 offset(UINT64_MAX);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "test" (entire string)
        std::vector<unsigned char> expected = {'t', 'e', 's', 't'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 17: OP_RIGHT with large offset (test boundary conditions)
    // Stack: "test" UINT64_MAX -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'t', 'e', 's', 't'});
        
        Val64 offset(UINT64_MAX);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 18: OP_LEFT with single character
    // Stack: "x" 1 -> "x"
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'x'});
        
        Val64 offset(1);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "x"
        std::vector<unsigned char> expected = {'x'};
        BOOST_CHECK(stack[0] == expected);
    }

    // Test 19: OP_RIGHT with single character and offset 1
    // Stack: "x" 1 -> ""
    {
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back({'x'});
        
        Val64 offset(1);
        stack.push_back(offset.move_to_valtype());
        
        CScript script;
        script << OP_RIGHT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be empty
        BOOST_CHECK(stack[0].empty());
    }

    // Test 20: OP_LEFT and OP_RIGHT with same data and offset for complementary test
    // Stack: "abcdef" 3 -> OP_LEFT -> "abc", then "abcdef" 3 -> OP_RIGHT -> "def"
    {
        std::vector<std::vector<unsigned char>> stack;
        std::vector<unsigned char> original = {'a', 'b', 'c', 'd', 'e', 'f'};
        
        // Test OP_LEFT
        stack.push_back(original);
        Val64 offset(3);
        stack.push_back(offset.move_to_valtype());
        
        CScript script_left;
        script_left << OP_LEFT;
        
        uint64_t budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script_left, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "abc"
        std::vector<unsigned char> expected_left = {'a', 'b', 'c'};
        BOOST_CHECK(stack[0] == expected_left);
        
        // Reset stack for OP_RIGHT test
        stack.clear();
        stack.push_back(original);
        Val64 offset2(3);
        stack.push_back(offset2.move_to_valtype());
        
        CScript script_right;
        script_right << OP_RIGHT;
        
        budget = 1000000;
        BOOST_CHECK(EvalScript(stack, script_right, 0, checker, SigVersion::TAPSCRIPT_V2, sdata, &serror, &budget));
        BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(stack.size(), 1);
        
        // Result should be "def"
        std::vector<unsigned char> expected_right = {'d', 'e', 'f'};
        BOOST_CHECK(stack[0] == expected_right);
    }
}

BOOST_AUTO_TEST_SUITE_END()
