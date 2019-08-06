// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stakescript.h"
#include "args.h"
#include "arith_uint256.h"
#include "chain/tx.h"
#include "interpreter.h"
#include "key.h"
#include "policy/policy.h"
#include "random.h"
#include "sigcache.h"
#include "sync.h"
#include "util/util.h"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <openssl/crypto.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <vector>

static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const arith_uint256 bnZero(0);
static const arith_uint256 bnOne(1);
static const arith_uint256 bnFalse(0);
static const arith_uint256 bnTrue(1);
static const size_t nMaxNumSize = 4;


// Valid signature cache, to avoid doing expensive ECDSA signature checking
// twice for every transaction (once when accepted into memory pool, and
// again when accepted into the block chain)

class CStakeSignatureCache
{
private:
    // sigdata_type is (signature hash, signature, public key):
    typedef boost::tuple<uint256, std::vector<unsigned char>, std::vector<unsigned char> > sigdata_type;
    std::set<sigdata_type> setValid;
    CCriticalSection cs_sigcache;

public:
    bool Get(uint256 hash, const std::vector<unsigned char> &vchSig, const std::vector<unsigned char> &pubKey)
    {
        LOCK(cs_sigcache);

        sigdata_type k(hash, vchSig, pubKey);
        std::set<sigdata_type>::iterator mi = setValid.find(k);
        if (mi != setValid.end())
            return true;
        return false;
    }

    void Set(uint256 hash, const std::vector<unsigned char> &vchSig, const std::vector<unsigned char> &pubKey)
    {
        // DoS prevention: limit cache size to less than 10MB
        // (~200 bytes per cache entry times 50,000 entries)
        // Since there are a maximum of 20,000 signature operations per block
        // 50,000 is a reasonable default.
        int64_t nMaxCacheSize = gArgs.GetArg("-maxsigcachesize", 50000);
        if (nMaxCacheSize <= 0)
            return;

        LOCK(cs_sigcache);

        while (static_cast<int64_t>(setValid.size()) > nMaxCacheSize)
        {
            // Evict a random entry. Random because that helps
            // foil would-be DoS attackers who might try to pre-generate
            // and re-use a set of valid signatures just-slightly-greater
            // than our cache size.
            uint256 randomHash = GetRandHash();
            std::vector<unsigned char> unused;
            std::set<sigdata_type>::iterator it = setValid.lower_bound(sigdata_type(randomHash, unused, unused));
            if (it == setValid.end())
                it = setValid.begin();
            setValid.erase(*it);
        }

        sigdata_type k(hash, vchSig, pubKey);
        setValid.insert(k);
    }
};


bool CheckSig(std::vector<unsigned char> vchSig,
    std::vector<unsigned char> vchPubKey,
    CScript scriptCode,
    const CTransaction &txTo,
    unsigned int nIn,
    int nHashType)
{
    static CStakeSignatureCache signatureCache;

    // Hash type is one byte tacked on to the end of the signature
    if (vchSig.empty())
        return false;
    if (nHashType == 0)
        nHashType = vchSig.back();
    else if (nHashType != vchSig.back())
        return false;
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    if (signatureCache.Get(sighash, vchSig, vchPubKey))
        return true;

    CPubKey key(vchPubKey);

    if (!key.Verify(sighash, vchSig))
        return false;

    signatureCache.Set(sighash, vchSig, vchPubKey);
    return true;
}


//
// WARNING: This does not work as expected for signed integers; the sign-bit
// is left in place as the integer is zero-extended. The correct behavior
// would be to move the most significant bit of the last byte during the
// resize process. MakeSameSize() is currently only used by the disabled
// opcodes OP_AND, OP_OR, and OP_XOR.
//
void MakeSameSize(valtype &vch1, valtype &vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        // PATCH:
        // +unsigned char msb = vch1[vch1.size()-1];
        // +vch1[vch1.size()-1] &= 0x7f;
        //  vch1.resize(vch2.size(), 0);
        // +vch1[vch1.size()-1] = msb;
        vch1.resize(vch2.size(), 0);
    if (vch2.size() < vch1.size())
        // PATCH:
        // +unsigned char msb = vch2[vch2.size()-1];
        // +vch2[vch2.size()-1] &= 0x7f;
        //  vch2.resize(vch1.size(), 0);
        // +vch2[vch2.size()-1] = msb;
        vch2.resize(vch1.size(), 0);
}


//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i) (stack.at(stack.size() + (i)))
#define altstacktop(i) (altstack.at(altstack.size() + (i)))
static inline void popstack(std::vector<std::vector<unsigned char> > &stack)
{
    if (stack.empty())
        throw std::runtime_error("popstack() : stack empty");
    stack.pop_back();
}

bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn)
{
    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), NULL))
        return false;
    stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), NULL))
        return false;
    if (stack.empty())
        return false;

    if (CastToBool(stack.back()) == false)
        return false;

    // Additional validation for spend-to-script-hash transactions:
    if (scriptPubKey.IsPayToScriptHash())
    {
        if (!scriptSig.IsPushOnly()) // scriptSig must be literals-only
            return false; // or validation fails

        const std::vector<unsigned char> &pubKeySerialized = stackCopy.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stackCopy);

        if (!EvalScript(
                stackCopy, pubKey2, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), NULL))
            return false;
        if (stackCopy.empty())
            return false;
        return CastToBool(stackCopy.back());
    }

    return true;
}

inline bool set_error_stake(ScriptError *ret, const ScriptError serror)
{
    if (ret)
        *ret = serror;
    return false;
}


bool VerifyScript(const CScript &scriptSig,
    const CScript &scriptPubKey,
    const CTransaction &txTo,
    unsigned int nIn,
    bool fValidatePayToScriptHash)
{
    ScriptError serror = SCRIPT_ERR_OK;
    set_error_stake(&serror, SCRIPT_ERR_UNKNOWN_ERROR);

    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), &serror))
    {
        return false;
    }
    if (fValidatePayToScriptHash)
    {
        stackCopy = stack;
    }
    if (!EvalScript(
            stack, scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), &serror))
    {
        return false;
    }
    if (stack.empty())
    {
        return false;
    }

    if (CastToBool(stack.back()) == false)
    {
        return false;
    }

    // Additional validation for spend-to-script-hash transactions:
    if (fValidatePayToScriptHash && scriptPubKey.IsPayToScriptHash())
    {
        if (!scriptSig.IsPushOnly()) // scriptSig must be literals-only
        {
            return false; // or validation fails
        }

        const std::vector<unsigned char> &pubKeySerialized = stackCopy.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stackCopy);

        if (!EvalScript(
                stackCopy, pubKey2, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txTo, nIn), NULL))
        {
            return false;
        }
        if (stackCopy.empty())
        {
            return false;
        }
        return CastToBool(stackCopy.back());
    }

    return true;
}

bool VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn)
{
    assert(nIn < txTo.vin.size());
    const CTxIn &txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut &txout = txFrom.vout[txin.prevout.n];

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    return VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn);
}

bool VerifySignature(const CTransaction &txFrom,
    const CTransaction &txTo,
    unsigned int nIn,
    bool fValidatePayToScriptHash)
{
    assert(nIn < txTo.vin.size());
    const CTxIn &txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut &txout = txFrom.vout[txin.prevout.n];

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    return VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, fValidatePayToScriptHash);
}
