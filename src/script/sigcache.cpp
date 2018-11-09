/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sigcache.h"

#include "args.h"
#include "memusage.h"
#include "pubkey.h"
#include "random.h"
#include "uint256.h"
#include "util/util.h"

#include <boost/thread.hpp>
#include <boost/unordered_set.hpp>

namespace
{
/**
 * We're hashing a nonce into the entries themselves, so we don't need extra
 * blinding in the set hash computation.
 */
class CSignatureCacheHasher
{
public:
    size_t operator()(const uint256 &key) const { return key.GetCheapHash(); }
};

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class CSignatureCache
{
private:
    //! Entries are SHA256(nonce || signature hash || public key || signature):
    uint256 nonce;
    typedef boost::unordered_set<uint256, CSignatureCacheHasher> map_type;
    map_type setValid;
    boost::shared_mutex cs_sigcache;


public:
    CSignatureCache() { GetRandBytes(nonce.begin(), 32); }
    void ComputeEntry(uint256 &entry,
        const uint256 &hash,
        const std::vector<unsigned char> &vchSig,
        const CPubKey &pubkey)
    {
        CSHA256()
            .Write(nonce.begin(), 32)
            .Write(hash.begin(), 32)
            .Write(&pubkey[0], pubkey.size())
            .Write(&vchSig[0], vchSig.size())
            .Finalize(entry.begin());
    }

    bool Get(const uint256 &entry)
    {
        boost::shared_lock<boost::shared_mutex> lock(cs_sigcache);
        return setValid.count(entry);
    }

    void Erase(const uint256 &entry)
    {
        boost::unique_lock<boost::shared_mutex> lock(cs_sigcache);
        setValid.erase(entry);
    }

    void Set(const uint256 &entry)
    {
        size_t nMaxCacheSize = gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) * ((size_t)1 << 20);
        if (nMaxCacheSize <= 0)
            return;

        boost::unique_lock<boost::shared_mutex> lock(cs_sigcache);
        while (memusage::DynamicUsage(setValid) > nMaxCacheSize)
        {
            map_type::size_type s = GetRand(setValid.bucket_count());
            map_type::local_iterator it = setValid.begin(s);
            if (it != setValid.end(s))
            {
                setValid.erase(*it);
            }
        }

        setValid.insert(entry);
    }
};
}

bool CachingTransactionSignatureChecker::VerifySignature(const std::vector<unsigned char> &vchSig,
    const CPubKey &pubkey,
    const uint256 &sighash) const
{
    static CSignatureCache signatureCache;

    uint256 entry;
    signatureCache.ComputeEntry(entry, sighash, vchSig, pubkey);

    if (signatureCache.Get(entry))
    {
        if (!store)
        {
            signatureCache.Erase(entry);
        }
        return true;
    }

    if (!TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash))
        return false;

    if (store)
    {
        signatureCache.Set(entry);
    }
    return true;
}
