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

#ifndef BITCOIN_COINS_H
#define BITCOIN_COINS_H

#include "compressor.h"
#include "core_memusage.h"
#include "memusage.h"
#include "serialize.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>
#include <unordered_map>

#include "compressor.h"
#include "core_memusage.h"
#include "crypto/hash.h"
#include "memusage.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>

#include <boost/foreach.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <unordered_map>

class CTxUndo;
struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nSerializedSize;
    uint256 hashSerialized;
    uint64_t nDiskSize;
    CAmount nTotalAmount;

    CCoinsStats()
        : nHeight(0), nTransactions(0), nTransactionOutputs(0), nSerializedSize(0), nDiskSize(0), nTotalAmount(0)
    {
    }
};

/**
 * A UTXO entry.
 *
 * Serialized format:
 * - VARINT((coinbase ? 1 : 0) | (height << 1))
 * - the non-spent CTxOut (via CTxOutCompressor)
 */
class Coin
{
public:
    //! unspent transaction output
    CTxOut out;

    //! whether containing transaction was a coinbase
    uint8_t fCoinBase : 1;

    uint8_t fCoinStake : 1;

    //! at which height this containing transaction was included in the active block chain
    uint32_t nHeight;

    uint64_t nTime;

    //! construct a Coin from a CTxOut and height/coinbase information.
    Coin(CTxOut &&outIn, int nHeightIn, bool fCoinBaseIn, bool fCoinStakeIn, uint64_t nTimeIn)
        : out(std::move(outIn)), fCoinBase(fCoinBaseIn), fCoinStake(fCoinStakeIn), nHeight(nHeightIn), nTime(nTimeIn)
    {
    }
    Coin(const CTxOut &outIn, int nHeightIn, bool fCoinBaseIn, bool fCoinStakeIn, uint64_t nTimeIn)
        : out(outIn), fCoinBase(fCoinBaseIn), fCoinStake(fCoinStakeIn), nHeight(nHeightIn), nTime(nTimeIn)
    {
    }

    void Clear()
    {
        out.SetNull();
        fCoinBase = 0;
        fCoinStake = 0;
        nHeight = 0;
        nTime = 0;
    }

    //! empty constructor
    Coin() { Clear(); }
    bool IsCoinBase() const { return fCoinBase; }
    bool IsCoinStake() const { return fCoinStake; }
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        assert(!IsSpent());
        uint8_t code = 0;
        if (fCoinBase)
        {
            code = code & 1;
        }
        if (fCoinStake)
        {
            code = code & 2;
        }
        assert((code & 3) != 3);
        ::Serialize(s, VARINT(code));
        ::Serialize(s, VARINT(nHeight));
        ::Serialize(s, VARINT(nTime));
        ::Serialize(s, CTxOutCompressor(REF(out)));
    }

    template <typename Stream>
    void Unserialize(Stream &s)
    {
        uint8_t code = 0;
        ::Unserialize(s, VARINT(code));
        fCoinBase = code & 1;
        fCoinStake = code & 2;
        ::Unserialize(s, VARINT(nHeight));
        ::Unserialize(s, VARINT(nTime));
        ::Unserialize(s, REF(CTxOutCompressor(out)));
    }

    bool IsSpent() const { return out.IsNull(); }
    size_t DynamicMemoryUsage() const { return memusage::DynamicUsage(out.scriptPubKey); }
};

class SaltedOutpointHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedOutpointHasher();

    uint64_t operator()(const COutPoint &id) const { return SipHashUint256Extra(k0, k1, id.hash, id.n); }
};

struct CCoinsCacheEntry
{
    Coin coin; // The actual cached data.
    unsigned char flags;

    enum Flags
    {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
        FRESH = (1 << 1), // The parent view does not have this entry (or it is pruned).
    };

    CCoinsCacheEntry() : flags(0) {}
    explicit CCoinsCacheEntry(Coin &&coin_) : coin(std::move(coin_)), flags(0) {}
};

typedef std::unordered_map<COutPoint, CCoinsCacheEntry, SaltedOutpointHasher> CCoinsMap;

/** Cursor for iterating over CoinsView state */
class CCoinsViewCursor
{
public:
    CCoinsViewCursor(const uint256 &hashBlockIn) : hashBlock(hashBlockIn) {}
    virtual ~CCoinsViewCursor();

    virtual bool GetKey(COutPoint &key) const = 0;
    virtual bool GetValue(Coin &coin) const = 0;
    /* Don't care about GetKeySize here */
    virtual unsigned int GetValueSize() const = 0;

    virtual bool Valid() const = 0;
    virtual void Next() = 0;

    //! Get best block at the time this cursor was created
    const uint256 &GetBestBlock() const { return hashBlock; }
private:
    uint256 hashBlock;
};

/** Abstract view on the open txout dataset. */
class CCoinsView
{
public:
    mutable CSharedCriticalSection cs_utxo;

    //! Retrieve the Coin (unspent transaction output) for a given outpoint.
    virtual bool GetCoin(const COutPoint &outpoint, Coin &coin) const;

    //! Just check whether we have data for a given outpoint.
    //! This may (but cannot always) return true for spent outputs.
    virtual bool HaveCoin(const COutPoint &outpoint) const;

    //! Retrieve the block hash whose state this CCoinsView currently represents
    virtual uint256 GetBestBlock() const;

    //! Do a bulk modification (multiple Coin changes + BestBlock change).
    //! The passed mapCoins can be modified.
    virtual bool BatchWrite(CCoinsMap &mapCoins,
        const uint256 &hashBlock,
        const uint64_t bestCoinHeight,
        size_t &nChildCachedCoinsUsage);

    //! Get a cursor to iterate over the whole state
    virtual CCoinsViewCursor *Cursor() const;

    //! As we use CCoinsViews polymorphically, have a virtual destructor
    virtual ~CCoinsView() {}
    //! Estimate database size (0 if not implemented)
    virtual size_t EstimateSize() const { return 0; }
};


/** CCoinsView backed by another CCoinsView */
class CCoinsViewBacked : public CCoinsView
{
protected:
    CCoinsView *base;

public:
    CCoinsViewBacked(CCoinsView *viewIn);
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    void SetBackend(CCoinsView &viewIn);
    bool BatchWrite(CCoinsMap &mapCoins,
        const uint256 &hashBlock,
        const uint64_t nBestCoinHeight,
        size_t &nChildCachedCoinsUsage) override;
    CCoinsViewCursor *Cursor() const override;
    size_t EstimateSize() const override;
};


/** CCoinsView that adds a memory cache for transactions to another CCoinsView */
class CCoinsViewCache : public CCoinsViewBacked
{
    friend class CoinAccessor;
    friend class CoinModifier;

protected:
    /**
     * Make mutable so that we can "fill the cache" even from Get-methods
     * declared as "const".
     */
    mutable uint256 hashBlock;
    mutable uint64_t nBestCoinHeight;
    mutable CCoinsMap cacheCoins;
    mutable CSharedCriticalSection csCacheInsert;
    /* Cached dynamic memory usage for the inner Coin objects. */
    mutable size_t cachedCoinsUsage;


public:
    CCoinsViewCache(CCoinsView *baseIn);

    // Standard CCoinsView methods
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const;
    bool HaveCoin(const COutPoint &outpoint) const;
    uint256 GetBestBlock() const;
    void SetBestBlock(const uint256 &hashBlock);
    bool BatchWrite(CCoinsMap &mapCoins,
        const uint256 &hashBlock,
        const uint64_t nBestCoinHeight,
        size_t &nChildCachedCoinsUsage);

    /**
     * Check if we have the given utxo already loaded in this cache.
     * The semantics are the same as HaveCoin(), but no calls to
     * the backing CCoinsView are made.
     */
    bool HaveCoinInCache(const COutPoint &outpoint) const;

    /**
     * Return a reference to Coin in the cache, or a pruned one if not found. This is
     * more efficient than GetCoin. Modifications to other cache entries are
     * allowed while accessing the returned pointer.
     */
    const Coin &_AccessCoin(const COutPoint &output) const;

    /**
     * Add a coin. Set potential_overwrite to true if a non-pruned version may
     * already exist.
     */
    void AddCoin(const COutPoint &outpoint, Coin &&coin, bool potential_overwrite);

    /**
     * Spend a coin. Pass moveto in order to get the deleted data.
     * If no unspent output exists for the passed outpoint, this call
     * has no effect.
     */
    void SpendCoin(const COutPoint &outpoint, Coin *moveto = nullptr);

    /**
     * Push the modifications applied to this cache to its base.
     * Failure to call this method before destruction will cause the changes to be forgotten.
     * If false is returned, the state of this cache (and its backing view) will be undefined.
     */
    bool Flush();

    /**
     * Empty the coins cache. Used primarily when we're shutting down and want to release memory
     */
    void Clear() { cacheCoins.clear(); }
    /**
     * Remove excess entries from this cache.
     * Entries are trimmed starting from the beginning of the map.  In this way if those entries
     * are needed later they will all be collocated near the the beginning of the leveldb database
     * and will be faster to retrieve.
     */
    void Trim(size_t nTrimSize) const;

    /**
     * Removes the UTXO with the given outpoint from the cache, if it is
     * not modified.
     */
    void Uncache(const COutPoint &outpoint);

    /**
     * Removes all the UTXO outpoints for a given transaction, if they are
     * not modified.
     */
    void UncacheTx(const CTransaction &tx);

    //! Calculate the size of the cache (in number of transaction outputs)
    unsigned int GetCacheSize() const;

    //! Calculate the size of the cache (in bytes)
    size_t DynamicMemoryUsage() const;
    size_t _DynamicMemoryUsage() const;

    //! Recalculate and Reset the size of cachedCoinsUsage
    size_t ResetCachedCoinUsage() const;

    /**
     * Amount of bitcoins coming in to a transaction
     * Note that lightweight clients may not know anything besides the hash of previous transactions,
     * so may not be able to calculate this.
     *
     * @param[in] tx        transaction for which we are checking input total
     * @return        Sum of value of all inputs (scriptSigs)
     */
    CAmount GetValueIn(const CTransaction &tx) const;

    //! Check whether all prevouts of the transaction are present in the UTXO set represented by this view
    bool HaveInputs(const CTransaction &tx) const;

    /**
     * Return priority of tx at height nHeight. Also calculate the sum of the values of the inputs
     * that are already in the chain.  These are the inputs that will age and increase priority as
     * new blocks are added to the chain.
     */
    double GetPriority(const CTransaction &tx, int nHeight, CAmount &inChainInputValue) const;

private:
    CCoinsMap::iterator FetchCoin(const COutPoint &outpoint, CDeferredSharedLocker *lock) const;

    /**
     * By making the copy constructor private, we prevent accidentally using it when one intends to create a cache on
     * top of a base cache.
     */
    CCoinsViewCache(const CCoinsViewCache &);
};

class CoinModifier
{
protected:
    const CCoinsViewCache *cache;
    CCoinsMap::const_iterator it;
    const Coin *coin;

public:
    operator bool() const { return coin != nullptr; }
    const Coin *operator->() { return coin; }
    const Coin &operator*() { return *coin; }
    CoinModifier(const CCoinsViewCache &cacheObj, const COutPoint &output);
    ~CoinModifier();
    friend class CCoinsViewCache;
};


/**
 * A reference to an immutable cache entry.  This class holds the appropriate lock for you
 * while you access the underlying data.
 */
class CoinAccessor
{
protected:
    const CCoinsViewCache *cache;
    CCoinsMap::const_iterator it;
    const Coin *coin;
    CDeferredSharedLocker lock;

public:
    operator bool() const { return coin != nullptr; }
    const Coin *operator->() { return coin; }
    const Coin &operator*() { return *coin; }
    CoinAccessor(const CCoinsViewCache &cacheObj, const COutPoint &output);
    // finds the first unspent output in this tx (slow)
    CoinAccessor(const CCoinsViewCache &cacheObj, const uint256 &txid);
    ~CoinAccessor();
    friend class CCoinsViewCache;
};

//! Utility function to add all of a transaction's outputs to a cache.
// It assumes that overwrites are only possible for coinbase transactions,
// TODO: pass in a boolean to limit these possible overwrites to known
// (pre-BIP34) cases.
void AddCoins(CCoinsViewCache &cache, const CTransaction &tx, int nHeight);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, int nHeight);
void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight);


#endif // BITCOIN_COINS_H
