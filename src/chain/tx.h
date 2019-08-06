// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "consensus/params.h"
#include "txin.h"
#include "txout.h"

/**
 * A TxId is the identifier of a transaction. Currently identical to TxHash but
 * differentiated for type safety.
 */
struct TxId : public uint256
{
    explicit TxId(const uint256 &b) : uint256(b) {}
};


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 hash;

public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 1;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    int32_t nVersion;
    unsigned int nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    uint256 serviceReferenceHash;

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CTransaction into a CTransaction. */
    CTransaction(const CTransaction &tx);

    CTransaction &operator=(const CTransaction &tx);


    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*const_cast<int32_t *>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<uint32_t *>(&this->nTime));
        READWRITE(*const_cast<std::vector<CTxIn> *>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut> *>(&vout));
        READWRITE(*const_cast<uint32_t *>(&nLockTime));
        if (this->nVersion == 2)
        {
            READWRITE(*const_cast<uint256 *>(&this->serviceReferenceHash));
        }
        if (ser_action.ForRead())
        {
            UpdateHash();
        }
    }


    /*
    template <typename Stream> inline void Serialize(Stream &s) const
    {
        s << this->nVersion;
        s << this->nTime;
        s << vin;
        s << vout;
        s << nLockTime;
        if (this->nVersion == 2)
        {
            s << this->serviceReferenceHash;
        }
    }

    template <typename Stream> inline void Unserialize(Stream &s)
    {
        s >> this->nVersion;
        this->vin.clear();
        this->vout.clear();
        s >> this->nTime;
        s >> vin;
        s >> vout;
        s >> nLockTime;
        if (this->nVersion == 2)
        {
            s >> this->serviceReferenceHash;
        }
        UpdateHash();
    }
    */


    template <typename Stream>
    CTransaction(deserialize_type, Stream &s)
    {
        Unserialize(s);
    }

    bool IsNull() const { return vin.empty() && vout.empty(); }
    const TxId GetId() const { return TxId(hash); }
    uint256 GetHash() const;

    // Return sum of txouts.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize = 0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize = 0) const;

    bool IsCoinBase() const { return (vin.size() == 1 && vin[0].prevout.IsNull()); }
    bool IsCoinStake() const
    {
        // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    bool IsFinal(int nBlockHeight = 0, int64_t nBlockTime = 0) const;

    friend bool operator==(const CTransaction &a, const CTransaction &b) { return a.hash == b.hash; }
    friend bool operator!=(const CTransaction &a, const CTransaction &b) { return a.hash != b.hash; }
    std::string ToString() const;
    bool GetCoinAge(uint64_t &nCoinAge) const; // ppcoin: get transaction coin age
    uint64_t GetCoinAge(uint64_t nCoinAge, bool byValue) const;

    void UpdateHash() const;
};

/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256 &hash,
    CTransaction &tx,
    const Consensus::Params &params,
    uint256 &hashBlock,
    bool fAllowSlow = false);

typedef std::shared_ptr<CTransaction> CTransactionRef;
static inline CTransactionRef MakeTransactionRef() { return std::make_shared<CTransaction>(); }
template <typename Tx>
static inline CTransactionRef MakeTransactionRef(Tx &&txIn)
{
    return std::make_shared<CTransaction>(std::forward<Tx>(txIn));
}

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
