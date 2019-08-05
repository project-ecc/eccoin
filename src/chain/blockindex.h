// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef BLOCKINDEX_H
#define BLOCKINDEX_H

#include "arith_uint256.h"
#include "block.h"
#include "chain/tx.h"
#include "serialize.h"
#include "tinyformat.h"
#include "uint256.h"

#include <string>

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(VARINT(nFile, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() { SetNull(); }
    CDiskBlockPos(int nFileIn, unsigned int nPosIn)
    {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b)
    {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) { return !(a == b); }
    void SetNull()
    {
        nFile = -1;
        nPos = 0;
    }
    bool IsNull() const { return (nFile == -1); }
    std::string ToString() const { return strprintf("CBlockDiskPos(nFile=%i, nPos=%i)", nFile, nPos); }
};

enum BlockStatus
{
    //! Unused.
    BLOCK_VALID_UNKNOWN = 0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER = 1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE = 2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS = 3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN = 4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS = 5,

    //! All validity bits.
    BLOCK_VALID_MASK =
        BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS | BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA = 8, //! full block available in blk*.dat
    BLOCK_HAVE_UNDO = 16, //! undo data available in rev*.dat
    BLOCK_HAVE_MASK = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID = 32, //! stage after last reached validness failed
    BLOCK_FAILED_CHILD = 64, //! descends from failed block
    BLOCK_FAILED_MASK = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    const uint256 *phashBlock;

    //! pointer to the index of the predecessor of this block
    CBlockIndex *pprev;

    //! pointer to the index of some further predecessor of this block
    CBlockIndex *pskip;

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight;

    //! Which # file this block is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    arith_uint256 nChainWork;

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    //! Change to 64-bit type when necessary; won't happen before 2030
    unsigned int nChainTx;

    //! Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    unsigned int nFlags; // ppcoin: block index flags
    enum
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
        BLOCK_STAKE_ENTROPY = (1 << 1), // entropy bit for stake modifier
    };

    uint256 nStakeModifier; // hash modifier for proof-of-stake

    // proof-of-stake specific fields
    COutPoint prevoutStake;
    unsigned int nStakeTime;
    uint256 hashProofOfStake;

    int64_t nMint;
    int64_t nMoneySupply;

    //! block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    uint32_t nSequenceId;

    void SetNull()
    {
        phashBlock = nullptr;
        pprev = nullptr;
        pskip = nullptr;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = arith_uint256();
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;
        nSequenceId = 0;

        nVersion = 0;
        hashMerkleRoot = uint256();
        nTime = 0;
        nBits = 0;
        nNonce = 0;

        // proof-of-stake specific fields
        nFlags = 0;
        nMint = 0;
        nMoneySupply = 0;
        nStakeModifier.SetNull();
        prevoutStake.SetNull();
        nStakeTime = 0;
        hashProofOfStake.SetNull();
    }

    CBlockIndex() { SetNull(); }
    CBlockIndex(const CBlockHeader &block)
    {
        SetNull();

        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime = block.nTime;
        nBits = block.nBits;
        nNonce = block.nNonce;
    }

    CDiskBlockPos GetBlockPos() const
    {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA)
        {
            ret.nFile = nFile;
            ret.nPos = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const
    {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO)
        {
            ret.nFile = nFile;
            ret.nPos = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block;
    }

    uint256 GetBlockHash() const { return *phashBlock; }
    int64_t GetBlockTime() const { return (int64_t)nTime; }
    enum
    {
        nMedianTimeSpan = 11
    };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t *pbegin = &pmedian[nMedianTimeSpan];
        int64_t *pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex *pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        {
            if (pindex)
            {
                *(--pbegin) = pindex->GetBlockTime();
            }
        }

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin) / 2];
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)", pprev, nHeight,
            hashMerkleRoot.ToString(), GetBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo)
        {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    void updateForPos(const CBlock &block);

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex *GetAncestor(int height);
    const CBlockIndex *GetAncestor(int height) const;

    // proof of stake functions
    bool IsProofOfWork() const;
    bool IsProofOfStake() const;
    void SetProofOfStake();
    unsigned int GetStakeEntropyBit() const;
    bool SetStakeEntropyBit(unsigned int nEntropyBit);
    void SetStakeModifier(uint256 nModifier);
};

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashBlock;
    uint256 hashPrev;

    CDiskBlockIndex() { hashPrev = uint256(); }
    explicit CDiskBlockIndex(const CBlockIndex *pindex) : CBlockIndex(*pindex)
    {
        hashBlock = pindex->GetBlockHash();
        hashPrev = (pprev ? pprev->GetBlockHash() : uint256());
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        int nStreamVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(VARINT(nStreamVersion, VarIntMode::NONNEGATIVE_SIGNED));

        READWRITE(VARINT(nHeight, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile, VarIntMode::NONNEGATIVE_SIGNED));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // added after db upgrade to reduce loadtime of index
        READWRITE(hashBlock);
        // block header
        READWRITE(nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nMint);
        READWRITE(nMoneySupply);
        READWRITE(nFlags);
        READWRITE(nStakeModifier);
        if (IsProofOfStake())
        {
            READWRITE(prevoutStake);
            READWRITE(nStakeTime);
            READWRITE(hashProofOfStake);
        }
    }

    uint256 GetBlockHash() const
    {
        CBlockHeader block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrev;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block.GetHash();
    }


    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str +=
            strprintf("\n                hashBlock=%s, hashPrev=%s)", GetBlockHash().ToString(), hashPrev.ToString());
        return str;
    }
};

#endif // BLOCKINDEX_H
