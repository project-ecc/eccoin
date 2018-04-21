// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include "compressor.h" 
#include "tx/tx.h"
#include "serialize.h"

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and if this was the
 *  last output of the affected transaction, its metadata as well
 *  (coinbase or not, height, transaction version)
 */
class CTxInUndo
{
public:
    CTxOut txout;         // the txout data before being spent
    bool fCoinBase;       // if the outpoint was the last unspent: whether it belonged to a coinbase
    unsigned int nHeight; // if the outpoint was the last unspent: its height
    int nVersion;         // if the outpoint was the last unspent: its version
    bool fCoinStake;      // if the outpoint was the last unspent: whether it belonged to a coinstake
    unsigned int nTime;   // if the outpoint was the last unspent: its tx timestamp

    CTxInUndo() : txout(), fCoinBase(false), nHeight(0), nVersion(0), fCoinStake(false), nTime(0) {}
    CTxInUndo(const CTxOut &txoutIn, bool fCoinBaseIn = false, unsigned int nHeightIn = 0, int nVersionIn = 0, bool fCoinStakeIn = false, unsigned int nTimeIn = 0) : txout(txoutIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), nVersion(nVersionIn), fCoinStake(fCoinStakeIn), nTime(nTimeIn) { }

    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return ::GetSerializeSize(VARINT(nHeight*2+(fCoinBase ? 1 : 0)+(fCoinStake ? 2 : 0)), nType, nVersion) +
               ::GetSerializeSize(VARINT(nTime), nType, nVersion) +
               (nHeight > 0 ? ::GetSerializeSize(VARINT(this->nVersion), nType, nVersion) : 0) +
               ::GetSerializeSize(CTxOutCompressor(REF(txout)), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream &s) const {
        ::Serialize(s, VARINT(nHeight*4+(fCoinBase ? 1 : 0)+(fCoinStake ? 2 : 0)));
        ::Serialize(s, VARINT(nTime));
        if (nHeight > 0)
            ::Serialize(s, VARINT(this->nVersion));
        ::Serialize(s, CTxOutCompressor(REF(txout)));
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        nHeight = nCode / 4;
        fCoinBase = nCode & 1;
        fCoinStake = nCode & 2;
        ::Unserialize(s, VARINT(nTime));
        if (nHeight > 0)
            ::Unserialize(s, VARINT(this->nVersion));
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout))));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<CTxInUndo> vprevout;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vprevout);
    }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vtxundo);
    }
};

enum DisconnectResult {
    // All good.
    DISCONNECT_OK,
    // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_UNCLEAN,
    // Something else went wrong.
    DISCONNECT_FAILED,
};

#endif // BITCOIN_UNDO_H
