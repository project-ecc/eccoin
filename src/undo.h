/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
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

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include "chain/tx.h"
#include "compressor.h"
#include "serialize.h"

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is be compatible with older versions which expect to see
 *  the transaction version there.
 */
class TxInUndoSerializer
{
    const Coin *txout;

public:
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        ::Serialize(s, VARINT(txout->nHeight * 4 + (txout->fCoinBase ? 1 : 0) + (txout->fCoinStake ? 2 : 0),
                           VarIntMode::NONNEGATIVE_SIGNED));
        // Required to maintain compatibility with older undo format
        ::Serialize(s, (unsigned char)0);
        if (txout->nHeight > 0)
        {
            // Required to maintain compatibility with older undo format
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, CTxOutCompressor(REF(txout->out)));
    }

    TxInUndoSerializer(const Coin *coin) : txout(coin) {}
};

class TxInUndoDeserializer
{
    Coin *txout;

public:
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout->nHeight = nCode / 4;
        txout->fCoinBase = nCode & 1;
        txout->fCoinStake = nCode & 2;
        unsigned int nTimeDummy;
        ::Unserialize(s, VARINT(nTimeDummy));
        if (txout->nHeight > 0)
        {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout->out))));
    }

    TxInUndoDeserializer(Coin *coin) : txout(coin) {}
};


static const size_t MAX_INPUTS_PER_BLOCK =
    std::numeric_limits<long long>::max() / ::GetSerializeSize(CTxIn(), SER_NETWORK, PROTOCOL_VERSION);

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        // TODO: avoid reimplementing vector serializer
        uint64_t count = vprevout.size();
        ::Serialize(s, COMPACTSIZE(REF(count)));
        for (const auto &prevout : vprevout)
        {
            ::Serialize(s, REF(TxInUndoSerializer(&prevout)));
        }
    }

    template <typename Stream>
    void Unserialize(Stream &s)
    {
        // TODO: avoid reimplementing vector deserializer
        uint64_t count = 0;
        ::Unserialize(s, COMPACTSIZE(count));
        if (count > MAX_INPUTS_PER_BLOCK)
        {
            throw std::ios_base::failure("Too many input undo records");
        }
        vprevout.resize(count);
        for (auto &prevout : vprevout)
        {
            ::Unserialize(s, REF(TxInUndoDeserializer(&prevout)));
        }
    }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(vtxundo);
    }
};

enum DisconnectResult
{
    // All good.
    DISCONNECT_OK,
    // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_UNCLEAN,
    // Something else went wrong.
    DISCONNECT_FAILED,
};

#endif // BITCOIN_UNDO_H
