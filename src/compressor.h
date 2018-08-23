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

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include "chain/tx.h"
#include "script/script.h"
#include "serialize.h"


class CKeyID;
class CPubKey;
class CScriptID;

/**
 * Compact serializer for scripts.
 *
 * It detects common cases and encodes them much more efficiently.
 * 3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 * Other scripts up to 121 bytes require 1 byte + script length. Above that,
 * scripts up to 16505 bytes require 2 bytes + script length.
 */
class CScriptCompressor {
private:
    /**
     * make this static for now (there are only 6 special scripts defined) this
     * can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion and
     * nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    CScript &script;

protected:
    /**
     * These check for scripts for which a special case with a shorter encoding
     * is defined. They are implemented separately from the CScript test, as
     * these test for exact byte sequence correspondences, and are more strict.
     * For example, IsToPubKey also verifies whether the public key is valid (as
     * invalid ones cannot be represented in compressed form).
     */
    bool IsToKeyID(CKeyID &hash) const;
    bool IsToScriptID(CScriptID &hash) const;
    bool IsToPubKey(CPubKey &pubkey) const;

    bool Compress(std::vector<uint8_t> &out) const;
    unsigned int GetSpecialSize(unsigned int nSize) const;
    bool Decompress(unsigned int nSize, const std::vector<uint8_t> &out);

public:
    CScriptCompressor(CScript &scriptIn) : script(scriptIn) {}

    template <typename Stream> void Serialize(Stream &s) const {
        std::vector<uint8_t> compr;
        if (Compress(compr)) {
            s << CFlatData(compr);
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << CFlatData(script);
    }

    template <typename Stream> void Unserialize(Stream &s) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            std::vector<uint8_t> vch(GetSpecialSize(nSize), 0x00);
            s >> REF(CFlatData(vch));
            Decompress(nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> REF(CFlatData(script));
        }
    }
};

/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor {
private:
    CTxOut &txout;

public:
    static uint64_t CompressAmount(uint64_t nAmount);
    static uint64_t DecompressAmount(uint64_t nAmount);

    CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if (!ser_action.ForRead()) {
            uint64_t nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        } else {
            uint64_t nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        CScriptCompressor cscript(REF(txout.scriptPubKey));
        READWRITE(cscript);
    }
};

#endif // BITCOIN_COMPRESSOR_H
