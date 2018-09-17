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

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "prevector.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <vector>

typedef uint256 ChainCode;

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256
{
private:
    CSHA256 sha;

public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(uint8_t hash[OUTPUT_SIZE])
    {
        uint8_t buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash256 &Write(const uint8_t *data, size_t len)
    {
        sha.Write(data, len);
        return *this;
    }

    CHash256 &Reset()
    {
        sha.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160
{
private:
    CSHA256 sha;

public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE])
    {
        unsigned char buf[sha.OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, sha.OUTPUT_SIZE).Finalize(hash);
    }

    CHash160 &Write(const unsigned char *data, size_t len)
    {
        sha.Write(data, len);
        return *this;
    }

    CHash160 &Reset()
    {
        sha.Reset();
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
template <typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256()
        .Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template <typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end, const T2 p2begin, const T2 p2end)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256()
        .Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
        .Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of three objects. */
template <typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin,
    const T1 p1end,
    const T2 p2begin,
    const T2 p2end,
    const T3 p3begin,
    const T3 p3end)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHash256()
        .Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
        .Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
        .Write(p3begin == p3end ? pblank : (const unsigned char *)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 160-bit hash an object. */
template <typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    uint160 result;
    CHash160()
        .Write(pbegin == pend ? pblank : (const unsigned char *)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
        .Finalize((unsigned char *)&result);
    return result;
}

/** Compute the 160-bit hash of a vector. */
inline uint160 Hash160(const std::vector<unsigned char> &vch) { return Hash160(vch.begin(), vch.end()); }
/** Compute the 160-bit hash of a vector. */
template <unsigned int N>
inline uint160 Hash160(const prevector<N, unsigned char> &vch)
{
    return Hash160(vch.begin(), vch.end());
}

/** A writer stream (for serialization) that computes a 256-bit hash. */
class CHashWriter
{
private:
    CHash256 ctx;

public:
    int nType;
    int nVersion;

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}
    CHashWriter &write(const char *pch, size_t size)
    {
        ctx.Write((const unsigned char *)pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash()
    {
        uint256 result;
        ctx.Finalize((unsigned char *)&result);
        return result;
    }

    template <typename T>
    CHashWriter &operator<<(const T &obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

/** Compute the 256-bit hash of an object's serialization. */
template <typename T>
uint256 SerializeHash(const T &obj, int nType = SER_GETHASH, int nVersion = PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char> &vDataToHash);

void BIP32Hash(const unsigned char chainCode[32],
    unsigned int nChild,
    unsigned char header,
    const unsigned char data[32],
    unsigned char output[64]);

/** SipHash-2-4 */
class CSipHasher
{
private:
    uint64_t v[4];
    uint64_t tmp;
    int count;

public:
    /** Construct a SipHash calculator initialized with 128-bit key (k0, k1) */
    CSipHasher(uint64_t k0, uint64_t k1);
    /**
     * Hash a 64-bit integer worth of data.
     * It is treated as if this was the little-endian interpretation of 8 bytes.
     * This function can only be used when a multiple of 8 bytes have been
     * written so far.
     */
    CSipHasher &Write(uint64_t data);
    /** Hash arbitrary bytes. */
    CSipHasher &Write(const uint8_t *data, size_t size);
    /** Compute the 64-bit SipHash-2-4 of the data written so far. The object
     * remains untouched. */
    uint64_t Finalize() const;
};

/** Optimized SipHash-2-4 implementation for uint256.
 *
 *  It is identical to:
 *    SipHasher(k0, k1)
 *      .Write(val.GetUint64(0))
 *      .Write(val.GetUint64(1))
 *      .Write(val.GetUint64(2))
 *      .Write(val.GetUint64(3))
 *      .Finalize()
 */
uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256 &val);
uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256 &val, uint32_t extra);

#endif // BITCOIN_HASH_H
