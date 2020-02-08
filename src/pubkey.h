// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PUBKEY_H
#define BITCOIN_PUBKEY_H

#include "crypto/hash.h"
#include "serialize.h"
#include "uint256.h"
#include "util/utilstrencodings.h"

#include <stdexcept>
#include <vector>

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    CKeyID(const uint160 &in) : uint160(in) {}
};

typedef uint256 ChainCode;

/** An encapsulated public key. */
class CPubKey
{
private:
    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    unsigned char vch[65];

    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 65;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate() { vch[0] = 0xFF; }
public:
    //! Construct an invalid public key.
    CPubKey() { Invalidate(); }
    std::vector<unsigned char> Raw() const
    {
        std::vector<unsigned char> ch;
        for (unsigned int i = 0; i < size(); i++)
        {
            ch.emplace_back(vch[i]);
        }
        return ch;
    }

    std::string Raw64Encoded() const
    {
        std::vector<unsigned char> ch;
        for (unsigned int i = 0; i < size(); i++)
        {
            ch.emplace_back(vch[i]);
        }
        return EncodeBase64(&ch[0], size());
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char *)&pbegin[0], len);
        else
            Invalidate();
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char> &_vch) { Set(_vch.begin(), _vch.end()); }
    CPubKey(const std::string &_vch_raw64)
    {
        std::vector<unsigned char> _vch = DecodeBase64(_vch_raw64.c_str());
        Set(_vch.begin(), _vch.end());
    }
    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char *begin() const { return vch; }
    const unsigned char *end() const { return vch + size(); }
    const unsigned char &operator[](unsigned int pos) const { return vch[pos]; }
    //! Comparator implementation.
    friend bool operator==(const CPubKey &a, const CPubKey &b)
    {
        return a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) { return !(a == b); }
    friend bool operator<(const CPubKey &a, const CPubKey &b)
    {
        return a.vch[0] < b.vch[0] || (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    //! Implement serialization, as if this was a byte vector.
    unsigned int GetSerializeSize(int nType, int nVersion) const { return size() + 1; }
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s.write((char *)vch, len);
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= 65)
        {
            s.read((char *)vch, len);
        }
        else
        {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const { return CKeyID(Hash160(vch, vch + size())); }
    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const { return Hash(vch, vch + size()); }
    /*
     * Check syntactic correctness.
     *
     * Note that this is consensus critical as CheckSig() calls it!
     */
    bool IsValid() const { return size() > 0; }
    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const { return size() == 33; }
    /**
     * Verify a DER signature (~72 bytes).
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256 &hash, const std::vector<unsigned char> &vchSig) const;

    /**
     * Check whether a signature is normalized (lower-S).
     */
    static bool CheckLowS(const std::vector<unsigned char> &vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256 &hash, const std::vector<unsigned char> &vchSig);

    //! Turn this public key into an uncompressed public key.
    bool Decompress();

    //! Derive BIP32 child pubkey.
    bool Derive(CPubKey &pubkeyChild, unsigned char ccChild[32], unsigned int nChild, const unsigned char cc[32]) const;
};

struct CExtPubKey
{
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    unsigned char vchChainCode[32];
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 &&
               a.nChild == b.nChild && memcmp(&a.vchChainCode[0], &b.vchChainCode[0], 32) == 0 && a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[74]) const;
    void Decode(const unsigned char code[74]);
    bool Derive(CExtPubKey &out, unsigned int nChild) const;
};

/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

#endif // BITCOIN_PUBKEY_H
