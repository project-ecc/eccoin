// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_CRYPTER_H
#define BITCOIN_WALLET_CRYPTER_H

#include "keystore.h"
#include "serialize.h"
#include "support/allocators/secure.h"

class uint256;

const unsigned int WALLET_CRYPTO_KEY_SIZE = 32;
const unsigned int WALLET_CRYPTO_SALT_SIZE = 8;

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;

/** Encryption/decryption context with key information */
class CCrypter
{
private:
    unsigned char chKey[WALLET_CRYPTO_KEY_SIZE];
    unsigned char chIV[WALLET_CRYPTO_KEY_SIZE];
    bool fKeySet;

public:
    bool SetKeyFromPassphrase(const SecureString &strKeyData,
        const std::vector<unsigned char> &chSalt,
        const unsigned int nRounds,
        const unsigned int nDerivationMethod);
    bool Encrypt(const CKeyingMaterial &vchPlaintext, std::vector<unsigned char> &vchCiphertext);
    bool Encrypt(const CKeyingMaterial &vchPlaintext, CCryptedPrivKey &vchCiphertext);
    bool Decrypt(const std::vector<unsigned char> &vchCiphertext, CKeyingMaterial &vchPlaintext);
    bool Decrypt(const CCryptedPrivKey &vchCiphertext, CKeyingMaterial &vchPlaintext);
    bool SetKey(const CKeyingMaterial &chNewKey, const std::vector<unsigned char> &chNewIV);

    void CleanKey()
    {
        memory_cleanse(chKey, sizeof(chKey));
        memory_cleanse(chIV, sizeof(chIV));
        fKeySet = false;
    }

    CCrypter()
    {
        fKeySet = false;

        // Try to keep the key data out of swap (and be a bit over-careful to keep the IV that we don't even use out of
        // swap)
        // Note that this does nothing about suspend-to-disk (which will put all our key data on disk)
        // Note as well that at no point in this program is any attempt made to prevent stealing of keys by reading the
        // memory of the running process.
        LockedPageManager::Instance().LockRange(&chKey[0], sizeof chKey);
        LockedPageManager::Instance().LockRange(&chIV[0], sizeof chIV);
    }

    ~CCrypter()
    {
        CleanKey();

        LockedPageManager::Instance().UnlockRange(&chKey[0], sizeof chKey);
        LockedPageManager::Instance().UnlockRange(&chIV[0], sizeof chIV);
    }
};

#endif // BITCOIN_WALLET_CRYPTER_H
