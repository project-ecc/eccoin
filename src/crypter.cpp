// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypter.h"

#include "crypto/aes.h"
#include "script/script.h"
#include "script/standard.h"
#include "util/logger.h"
#include "util/util.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

bool CCrypter::SetKeyFromPassphrase(const SecureString &strKeyData,
    const std::vector<unsigned char> &chSalt,
    const unsigned int nRounds,
    const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &chSalt[0], (unsigned char *)&strKeyData[0],
            strKeyData.size(), nRounds, chKey, chIV);

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(chKey, sizeof(chKey));
        memory_cleanse(chIV, sizeof(chIV));
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial &chNewKey, const std::vector<unsigned char> &chNewIV)
{
    if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_KEY_SIZE)
        return false;

    memcpy(&chKey[0], &chNewKey[0], sizeof chKey);
    memcpy(&chIV[0], &chNewIV[0], sizeof chIV);

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial &vchPlaintext, std::vector<unsigned char> &vchCiphertext)
{
    if (!fKeySet)
        return false;
    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCKSIZE bytes
    vchCiphertext.resize(vchPlaintext.size() + AES_BLOCKSIZE);

    AES256CBCEncrypt enc(chKey, chIV, true);
    size_t nLen = enc.Encrypt(&vchPlaintext[0], vchPlaintext.size(), &vchCiphertext[0]);
    if (nLen < vchPlaintext.size())
        return false;
    vchCiphertext.resize(nLen);
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial &vchPlaintext, CCryptedPrivKey &vchCiphertext)
{
    if (!fKeySet)
        return false;
    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCKSIZE bytes
    vchCiphertext.resize(vchPlaintext.size() + AES_BLOCKSIZE);

    AES256CBCEncrypt enc(chKey, chIV, true);
    size_t nLen = enc.Encrypt(&vchPlaintext[0], vchPlaintext.size(), &vchCiphertext[0]);
    if (nLen < vchPlaintext.size())
        return false;
    vchCiphertext.resize(nLen);
    return true;
}

bool CCrypter::Decrypt(const std::vector<unsigned char> &vchCiphertext, CKeyingMaterial &vchPlaintext)
{
    if (!fKeySet)
        return false;
    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();
    vchPlaintext.resize(nLen);
    AES256CBCDecrypt dec(chKey, chIV, true);
    nLen = dec.Decrypt(&vchCiphertext[0], vchCiphertext.size(), &vchPlaintext[0]);
    if (nLen == 0)
        return false;
    vchPlaintext.resize(nLen);
    return true;
}

bool CCrypter::Decrypt(const CCryptedPrivKey &vchCiphertext, CKeyingMaterial &vchPlaintext)
{
    if (!fKeySet)
        return false;
    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();
    vchPlaintext.resize(nLen);
    AES256CBCDecrypt dec(chKey, chIV, true);
    nLen = dec.Decrypt(&vchCiphertext[0], vchCiphertext.size(), &vchPlaintext[0]);
    if (nLen == 0)
        return false;
    vchPlaintext.resize(nLen);
    return true;
}
