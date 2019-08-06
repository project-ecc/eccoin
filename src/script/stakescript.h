// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STAKESCRIPT_H
#define STAKESCRIPT_H

#include "script.h"

class CTransaction;

bool VerifyScript(const CScript &scriptSig,
    const CScript &scriptPubKey,
    const CTransaction &txTo,
    unsigned int nIn,
    bool fValidatePayToScriptHash);
bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CTransaction &txTo, unsigned int nIn);
bool VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn);
bool VerifySignature(const CTransaction &txFrom,
    const CTransaction &txTo,
    unsigned int nIn,
    bool fValidatePayToScriptHash);

#endif // STAKESCRIPT_H
