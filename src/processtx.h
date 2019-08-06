// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXVALIDATION_H
#define TXVALIDATION_H

#include "chain/tx.h"
#include "validationinterface.h"

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction &tx, CValidationState &state);

#endif // TXVALIDATION_H
