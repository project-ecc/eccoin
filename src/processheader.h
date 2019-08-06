// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROCESSHEADER_H
#define PROCESSHEADER_H

#include "networks/networktemplate.h"
#include "validationinterface.h"

bool CheckBlockHeader(const CBlockHeader &block, CValidationState &state);
bool ContextualCheckBlockHeader(const CBlockHeader &block, CValidationState &state, CBlockIndex *pindexPrev);
bool AcceptBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CNetworkTemplate &chainparams,
    CBlockIndex **ppindex = NULL);

#endif // PROCESSHEADER_H
