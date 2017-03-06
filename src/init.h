// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "util.h"
#include "wallet.h"
#include "checkpoints.h"

extern CWallet* pwalletMain;
extern Checkpoints* pcheckpointMain;


extern std::string strWalletFileName;
void StartShutdown();
void Shutdown(void* parg);
bool AppInit2();
std::string HelpMessage();

extern bool fEnforceCanonical;

#endif
