// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "chain/chainman.h"
#include "wallet/wallet.h"
#include <string>

class CWallet;

extern CWallet *pwalletMain;

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt(thread_group &threadGroup);
void Shutdown(thread_group &threadGroup);
//! Initialize the logging infrastructure
void InitLogging();
//! Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction();
bool AppInit2(thread_group &threadGroup);

/** Help for options shared between UI and daemon (for -help) */
std::string HelpMessage();
/** Returns licensing information (for -version) */
std::string LicenseInfo();

void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex);

extern std::unique_ptr<CCoinsViewDB> pcoinsdbview;


#endif // BITCOIN_INIT_H
