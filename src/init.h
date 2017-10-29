// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <string>
#include "wallet/wallet.h"
#include "chain/chainman.h"
#include "networks/netman.h"

class CScheduler;
class CWallet;

namespace boost
{
class thread_group;
} // namespace boost

extern CChainManager* pchainMain;
extern CWallet* pwalletMain;
extern CNetworkManager* pnetMan;

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt(boost::thread_group& threadGroup);
void Shutdown();
//!Initialize the logging infrastructure
void InitLogging();
//!Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction();
void GenerateNetworkTemplates();
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler);

/** Help for options shared between UI and daemon (for -help) */
std::string HelpMessage();
/** Returns licensing information (for -version) */
std::string LicenseInfo();

extern bool fShutdown;

#endif // BITCOIN_INIT_H
