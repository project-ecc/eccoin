/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
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

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "chain/chainman.h"
#include "networks/netman.h"
#include "wallet/wallet.h"
#include <string>

class CWallet;

extern CWallet *pwalletMain;
extern CNetworkManager *pnetMan;

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt(thread_group &threadGroup);
void Shutdown(thread_group &threadGroup);
//! Initialize the logging infrastructure
void InitLogging();
//! Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction();
void GenerateNetworkTemplates();
bool AppInit2(thread_group &threadGroup);

/** Help for options shared between UI and daemon (for -help) */
std::string HelpMessage();
/** Returns licensing information (for -version) */
std::string LicenseInfo();

void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex);

extern std::unique_ptr<CCoinsViewDB> pcoinsdbview;


#endif // BITCOIN_INIT_H
