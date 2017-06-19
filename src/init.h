// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "wallet.h"
#include "checkpoints.h"

namespace boost
{
class thread_group;
} // namespace boost

extern CWallet* pwalletMain;
extern Checkpoints* pcheckpointMain;
extern ServiceFlags nLocalServices;


extern std::string strWalletFileName;
void StartShutdown();
void Shutdown(void* parg);
bool AppInit2();
std::string HelpMessage();
bool ShutdownRequested();

/** Interrupt threads */
void Interrupt(boost::thread_group& threadGroup);
//!Initialize the logging infrastructure
void InitLogging();
//!Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction();

/** Initialize eccoin core: Basic context setup.
 *  @note This can be done before daemonization.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInitBasicSetup();
/**
 * Initialization: parameter interaction.
 * @note This can be done before daemonization.
 * @pre Parameters should be parsed and config file should be read, AppInitBasicSetup should have been called.
 */
bool AppInitParameterInteraction();

/**
 * Initialization sanity checks: ecc init, sanity checks, dir lock.
 * @note This can be done before daemonization.
 * @pre Parameters should be parsed and config file should be read, AppInitParameterInteraction should have been called.
 */
bool AppInitSanityChecks();

std::string LicenseInfo();

extern bool fEnforceCanonical;



#endif

