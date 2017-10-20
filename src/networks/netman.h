// Copyright (c) 2014-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMSBASE_H
#define BITCOIN_CHAINPARAMSBASE_H

#include <string>
#include <vector>

#include "baseparams.h"

/**
 * CBaseChainParams defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CNetMan
{
public:
    /** BIP70 chain name strings */

    //ecc payment networks
    static const std::string LEGACY; // legacy network that started the chain in 2014. will be replaced by payment network in 2018
    static const std::string PAYMENT; // payment network

    //service networks
    static const std::string ANS;  // Address-Name Service (DNS for addresses to usernames)
    static const std::string CMAP; // Chain Messaging Access Protocol (on chain IMAP) (where the chain is the server and daemons are the clients)
    static const std::string SFSP; // Secure File Storage Protocol (SFTP equivalent)
    static const std::string WEB;  // (HTTP and HTTPS)

    /// if testnet or regtest are active, none of the service networks should be allowed to be
    static const std::string TESTNET;
    static const std::string REGTEST;

    const std::string& DataDir() const { return strDataDir; }
    int RPCPort() const { return nRPCPort; }

protected:
    CNetMan() {}

    int nRPCPort;
    std::string strDataDir;
};

/**
 * Append the help messages for the chainparams options to the
 * parameter string.
 */
void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp=true);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CNetMan& BaseParams();

CNetMan& BaseParams(const std::string& chain);

/** Sets the params returned by Params() to those for the given network. */
void SelectBaseParams(const std::string& chain);

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();

/**
 * Return true if SelectBaseParamsFromCommandLine() has been called to select
 * a network.
 */
bool AreBaseParamsConfigured();

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CBaseParams &Params();

/**
 * @returns CChainParams for the given BIP70 chain name.
 */
CBaseParams& Params(const std::string& chain);

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string& chain);

#endif // BITCOIN_CHAINPARAMSBASE_H
