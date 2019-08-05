// This file is part of the Eccoin project
// Copyright (c) 2017-2018 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMSBASE_H
#define BITCOIN_CHAINPARAMSBASE_H

#include <string>
#include <vector>

#include "network.h"

static const int64_t SERVICE_UPGRADE_HARDFORK = 1525478400; // May 5th at 00:00:00 UTC

/**
 * CNetwork defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CNetworkManager
{
private:
    CNetwork *activePaymentNetwork;

    CNetwork *pnetLegacy;
    CNetwork *pnetTestnet0;
    CNetwork *pnetRegTest;

    CNetworkTemplate *legacyTemplate;
    CNetworkTemplate *testnet0Template;
    CNetworkTemplate *regTestTemplate;

public:
    CNetworkManager()
    {
        setNull();
        initialize();
    }

    void setNull()
    {
        legacyTemplate = nullptr;
        testnet0Template = nullptr;
        regTestTemplate = nullptr;


        pnetLegacy = nullptr;
        pnetTestnet0 = nullptr;
        pnetRegTest = nullptr;

        activePaymentNetwork = nullptr;
    }

    void initialize()
    {
        legacyTemplate = new CNetworkTemplate();
        ConstructLegacyNetworkTemplate();
        testnet0Template = new CNetworkTemplate();
        ConstructTetnet0Template();
        regTestTemplate = new CNetworkTemplate();
        ConstructRegTestTemplate();
        // only run construct networks after all templates have been made
        ConstructNetworks();
    }

    void ConstructLegacyNetworkTemplate();
    void ConstructTetnet0Template();
    void ConstructRegTestTemplate();
    void ConstructNetworks();

    CNetwork *getActivePaymentNetwork() { return activePaymentNetwork; }
    CChainManager *getChainActive() { return activePaymentNetwork->getChainManager(); }
    void SetParams(const std::string &network)
    {
        if (network == "LEGACY")
        {
            activePaymentNetwork = pnetLegacy;
        }
        else if (network == "TESTNET0")
        {
            activePaymentNetwork = pnetTestnet0;
        }
        else if (network == "REGTEST")
        {
            activePaymentNetwork = pnetRegTest;
        }
        else
        {
            throw std::runtime_error(strprintf("%s: Unknown network %s.", __func__, network));
        }
        return;
    }
};

// TODO : Fix this workaround that is used for RPC on command line. shuould either construct pnetMan earlier or find
// another way to get this value
int RPCPortFromCommandLine();

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();


void CheckParams(const std::string &network);

#endif // BITCOIN_CHAINPARAMSBASE_H
