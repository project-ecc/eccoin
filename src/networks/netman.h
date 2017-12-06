// Copyright (c) 2014-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMSBASE_H
#define BITCOIN_CHAINPARAMSBASE_H

#include <string>
#include <vector>

#include "network.h"

/**
 * CNetwork defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CNetworkManager
{
public:
    CNetworkManager()
    {
        setNull();
        initialize();
    }

    void setNull()
    {
        legacyTemplate = NULL;
        paymentTemplate = NULL;
        netManTestnetTemplate = NULL;
        
        pnetLegacy = NULL;
        pnetPayment = NULL;
        pnetTestnet0 = NULL;
        
        activePaymentNetwork = NULL;
    }

    void initialize()
    {
        legacyTemplate = new CNetworkTemplate();
        ConstructLegacyNetworkTemplate();
        netManTestnetTemplate = new CNetworkTemplate();
        ConstructTetnet0Template();
        //only run construct networks after all templates have been made
        ConstructNetworks();
    }

    void ConstructLegacyNetworkTemplate();

    void ConstructTetnet0Template();

    void ConstructNetworks();

    CNetwork* getActivePaymentNetwork()
    {
        return activePaymentNetwork;
    }

    void SetParams(const std::string& network)
    {
        if (network == "LEGACY")
        {
            activePaymentNetwork = pnetLegacy;
        }
        else if (network == "TESTNET0-TEMPORARY")
        {
            activePaymentNetwork = pnetTestnet0;
        }
        else
        {
            throw std::runtime_error(strprintf("%s: Unknown network %s.", __func__, network));
        }
        return;
    }
private:
    CNetwork* activePaymentNetwork;

    CNetwork* pnetLegacy;
    CNetwork* pnetPayment;

    CNetwork* pnetTestnet0;

    CNetworkTemplate* legacyTemplate;
    CNetworkTemplate* paymentTemplate;
    CNetworkTemplate* netManTestnetTemplate;


};

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();


void CheckParams(const std::string& network);

#endif // BITCOIN_CHAINPARAMSBASE_H

