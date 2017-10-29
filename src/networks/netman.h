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

        pnetLegacy = NULL;
        pnetPayment = NULL;
    }

    void initialize()
    {
        legacyTemplate = new CNetworkTemplate();
        ConstructLegacyNetworkTemplate();
        ConstructNetworks();
    }

    void ConstructLegacyNetworkTemplate();
    void ConstructNetworks();

    CNetwork* getActivePaymentNetwork()
    {
        return pnetLegacy;
    }

private:

    CNetwork* pnetLegacy;
    CNetwork* pnetPayment;

    CNetworkTemplate* legacyTemplate;
    CNetworkTemplate* paymentTemplate;

};

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();


#endif // BITCOIN_CHAINPARAMSBASE_H
