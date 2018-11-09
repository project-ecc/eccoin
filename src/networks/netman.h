/*
 * This file is part of the Eccoin project
 * Copyright (c) 2017-2018 Greg Griffith
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
    CNetwork* activePaymentNetwork;

    CNetwork* pnetLegacy;
    CNetwork* pnetPayment;
    CNetwork* pnetTestnet0;
    CNetwork* pnetRegTest;

    CNetworkTemplate* legacyTemplate;
    CNetworkTemplate* paymentTemplate;
    CNetworkTemplate* testnet0Template;
    CNetworkTemplate* regTestTemplate;

public:
    CNetworkManager()
    {
        setNull();
        initialize();
    }

    void setNull()
    {
        legacyTemplate = nullptr;
        paymentTemplate = nullptr;
        testnet0Template = nullptr;
        regTestTemplate = nullptr;


        pnetLegacy = nullptr;
        pnetPayment = nullptr;
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
        //only run construct networks after all templates have been made
        ConstructNetworks();
    }

    void ConstructLegacyNetworkTemplate();
    void ConstructTetnet0Template();
    void ConstructRegTestTemplate();
    void ConstructNetworks();

    CNetwork* getActivePaymentNetwork()
    {
        return activePaymentNetwork;
    }
    CChainManager* getChainActive()
    {
        return activePaymentNetwork->getChainManager();
    }

    void SetParams(const std::string& network)
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

/// TODO : Fix this workaround that is used for RPC on command line. shuould either construct pnetMan earlier or find another way to get this value
int RPCPortFromCommandLine();

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();


void CheckParams(const std::string& network);

#endif // BITCOIN_CHAINPARAMSBASE_H
