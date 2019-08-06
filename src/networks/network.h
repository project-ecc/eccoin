// This file is part of the Eccoin project
// Copyright (c) 2017-2018 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NETWORK_H
#define NETWORK_H

#include <boost/variant.hpp>
#include <string>
#include <vector>

#include "chain/chainman.h"
#include "networktemplate.h"


/** BIP70 chain name strings */
/*

    //ecc networks
    LEGACY = "LEGACY",    // legacy network that started the chain in 2014

    //service networks
    ANS  = "ANS" ,        // Address-Name Service (DNS for addresses to usernames)
    CMTP = "CMTP",        // Chain Mail Transfer Protocol
    SFSP = "SFSP",        // Secure File Storage Protocol (SFTP equivalent)
    WEB  = "WEB" ,        // (HTTP and HTTPS)

    /// if testnet or regtest are active, none of the service networks should be allowed to be
    TESTNET0 = "TESTNET0",  //
    REGTEST = "REGTEST",  //

*/

/**
 * CNetwork defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CNetwork : public CNetworkTemplate
{
public:
    CNetwork(CNetworkTemplate *param_netTemplate) : CNetworkTemplate(param_netTemplate)
    {
        this->chainman = CChainManager();
    }
    const std::string &DataDir() const { return strNetworkDataDir; }
    CChainManager *getChainManager() { return &chainman; }
    /// TODO: put a check somewhere to make sure all data members have been set properly
private:
    CChainManager chainman;
};

#endif // NETWORK_H
