#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include <boost/variant.hpp>

#include "chain/chainman.h"
#include "networktemplate.h"


/** BIP70 chain name strings */
/*

    //ecc payment networks
    LEGACY = "LEGACY",    // legacy network that started the chain in 2014. will be replaced by payment network in 2018
    PAYMENT = "PAYMENT",  // payment network

    //service networks
    ANS  = "ANS" ,        // Address-Name Service (DNS for addresses to usernames)
    CMAP = "CMAP",        // Chain Messaging Access Protocol (on chain IMAP) (where the chain is the server and daemons are the clients)
    SFSP = "SFSP",        // Secure File Storage Protocol (SFTP equivalent)
    WEB  = "WEB" ,        // (HTTP and HTTPS)

    /// if testnet or regtest are active, none of the service networks should be allowed to be
    TESTNET = "TESTNET",  //
    REGTEST = "REGTEST",  //

*/

/**
 * CNetwork defines the base parameters (shared between bitcoin-cli and bitcoind)
 * of a given instance of the Bitcoin system.
 */
class CNetwork : public CNetworkTemplate
{
public:
    CNetwork(const CNetworkTemplate& param_netTemplate) : CNetworkTemplate(param_netTemplate)
    {
    }
    const std::string& DataDir() const { return strDataDir; }
    CChainManager* getChainManager() { return &chainman; }

    /// TODO: put a check somewhere to make sure all data members have been set properly
private:
    std::string strDataDir;
    CChainManager chainman;
};

#endif // NETWORK_H
