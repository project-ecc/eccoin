// This file is part of the Eccoin project
// Copyright (c) 2017-2018 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <map>
#include <string>
#include <vector>

#include "chain/block.h"
#include "chain/checkpoints.h"
#include "consensus/params.h"
#include "net/protocol.h"

struct CDNSSeedData
{
    std::string name, host;
    bool supportsServiceBitsFiltering;
    CDNSSeedData(const std::string &strName, const std::string &strHost, bool supportsServiceBitsFilteringIn = false)
        : name(strName), host(strHost), supportsServiceBitsFiltering(supportsServiceBitsFilteringIn)
    {
    }
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type
    {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        MAX_BASE58_TYPES
    };

protected:
    Consensus::Params consensus;
    CMessageHeader::MessageMagic pchMessageStart;
    int nDefaultPort;
    int nRPCPort;
    long nMaxTipAge;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string strNetworkID;
    std::string strNetworkDataDir;
    CBlock genesis;
    bool fMiningRequiresPeers;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    bool fTestnetToBeDeprecatedFieldRPC;
    MapCheckpoints mapCheckpoints;
    unsigned int nStakeMaxAge;
    unsigned int nStakeMinAge;

public:
    CChainParams() {}
    const Consensus::Params &GetConsensus() const { return consensus; }
    const CMessageHeader::MessageMagic &MessageStart() const { return pchMessageStart; }
    int GetDefaultPort() const { return nDefaultPort; }
    int GetRPCPort() const { return nRPCPort; }
    const CBlock &GenesisBlock() const { return genesis; }
    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    int64_t MaxTipAge() const { return nMaxTipAge; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** In the future use NetworkIDString() for RPC fields */
    bool TestnetToBeDeprecatedFieldRPC() const { return fTestnetToBeDeprecatedFieldRPC; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    std::string NetworkDataDir() const { return strNetworkDataDir; }
    const std::vector<CDNSSeedData> &DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char> &Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const MapCheckpoints &Checkpoints() const { return mapCheckpoints; }
    unsigned int getStakeMaxAge() const { return nStakeMaxAge; }
    unsigned int getStakeMinAge() const { return nStakeMinAge; }
    int getpch0() const { return pchMessageStart[0]; }
    int getpch1() const { return pchMessageStart[1]; }
    int getpch2() const { return pchMessageStart[2]; }
    int getpch3() const { return pchMessageStart[3]; }
};

const CChainParams &Params();

static const int64_t LONGER_BLOCKTIME_HARDFORK = 1525478400; // May 5th at 00:00:00 UTC

// TODO : Fix this workaround that is used for RPC on command line. shuould either construct pnetMan earlier or find
// another way to get this value
int RPCPortFromCommandLine();

/**
 * Looks for -regtest, -testnet and returns the appropriate BIP70 chain name.
 * @return CBaseChainParams::MAX_NETWORK_TYPES if an invalid combination is given. CBaseChainParams::MAIN by default.
 */
std::string ChainNameFromCommandLine();

void CheckAndSetParams(const std::string &network);

#endif // BITCOIN_CHAINPARAMS_H
