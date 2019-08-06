// This file is part of the Eccoin project
// Copyright (c) 2017-2018 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include "chain/block.h"
#include "consensus/params.h"
#include "net/protocol.h"

#include <vector>

struct CDNSSeedData
{
    std::string name, host;
    bool supportsServiceBitsFiltering;
    CDNSSeedData(const std::string &strName, const std::string &strHost, bool supportsServiceBitsFilteringIn = false)
        : name(strName), host(strHost), supportsServiceBitsFiltering(supportsServiceBitsFilteringIn)
    {
    }
};


typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData
{
    MapCheckpoints mapCheckpoints;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CNetworkTemplate
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

    /// TODO: make all of the data members below this point protected and make setters for them all

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
    CCheckpointData checkpointData;
    unsigned int nStakeMaxAge;
    unsigned int nStakeMinAge;


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
    const CCheckpointData &Checkpoints() const { return checkpointData; }
    unsigned int getStakeMaxAge() const { return nStakeMaxAge; }
    unsigned int getStakeMinAge() const { return nStakeMinAge; }
    int getpch0() const { return pchMessageStart[0]; }
    int getpch1() const { return pchMessageStart[1]; }
    int getpch2() const { return pchMessageStart[2]; }
    int getpch3() const { return pchMessageStart[3]; }
    CNetworkTemplate() {}
    CNetworkTemplate(CNetworkTemplate *param_netTemplate)
    {
        this->consensus = param_netTemplate->GetConsensus();

        this->pchMessageStart[0] = param_netTemplate->getpch0();
        this->pchMessageStart[1] = param_netTemplate->getpch1();
        this->pchMessageStart[2] = param_netTemplate->getpch2();
        this->pchMessageStart[3] = param_netTemplate->getpch3();

        this->base58Prefixes[CNetworkTemplate::PUBKEY_ADDRESS] =
            param_netTemplate->Base58Prefix(CNetworkTemplate::PUBKEY_ADDRESS);
        this->base58Prefixes[CNetworkTemplate::SCRIPT_ADDRESS] =
            param_netTemplate->Base58Prefix(CNetworkTemplate::SCRIPT_ADDRESS);
        this->base58Prefixes[CNetworkTemplate::SECRET_KEY] =
            param_netTemplate->Base58Prefix(CNetworkTemplate::SECRET_KEY);
        this->base58Prefixes[CNetworkTemplate::EXT_PUBLIC_KEY] =
            param_netTemplate->Base58Prefix(CNetworkTemplate::EXT_PUBLIC_KEY);
        this->base58Prefixes[CNetworkTemplate::EXT_SECRET_KEY] =
            param_netTemplate->Base58Prefix(CNetworkTemplate::EXT_SECRET_KEY);

        this->nDefaultPort = param_netTemplate->GetDefaultPort();
        this->nRPCPort = param_netTemplate->GetRPCPort();
        this->nMaxTipAge = param_netTemplate->MaxTipAge();
        this->vSeeds = param_netTemplate->DNSSeeds();
        this->strNetworkID = param_netTemplate->NetworkIDString();
        this->strNetworkDataDir = param_netTemplate->NetworkDataDir();
        this->genesis = param_netTemplate->GenesisBlock();
        this->fMiningRequiresPeers = param_netTemplate->MiningRequiresPeers();
        this->fDefaultConsistencyChecks = param_netTemplate->DefaultConsistencyChecks();
        this->fRequireStandard = param_netTemplate->RequireStandard();
        this->fMineBlocksOnDemand = param_netTemplate->MineBlocksOnDemand();
        this->fTestnetToBeDeprecatedFieldRPC = param_netTemplate->TestnetToBeDeprecatedFieldRPC();
        this->checkpointData = param_netTemplate->Checkpoints();
        this->nStakeMaxAge = param_netTemplate->getStakeMaxAge();
        this->nStakeMinAge = param_netTemplate->getStakeMinAge();
    }
};

#endif // BITCOIN_CHAINPARAMS_H
