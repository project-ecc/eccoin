// This file is part of the Eccoin project
// Copyright (c) 2017-2018 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "args.h"
#include "consensus/merkle.h"
#include "tinyformat.h"
#include "util/util.h"

#include <assert.h>

extern CChainParams chainparams;

const CChainParams &Params()
{
    return chainparams;
}

void AppendParamsHelpMessages(std::string &strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup("Chain selection options:");
    strUsage += HelpMessageOpt("-testnet", "Use the test chain");
    if (debugHelp)
    {
        strUsage += HelpMessageOpt("-regtest",
            "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
            "This is intended for regression testing tools and app development.");
    }
}

class CLegacyNetwork : public CChainParams
{
public:
    CLegacyNetwork()
    {
        strNetworkID = "LEGACY";
        strNetworkDataDir = "";
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 30 * 45;
        consensus.nTargetSpacing = 45;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xdb;
        pchMessageStart[3] = 0xfa;
        nDefaultPort = 19118;
        nRPCPort = 19119;
        nMaxTipAge = 24 * 60 * 60;
        nStakeMaxAge = 60 * 60 * 24 * 84; // 84 days
        nStakeMinAge = 60 * 60 * 2; // 2 hours

        const char *pszTimestamp =
            "AP | Mar 2, 2014, 10.35 AM IST: China blames Uighur separatists for knife attack; 33 dead";
        CTransaction txNew;
        txNew.nTime = 1393744287;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999)
                                           << std::vector<unsigned char>((const unsigned char *)pszTimestamp,
                                                  (const unsigned char *)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();

        genesis.vtx.push_back(MakeTransactionRef(txNew));
        genesis.hashPrevBlock.SetNull();
        genesis.nVersion = 1;
        genesis.nTime = 1393744307;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 12799721;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4db82fe8b45f3dae2b7c7b8be5ec4c37e72e25eaf989b9db24ce1d0fd37eed8b"));

        vSeeds.push_back(CDNSSeedData("ECC-Seed1", "eccserver1.ddns.net", true));
        vSeeds.push_back(CDNSSeedData("ECC-Seed2", "eccnode.altj.com", true));
        vSeeds.push_back(CDNSSeedData("ECC-Seed3", "5.189.131.197", true));
        vSeeds.push_back(CDNSSeedData("ECC-Seed4", "185.21.216.160", true));

        base58Prefixes[CChainParams::PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 33);
        base58Prefixes[CChainParams::SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 8);
        base58Prefixes[CChainParams::SECRET_KEY] = std::vector<unsigned char>(1, 161);
        base58Prefixes[CChainParams::EXT_PUBLIC_KEY] = {(0x04),(0x88),(0xB2),(0x1E)};
        base58Prefixes[CChainParams::EXT_SECRET_KEY] = {(0x04),(0x88),(0xAD),(0xE4)};

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        mapCheckpoints =
        {
            {0,       uint256S("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1")},
            {1,       uint256S("0x00000762d19a3a38458e73de6c937fd483f17bd75f55d7fe4e95713f51d6b816")},
            {2,       uint256S("0x00000ea50ea0cae64779ff4bb4a0ee94841e2ee20642641a062cbdd342e0a3c5")},
            {3,       uint256S("0x00000513cc6f4bec8d7e7bd0ded854200b6c784c8c830a3e4fd0cccc2cb9e58c")},
            {1000,    uint256S("0x000000000df3f7a5f719c247782d7a43d75186ebc043341e2668320f9d940bcd")},
            {10000,   uint256S("0x00000000076d45a9579c879d46354dd81eeba7060a9a065e13c9dd1c28f474d1")},
            {23920,   uint256S("0x000000000331540c766c4ac667a6fbc65ff93f5a30fbb0c6822986885b1b56c0")},
            {36918,   uint256S("0x0000000001353725582b099cdd3c89933bbd08a17ace464fba935ecfc41572ef")},
            {50000,   uint256S("0x0000000001c770384cd12a74eb5456358425fc6a94a250c3466aaa2ca7460131")},
            {86401,   uint256S("0x51bb1ac3ffd009c12791b9d4320dec0ba69e15c8b6d03d17889b0c09fb5b05a4")},
            {86402,   uint256S("0xa9f3141e571231e02b4fb649370af6173e1a80a9e0d21aa8859bd17ce1260a05")},
            {86403,   uint256S("0xf6c11aadca44fce2390107e229d4d0d70f7cf64266b959672711c68e0f411af5")},
            {86759,   uint256S("0x5c6ed2e23ccc27d59a0659a9a32a4c0ca97d829249277c6a35918f4ec94b1748")},
            {86761,   uint256S("0xca305a45c9f8a89c050f004d0438b38f190fe6bfe51128f0c3e864ddcf2c765c")},
            {86901,   uint256S("0xe769d38b7e140267b688f9d9cc6b58d38185427facb6a1aa719db60a0d54f3f7")},
            {87000,   uint256S("0xbb069ba59aa5a6acc68413ef7c2d0c009b061daf160edf958738d197a059f11d")},
            {87101,   uint256S("0x1ffbfd2a70e626d5f848775851e6f89bee6f2225ed78131b16f9547449d2e2ee")},
            {96500,   uint256S("0x13f0755045a3ae90d33c4bcf6ba1581025fc6e0caf46f7624063cb59dcc3d27c")},
            {100000,  uint256S("0x28a483386650a188c3346fd5e329e2c8cc137cf3557547e8525f5cdea601501a")},
            {136500,  uint256S("0x7e4ec82a165762e8a324038ef1cdd0b83e603f4737ae6f9e5967b13b8b6ace5c")},
            {150000,  uint256S("0xfee6d00910e8d0aa2f0ca8a447b4de366a12f9df2521f77c5a97a5ae0af8834e")},
            {185000,  uint256S("0xce904504a0df58944c6a633b739abcec3bbb256b510a616b465c24525d564828")},
            {197712,  uint256S("0x7576d0f370b1efdce01075a9491fb8d2f98af485f78d170196270f1eb156ee40")},
            {200000,  uint256S("0x1f1ea51aee8a7456655e31857c7cd4a9f494556438485abd4c60d86cacf24b44")},
            {205000,  uint256S("0x9e4528bc818bb1ee2cdf44ba7805e88b4fc85bbf496516f35d4d642c6812503e")},
            {209762,  uint256S("0x49448f382f9ec8f126542244573e7349c7b07db0cbdc2ab8326942cbfff603b3")},
            {209786,  uint256S("0x28558eedf7f5c049e9f2ea61da270fffc5b50310aafb29c7595840784e8b1d61")},
            {215650,  uint256S("0xd7fb37df6be4bf2c5c9ea47ba4a14f9af35c326cd225122b03f61b74d1283d09")},
            {215690,  uint256S("0x8af4d5450c238460a4775b19c94872eaf5664657f702bef53576bc9f77af319d")},
            {220504,  uint256S("0x5781d160a46a6631a21e62a9a67932d0f9b8636c8f5241973b076db3854de405")},
            {221000,  uint256S("0x51cd22cde58a3738e851f155a282b4624d3e18e84fbcb02de5006029dec8f7e3")},
            {233855,  uint256S("0x77c1312f0b4ba0fc34cb7a0f3472012739bbd22c317add69edaa4908e83b00eb")},
            {236850,  uint256S("0x139203f72c943433880c4f8d3581a4cb7ee0877f341639cd4c7810edc7fc7d80")},
            {237000,  uint256S("0x70fdb4f39e571afff137c7bd40c4df98ccab32cec1d305074bac9fca30754bc0")},
            {241130,  uint256S("0xdd900777cb9e2ea2cae0bf410ce2f2484a415c7bf7af59d9492868195583e3b2")},
            {242150,  uint256S("0xba96de8da95ac53cedc7fd0cd3c17b32f5d3a04f33a544060606c095b28bf4c1")},
            {300000,  uint256S("0x2c654dfa9f1ab51a64509910b1f053fc20d572022480814988c36f042cb3010b")},
            {350000,  uint256S("0xfdb1df53f4365d494d9fa54247a533cbfcd9b6992491f40c8ccfeed454932a70")},
            {400000,  uint256S("0xc04d360938d5ff66294100a10424f7e284abe76d117f28460e16752edeb03444")},
            {435000,  uint256S("0x801a211aa479129e42554bc812d624e585e1b0dd608e23b1a7f87a9d14e7fdec")},
            {450000,  uint256S("0x53e21a2574ff6acc0f31640c4058554dde2fe8972ec72867403e8b88e9ba1bc6")},
            {500000,  uint256S("0x779f22407cf9fa0adb8a361918ccf249ef913070ce368070c1ac5063005e3e3c")},
            {550000,  uint256S("0xf340b738c21c0a9b6b2eff0f40d9ab3fca9830d8597131680cd5a2615594cfb0")},
            {600000,  uint256S("0x589fc3d25c15caaa468dc8b4249e1cbb6ea18368897bd3b1d80f1404486e3783")},
            {650000,  uint256S("0xc28634f7211ff0582dfe8df1849711a9bd7815005e59dff0059a20876c465f51")},
            {675000,  uint256S("0xe1aca23bd72ad9d153767272f43d33a0542d2a61a78e281341d0f12cd0521024")},
            {675500,  uint256S("0x26ccdf8bcb1a50ecef8f507de74ff030789aa1b52491fc4a4de4e4679d53a398")},
            {687345,  uint256S("0xae2e43c35a3346fa798a0a356ca7a4bce57885ee64e4319295f7f3b7210944f1")},
            {700000,  uint256S("0x0ab361e8acd391c6b5e726eb4704dd8d60e2e3b3f8856e2f7d6373c9a3e0da36")},
            {702950,  uint256S("0x26d2cd7b13f1aaa34ffc379696d0e5b14c2ddf8ef2c2c78348fec23f8b55e8ff")},
            {1030250, uint256S("0x434ee5c39b6ba186d66cbfaaa8004910b3556726f990b9f33bb48b9fc280c5de")},
            {1491250, uint256S("0x45a01a2b45ca91433c8c12378914463bd13afc410b27eeb18855d5b060d7e270")},
            {1492500, uint256S("0xd4185d9ae0c38211ac6e0ceddcca4207a00fc59d11b087e76c9bf6d4081856c8")},
            {1493040, uint256S("0xcd266ca5eaca1f561d3adf5ab0bc4994ea26418dd12d9072d5c5194639c40ac2")}
        };
    }
};
static CLegacyNetwork static_CLegacyNetwork;

class CTestnet0Network : public CChainParams
{
public:
    CTestnet0Network()
    {
        strNetworkID = "TESTNET0";
        strNetworkDataDir = "testnet0";
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 30 * 45;
        consensus.nTargetSpacing = 45;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xee;
        pchMessageStart[1] = 0xff;
        pchMessageStart[2] = 0xaa;
        pchMessageStart[3] = 0xbb;
        nDefaultPort = 30000;
        nRPCPort = 30001;
        nMaxTipAge = 24 * 60 * 60;
        nStakeMaxAge = 60 * 60 * 24 * 84; // 84 days
        nStakeMinAge = 60 * 2; // 2 minutes

        const char *pszTimestamp = "AP | Sep 12, 2018, Testing0 begins";
        CTransaction txNew;
        txNew.nTime = 1536781520;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999)
                                           << std::vector<unsigned char>((const unsigned char *)pszTimestamp,
                                                  (const unsigned char *)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();

        genesis.vtx.push_back(MakeTransactionRef(txNew));
        genesis.hashPrevBlock.SetNull();
        genesis.nVersion = 1;
        genesis.nTime = 1536781520;
        genesis.nBits = 0x1e0fffff;
        genesis.nNonce = 12799721;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0xcdf2b68d2fc9afdf991df5e321f59198189926ee757bf5efcf5c8c1a07b7c90e"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x68d635c49ffdd2bf5edf78149d0e2ea7dff97901d4596e865b87919853085311"));

        base58Prefixes[CChainParams::PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 51);
        base58Prefixes[CChainParams::SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 15);
        base58Prefixes[CChainParams::SECRET_KEY] = std::vector<unsigned char>(1, 159);
        base58Prefixes[CChainParams::EXT_PUBLIC_KEY] = {(0x04),(0x88),(0xB2),(0x1E)};
        base58Prefixes[CChainParams::EXT_SECRET_KEY] = {(0x04),(0x88),(0xAD),(0xE4)};

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        mapCheckpoints =
        {
            {0, uint256S("0xcdf2b68d2fc9afdf991df5e321f59198189926ee757bf5efcf5c8c1a07b7c90e")}
        };
    }
};
static CTestnet0Network static_CTestnet0Network;

class CRegtestNetwork : public CChainParams
{
public:
    CRegtestNetwork()
    {
        strNetworkID = "REGTEST";
        strNetworkDataDir = "regtest";
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 30 * 45;
        consensus.nTargetSpacing = 45;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;
        // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xcc;
        pchMessageStart[3] = 0xdd;
        nDefaultPort = 40000;
        nRPCPort = 40001;
        nMaxTipAge = 24 * 60 * 60;
        nStakeMaxAge = 1;
        nStakeMinAge = 1;

        const char *pszTimestamp = "AP | Sep 12, 2018, Regtest implemented";
        CTransaction txNew;
        txNew.nTime = 1536781520;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999)
                                           << std::vector<unsigned char>((const unsigned char *)pszTimestamp,
                                                  (const unsigned char *)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();

        genesis.vtx.push_back(MakeTransactionRef(txNew));
        genesis.hashPrevBlock.SetNull();
        genesis.nVersion = 1;
        genesis.nTime = 1536781520;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 12799721;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x296d58ef241b0dde2372fbc7b09ec4aacf7b4dad88561f02469f3f4695c4fbb1"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x3565e20605dbdfe7a63ec4b9f5b9d2d25b69fcc13d6bfd7cc42615fcd41a323c"));

        base58Prefixes[CChainParams::PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 51);
        base58Prefixes[CChainParams::SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 15);
        base58Prefixes[CChainParams::SECRET_KEY] = std::vector<unsigned char>(1, 159);
        base58Prefixes[CChainParams::EXT_PUBLIC_KEY] = {(0x04),(0x88),(0xB2),(0x1E)};
        base58Prefixes[CChainParams::EXT_SECRET_KEY] = {(0x04),(0x88),(0xAD),(0xE4)};

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        mapCheckpoints =
        {
            {0, uint256S("0x296d58ef241b0dde2372fbc7b09ec4aacf7b4dad88561f02469f3f4695c4fbb1")}
        };
    }
};
static CRegtestNetwork static_CRegtestNetwork;

std::string ChainNameFromCommandLine()
{
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);
    bool fTestNet = gArgs.GetBoolArg("-testnet0", false);

    if (fTestNet && fRegTest)
    {
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    }
    if (fTestNet)
    {
        return "TESTNET0";
    }
    if (fRegTest)
    {
        return "REGTEST";
    }
    return "LEGACY";
}

int RPCPortFromCommandLine()
{
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);
    bool fTestNet = gArgs.GetBoolArg("-testnet0", false);

    if (fTestNet && fRegTest)
    {
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    }
    if (fTestNet)
    {
        return 30001;
    }
    if (fRegTest)
    {
        return 40001;
    }
    return 19119;
}

void CheckAndSetParams(const std::string &network)
{
    if (network == "LEGACY")
    {
        chainparams = static_CLegacyNetwork;
    }
    else if (network == "TESTNET0")
    {
        chainparams = static_CTestnet0Network;
    }
    else if (network == "REGTEST")
    {
        chainparams = static_CRegtestNetwork;
    }
    else
    {
        throw std::runtime_error(strprintf("%s: Unknown network %s.", __func__, network));
    }
    return;
}
