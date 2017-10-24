// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netman.h"
#include "legacy.h"
#include "tinyformat.h"
#include "util/util.h"
#include "args.h"


#include <assert.h>

const std::string CNetMan::LEGACY = "main";
const std::string CNetMan::TESTNET = "test";
const std::string CNetMan::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

static CLegacyParams legacyParams;

/**
 * Main network
 */
class CBaseMainParams : public CNetMan
{
public:
    CBaseMainParams()
    {
        nRPCPort = 8332;
    }
};
static CBaseMainParams mainParams;

/**
 * Testnet (v3)
 */
class CBaseTestNetParams : public CNetMan
{
public:
    CBaseTestNetParams()
    {
        nRPCPort = 18332;
        strDataDir = "testnet3";
    }
};
static CBaseTestNetParams testNetParams;

/*m
 * Regression test
 */
class CBaseRegTestParams : public CNetMan
{
public:
    CBaseRegTestParams()
    {
        nRPCPort = 18332;
        strDataDir = "regtest";
    }
};
static CBaseRegTestParams regTestParams;

static CNetMan* pCurrentBaseParams = 0;

const CNetMan& BaseParams()
{
    assert(pCurrentBaseParams);
    return *pCurrentBaseParams;
}

CNetMan& BaseParams(const std::string& chain)
{
    if (chain == CNetMan::LEGACY)
        return mainParams;
    else if (chain == CNetMan::TESTNET)
        return testNetParams;
    else if (chain == CNetMan::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    pCurrentBaseParams = &BaseParams(chain);
}

std::string ChainNameFromCommandLine()
{
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);
    bool fTestNet = gArgs.GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (fRegTest)
        return CNetMan::REGTEST;
    if (fTestNet)
        return CNetMan::TESTNET;
    return CNetMan::LEGACY;
}

bool AreBaseParamsConfigured()
{
    return pCurrentBaseParams != NULL;
}

static CBaseParams *pCurrentParams = 0;

const CBaseParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CBaseParams& Params(const std::string& chain)
{
    if (chain == CNetMan::LEGACY)
            return legacyParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
