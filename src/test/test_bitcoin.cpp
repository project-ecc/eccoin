// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bitcoin Test Suite

#include "test_bitcoin.h"


#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "fs.h"
#include "init.h"
#include "key.h"
#include "main.h"
#include "messages.h"
#include "miner.h"
#include "processblock.h"
#include "pubkey.h"
#include "random.h"
#include "rpc/rpcserver.h"
#include "test/testutil.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include <boost/program_options.hpp>
#include <boost/test/unit_test.hpp>

#include <memory>

#include <boost/thread.hpp>

extern bool fPrintToConsole;
extern void noui_connect();
CWallet *pwallet = nullptr;


BasicTestingSetup::BasicTestingSetup(const std::string &chainName)
{
    ECC_Start();
    SetupEnvironment();
    SetupNetworking();
    fPrintToDebugLog = false; // don't want to write to debug.log file
    fCheckBlockIndex = true;
    pnetMan = new CNetworkManager();
    pwallet = new CWallet("walletFile");
    pnetMan->SetParams(chainName);
    noui_connect();
}

BasicTestingSetup::~BasicTestingSetup() { ECC_Stop(); }
TestingSetup::TestingSetup(const std::string &chainName) : BasicTestingSetup(chainName)
{
    // Ideally we'd move all the RPC tests to the functional testing framework
    // instead of unit tests, but for now we need these here.
    const CNetworkTemplate &chainparams = pnetMan->getActivePaymentNetwork();
    // RegisterAllCoreRPCCommands(tableRPC);
    ClearDatadirCache();
    pathTemp = GetTempPathTest() / strprintf("test_bitcoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
    fs::create_directories(pathTemp);
    pnetMan->getChainActive()->pblocktree.reset(new CBlockTreeDB(1 << 20, true));
    pcoinsdbview = new CCoinsViewDB(1 << 23, true);
    pnetMan->getChainActive()->pcoinsTip.reset(new CCoinsViewCache(pcoinsdbview));
    bool worked = pnetMan->getChainActive()->InitBlockIndex(chainparams);
    assert(worked);
    RegisterNodeSignals(GetNodeSignals());
}

TestingSetup::~TestingSetup()
{
    UnregisterNodeSignals(GetNodeSignals());
    threadGroup.interrupt_all();
    threadGroup.join_all();
    pnetMan->getChainActive()->UnloadBlockIndex();
    pnetMan->getChainActive()->pcoinsTip.reset();
    pcoinsdbview = nullptr;
    pnetMan->getChainActive()->pblocktree.reset();
    fs::remove_all(pathTemp);
}

TestChain100Setup::TestChain100Setup() : TestingSetup("TESTNET0-TEMPORARY")
{
    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < COINBASE_MATURITY; i++)
    {
        std::vector<CTransactionRef> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        coinbaseTxns.push_back(b.vtx[0]);
    }
}

//
// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
//
CBlock TestChain100Setup::CreateAndProcessBlock(const std::vector<CTransactionRef> &txns, const CScript &scriptPubKey)
{
    std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(pwallet, false));
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    *pblock = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    pblock->vtx.resize(1);
    BOOST_FOREACH (const CTransactionRef &tx, txns)
        pblock->vtx.push_back(tx);
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(pblock.get(), pnetMan->getChainActive()->chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, pnetMan->getActivePaymentNetwork()->GetConsensus()))
        ++pblock->nNonce;

    CValidationState state;
    ProcessNewBlock(state, pnetMan->getActivePaymentNetwork(), NULL, pblock, true, NULL);

    CBlock result = *pblock;
    pblocktemplate.reset();
    return result;
}

TestChain100Setup::~TestChain100Setup() {}
CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(CTransaction &tx, CTxMemPool *pool)
{
    CTransaction txn(tx);
    bool hasNoDependencies = pool ? pool->HasNoInputsOf(tx) : hadNoDependencies;
    // Hack to assume either its completely dependent on other mempool txs or not at all
    CAmount inChainValue = hasNoDependencies ? txn.GetValueOut() : 0;

    return CTxMemPoolEntry(MakeTransactionRef(std::move(txn)), nFee, nTime, dPriority, nHeight, hasNoDependencies,
        inChainValue, spendsCoinbase, sigOpCount, lp);
}

void ShutdownTest(void *parg) { exit(0); }
void StartShutdownTest() { exit(0); }
bool ShutdownRequestedTest() { return false; }
using namespace boost::program_options;

struct StartupShutdown
{
    void StartupShutdownTest()
    {
        options_description optDef("Options");
        optDef.add_options()("testhelp", "program options information")(
            "log_level", "set boost logging (all, test_suite, message, warning, error, ...)")(
            "log_bitcoin", value<std::string>()->required(), "bitcoin logging destination (console, none)");
        variables_map opts;
        store(parse_command_line(boost::unit_test::framework::master_test_suite().argc,
                  boost::unit_test::framework::master_test_suite().argv, optDef),
            opts);

        if (opts.count("testhelp"))
        {
            std::cout << optDef << std::endl;
            exit(0);
        }

        if (opts.count("log_bitcoin"))
        {
            std::string s = opts["log_bitcoin"].as<std::string>();
            if (s == "console")
            {
                fPrintToConsole = true;
                fPrintToDebugLog = false;
            }
            else if (s == "none")
            {
                fPrintToConsole = false;
                fPrintToDebugLog = false;
            }
        }
    }
    // ~StartupShutdownTest() { }
};

BOOST_GLOBAL_FIXTURE(StartupShutdown);
