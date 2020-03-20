// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"

#include "amount.h"
#include "args.h"
#include "beta.h"
#include "blockgeneration/blockgeneration.h"
#include "blockstorage/blockstorage.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "compat/sanity.h"
#include "consensus/validation.h"
#include "httprpc.h"
#include "httpserver.h"
#include "key.h"
#include "main.h"
#include "net/addrman.h"
#include "net/messages.h"
#include "net/net.h"
#include "networks/netman.h"
#include "networks/networktemplate.h"
#include "policy/policy.h"
#include "processblock.h"
#include "rpc/rpcserver.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "torcontrol.h"
#include "txdb.h"
#include "txmempool.h"
#include "util/util.h"
#include "util/utilmoneystr.h"
#include "util/utilstrencodings.h"
#include "validationinterface.h"
#include "verifydb.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef WIN32
#include <signal.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

#include <openssl/crypto.h>

#if ENABLE_ZMQ
#include <zmq/zmqnotificationinterface.h>
#endif

extern std::unique_ptr<PeerLogicValidation> peerLogic;

bool fFeeEstimatesInitialized = false;
static const bool DEFAULT_PROXYRANDOMIZE = true;
static const bool DEFAULT_DISABLE_SAFEMODE = false;
static const bool DEFAULT_STOPAFTERBLOCKIMPORT = false;

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

/** Used to pass flags to the Bind() function */
enum BindFlags
{
    BF_NONE = 0,
    BF_EXPLICIT = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST = (1U << 2),
};

static const char *FEE_ESTIMATES_FILENAME = "fee_estimates.dat";

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets shutdown_threads, which triggers
// the DetectShutdownThread(), which interrupts the main thread group.
// DetectShutdownThread() then exits, which causes AppInit() to
// continue (it .joins the shutdown thread).
// Shutdown() is then
// called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Note that if running -daemon the parent process returns from AppInit2
// before adding any threads to the threadGroup, so .join_all() returns
// immediately and the parent exits from main().
//
//


std::atomic<bool> shutdown_threads(false);

void StartShutdown()
{
    // use one atomic bool for shutdowns
    shutdown_threads.store(true);
}
bool ShutdownRequested()
{
    // use one atomic bool for shutdowns
    return shutdown_threads.load();
}

class CCoinsViewErrorCatcher final : public CCoinsViewBacked
{
public:
    CCoinsViewErrorCatcher(CCoinsView *view) : CCoinsViewBacked(view) {}
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override
    {
        try
        {
            return CCoinsViewBacked::GetCoin(outpoint, coin);
        }
        catch (const std::runtime_error &e)
        {
            LogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller.
};

std::unique_ptr<CCoinsViewDB> pcoinsdbview;
std::unique_ptr<CCoinsViewErrorCatcher> pcoinscatcher;
static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle;

void Interrupt(thread_group &threadGroup)
{
    threadGroup.interrupt_all();
    g_connman->Interrupt();
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptTorControl();
    InterruptScriptCheck();
}

void Shutdown(thread_group &threadGroup)
{
    GetMainSignals().SystemMessage("SHUTDOWN: INITIATED");
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
    {
        return;
    }
    // we should have already interrupted but there is no harm in doing it again
    threadGroup.interrupt_all();
    threadGroup.join_all();

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("bitcoin-shutoff");
    mempool.AddTransactionsUpdated(1);

    {
        LOCK(cs_main);
        if (pcoinsTip != nullptr)
        {
            // Flush state and clear cache completely to release as much memory as possible before continuing.
            FlushStateToDisk();
            pcoinsTip->Clear();
        }
    }

    StopHTTPRPC();
    StopRPC();
    StopHTTPServer();

    if (pwalletMain)
        pwalletMain->Flush(false);

    // shut off pos miner
    ThreadGeneration(pwalletMain, true, true);
    // shut off pow miner
    ThreadGeneration(pwalletMain, true, false);

    MapPort(false);
    UnregisterValidationInterface(peerLogic.get());
    peerLogic.reset();

    g_connman.reset();

    StopTorControl();

    UnregisterNodeSignals(GetNodeSignals());

    if (fFeeEstimatesInitialized)
    {
        fs::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            mempool.WriteFeeEstimates(est_fileout);
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    {
        LOCK(cs_main);
        if (pcoinsTip != nullptr)
        {
            FlushStateToDisk();
        }
        pcoinsTip.reset();
        pcoinsTip = nullptr;
        pcoinscatcher.reset();
        pcoinscatcher = nullptr;
        pcoinsdbview.reset();
        pcoinsdbview = nullptr;
        pblocktree.reset();
        pblocktree = nullptr;
    }

    if (pwalletMain)
    {
        pwalletMain->Flush(true);
    }

#if ENABLE_ZMQ
    if (g_zmq_notification_interface)
    {
        UnregisterValidationInterface(g_zmq_notification_interface);
        delete g_zmq_notification_interface;
        g_zmq_notification_interface = NULL;
    }
#endif

#ifndef WIN32
    try
    {
        fs::remove(GetPidFile());
    }
    catch (const fs::filesystem_error &e)
    {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces();

    delete pwalletMain;
    pwalletMain = nullptr;
    globalVerifyHandle.reset();
    ECC_Stop();
    LogPrintf("%s: done\n", __func__);
    g_logger.reset();
    g_logger = nullptr;
}

/**
 * Signal handlers are very limited in what they are allowed to do, so:
 */
void HandleSIGTERM(int) { shutdown_threads.store(true); }
void HandleSIGHUP(int) { fReopenDebugLog = true; }
bool static InitError(const std::string &str)
{
    LogPrintf("InitError: %s\n", str.c_str());
    return false;
}

bool static InitWarning(const std::string &str)
{
    LogPrintf("InitWarning: %s\n", str.c_str());
    return true;
}

bool static Bind(CConnman &connman, const CService &addr, unsigned int flags)
{
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!connman.BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0))
    {
        if (flags & BF_REPORT_ERROR)
            return InitError(strError);
        return false;
    }
    return true;
}

void OnRPCStopped()
{
    cvBlockChange.notify_all();
    LogPrint("rpc", "RPC stopped.\n");
}

void OnRPCPreCommand(const CRPCCommand &cmd)
{
    // Observe safe mode
    std::string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !gArgs.GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) && !cmd.okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, std::string("Safe mode: ") + strWarning);
}

std::string HelpMessage()
{
    const bool showDebug = gArgs.GetBoolArg("-help-debug", false);

    // When adding new options to the categories, please keep and ensure alphabetical ordering.
    // Do not translate _(...) -help-debug options, Many technical terms, and only a very small audience, so is
    // unnecessary stress to translators.
    std::string strUsage = HelpMessageGroup(("Options:"));
    strUsage += HelpMessageOpt("-?", ("This help message"));
    strUsage += HelpMessageOpt("-version", ("Print version and exit"));
    strUsage += HelpMessageOpt(
        "-blocknotify=<cmd>", ("Execute command when the best block changes (%s in cmd is replaced by block hash)"));
    strUsage += HelpMessageOpt("-checkblocks=<n>",
        strprintf(("How many blocks to check at startup (default: %u, 0 = all)"), DEFAULT_CHECKBLOCKS));
    strUsage += HelpMessageOpt("-checklevel=<n>",
        strprintf(("How thorough the block verification of -checkblocks is (0-4, default: %u)"), DEFAULT_CHECKLEVEL));
    strUsage += HelpMessageOpt("-conf=<file>", strprintf(("Specify configuration file (default: %s)"), CONF_FILENAME));
    strUsage += HelpMessageOpt("-returnchange",
        strprintf(("Specify if change is returned to same address (default: %u)"), DEFAULT_RETURN_CHANGE));
    {
#ifndef WIN32
        strUsage += HelpMessageOpt("-daemon", ("Run in the background as a daemon and accept commands"));
#endif
    }
    strUsage += HelpMessageOpt("-datadir=<dir>", ("Specify data directory"));
    strUsage +=
        HelpMessageOpt("-dbcache=<n>", strprintf(("Set database cache size in megabytes (%d to %d, default: %d)"),
                                           nMinDbCache, nMaxDbCache, nDefaultDbCache));
    strUsage += HelpMessageOpt("-loadblock=<file>", ("Imports blocks from external blk000??.dat file on startup"));
    strUsage += HelpMessageOpt(
        "-maxorphantx=<n>", strprintf(("Keep at most <n> unconnectable transactions in memory (default: %u)"),
                                DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-maxmempool=<n>",
        strprintf(("Keep the transaction memory pool below <n> megabytes (default: %u)"), DEFAULT_MAX_MEMPOOL_SIZE));
    strUsage += HelpMessageOpt(
        "-mempoolexpiry=<n>", strprintf(("Do not keep transactions in the mempool longer than <n> hours (default: %u)"),
                                  DEFAULT_MEMPOOL_EXPIRY));
    strUsage += HelpMessageOpt("-par=<n>", strprintf(("Set the number of script verification threads (%u to %d, 0 = "
                                                      "auto, <0 = leave that many cores free, default: %d)"),
                                               -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-pid=<file>", strprintf(("Specify pid file (default: %s)"), PID_FILENAME));
#endif
    strUsage += HelpMessageOpt("-reindex", ("Rebuild block chain index from current blk000??.dat files on startup"));

    strUsage += HelpMessageGroup(("Connection options:"));
    strUsage += HelpMessageOpt("-addnode=<ip>", ("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-banscore=<n>",
        strprintf(("Threshold for disconnecting misbehaving peers (default: %u)"), DEFAULT_BANSCORE_THRESHOLD));
    strUsage += HelpMessageOpt(
        "-bantime=<n>", strprintf(("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"),
                            DEFAULT_MISBEHAVING_BANTIME));
    strUsage += HelpMessageOpt(
        "-bind=<addr>", ("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-connect=<ip>", ("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt(
        "-discover", ("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-dns",
        "Allow DNS lookups for -addnode, -seednode and -connect " + strprintf("(default: %u)", DEFAULT_NAME_LOOKUP));
    strUsage += HelpMessageOpt(
        "-dnsseed", ("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)"));
    strUsage += HelpMessageOpt("-externalip=<ip>", ("Specify your own public address"));
    strUsage += HelpMessageOpt("-forcednsseed",
        strprintf(("Always query for peer addresses via DNS lookup (default: %u)"), DEFAULT_FORCEDNSSEED));
    strUsage += HelpMessageOpt("-listen", ("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    strUsage += HelpMessageOpt(
        "-listenonion", strprintf(("Automatically create Tor hidden service (default: %d)"), DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-maxconnections=<n>",
        strprintf(("Maintain at most <n> connections to peers (default: %u)"), DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-maxreceivebuffer=<n>",
        strprintf(("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"), DEFAULT_MAXRECEIVEBUFFER));
    strUsage += HelpMessageOpt("-maxsendbuffer=<n>",
        strprintf(("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"), DEFAULT_MAXSENDBUFFER));
    strUsage += HelpMessageOpt("-onion=<ip:port>",
        strprintf(("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-proxy"));
    strUsage += HelpMessageOpt("-onlynet=<net>", ("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt(
        "-permitbaremultisig", strprintf(("Relay non-P2SH multisig (default: %u)"), DEFAULT_PERMIT_BAREMULTISIG));
    strUsage += HelpMessageOpt("-peerbloomfilters",
        strprintf(("Support filtering of blocks and transaction with bloom filters (default: %u)"), 1));
    strUsage += HelpMessageOpt("-port=<port>", strprintf(("Listen for connections on <port> (default: %u)"),
                                                   pnetMan->getActivePaymentNetwork()->GetDefaultPort()));
    strUsage += HelpMessageOpt("-proxy=<ip:port>", ("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-proxyrandomize",
        strprintf(("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"),
                                   DEFAULT_PROXYRANDOMIZE));
    strUsage += HelpMessageOpt("-seednode=<ip>", ("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-timeout=<n>",
        strprintf(("Specify connection timeout in milliseconds (minimum: 1, default: %d)"), DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-torcontrol=<ip>:<port>",
        strprintf(("Tor control port to use if onion listening enabled (default: %s)"), DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-torpassword=<pass>", ("Tor control port password (default: empty)"));
#ifdef USE_UPNP
#if USE_UPNP
    strUsage +=
        HelpMessageOpt("-upnp", ("Use UPnP to map the listening port (default: 1 when listening and no -proxy)"));
#else
    strUsage += HelpMessageOpt("-upnp", strprintf(("Use UPnP to map the listening port (default: %u)"), 0));
#endif
#endif
    strUsage += HelpMessageOpt("-whitebind=<addr>",
        ("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-whitelist=<netmask>",
        "Whitelist peers connecting from the given netmask or IP address. Can be specified multiple times. "
        "Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are "
        "already in the mempool, useful e.g. for a gateway");
    strUsage +=
        HelpMessageOpt("-whitelistrelay", strprintf(("Accept relayed transactions received from whitelisted peers "
                                                     "even when not relaying transactions (default: %d)"),
                                              DEFAULT_WHITELISTRELAY));
    strUsage += HelpMessageOpt(
        "-whitelistforcerelay",
        strprintf(
            ("Force relay of transactions from whitelisted peers even they violate local relay policy (default: %d)"),
            DEFAULT_WHITELISTFORCERELAY));
    strUsage += HelpMessageOpt(
        "-maxuploadtarget=<n>",
        strprintf(
            ("Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit (default: %d)"),
            DEFAULT_MAX_UPLOAD_TARGET));


    strUsage += HelpMessageGroup(("Wallet options:"));
    strUsage += HelpMessageOpt(
        "-allownewkeys", strprintf(("Allow the wallet to generate new keys if the keypool runs out <n> (default: %u)"),
                             DEFAULT_ALLOW_KEYPOOL_REFILLS));
    strUsage +=
        HelpMessageOpt("-keypool=<n>", strprintf(("Set key pool size to <n> (default: %u)"), DEFAULT_KEYPOOL_SIZE));
    strUsage += HelpMessageOpt("-fallbackfee=<amt>",
        strprintf(("A fee rate (in %s/kB) that will be used when fee estimation has insufficient data (default: %s)"),
                                   CURRENCY_UNIT, FormatMoney(DEFAULT_FALLBACK_FEE)));
    strUsage += HelpMessageOpt("-mintxfee=<amt>",
        strprintf(("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)"),
                                   CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MINFEE)));
    strUsage +=
        HelpMessageOpt("-paytxfee=<amt>", strprintf(("Fee (in %s/kB) to add to transactions you send (default: %s)"),
                                              CURRENCY_UNIT, FormatMoney(payTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-rescan", ("Rescan the block chain for missing wallet transactions on startup"));
    strUsage +=
        HelpMessageOpt("-salvagewallet", ("Attempt to recover private keys from a corrupt wallet.dat on startup"));
    strUsage += HelpMessageOpt(
        "-sendfreetransactions", strprintf(("Send transactions as zero-fee transactions if possible (default: %u)"),
                                     DEFAULT_SEND_FREE_TRANSACTIONS));
    strUsage += HelpMessageOpt("-spendzeroconfchange",
        strprintf(("Spend unconfirmed change when sending transactions (default: %u)"), DEFAULT_SPEND_ZEROCONF_CHANGE));
    strUsage += HelpMessageOpt(
        "-txconfirmtarget=<n>", strprintf(("If paytxfee is not set, include enough fee so transactions begin "
                                           "confirmation on average within n blocks (default: %u)"),
                                    DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt(
        "-maxtxfee=<amt>", strprintf(("Maximum total fees (in %s) to use in a single wallet transaction; setting this "
                                      "too low may abort large transactions (default: %s)"),
                               CURRENCY_UNIT, FormatMoney(DEFAULT_TRANSACTION_MAXFEE)));
    strUsage += HelpMessageOpt("-upgradewallet", ("Upgrade wallet to latest format on startup"));
    strUsage += HelpMessageOpt("-wallet=<file>", "Specify wallet file (within data directory) (default: wallet.dat)");
    strUsage += HelpMessageOpt("-walletbroadcast",
        "Make the wallet broadcast transactions " + strprintf("(default: %u)", DEFAULT_WALLETBROADCAST));
    strUsage += HelpMessageOpt(
        "-walletnotify=<cmd>", ("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-zapwallettxes=<mode>",
        "Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup "
        "(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)");

    strUsage += HelpMessageGroup(("Debugging/Testing options:"));
    strUsage += HelpMessageOpt("-uacomment=<cmt>", ("Append comment to the user agent string"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-checkblockindex",
            strprintf("Do a full consistency check for mapBlockIndex, setBlockIndexCandidates, chainActive and "
                      "mapBlocksUnlinked occasionally. Also sets -checkmempool (default: %u)",
                                       pnetMan->getActivePaymentNetwork()->DefaultConsistencyChecks()));
        strUsage +=
            HelpMessageOpt("-checkmempool=<n>", strprintf("Run checks every <n> transactions (default: %u)",
                                                    pnetMan->getActivePaymentNetwork()->DefaultConsistencyChecks()));
        strUsage += HelpMessageOpt(
            "-checkpoints", strprintf("Disable expensive verification for known chain history (default: %u)",
                                DEFAULT_CHECKPOINTS_ENABLED));

        strUsage += HelpMessageOpt("-dblogsize=<n>",
            strprintf("Flush wallet database activity from memory to disk log every <n> megabytes (default: %u)",
                                       DEFAULT_WALLET_DBLOGSIZE));
        strUsage += HelpMessageOpt("-disablesafemode",
            strprintf("Disable safemode, override a real safe mode event (default: %u)", DEFAULT_DISABLE_SAFEMODE));
        strUsage += HelpMessageOpt("-testsafemode", strprintf("Force safe mode (default: %u)", DEFAULT_TESTSAFEMODE));
        strUsage += HelpMessageOpt("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-fuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");

        strUsage += HelpMessageOpt(
            "-flushwallet", strprintf("Run a thread to flush wallet periodically (default: %u)", DEFAULT_FLUSHWALLET));
        strUsage += HelpMessageOpt("-stopafterblockimport",
            strprintf("Stop running after importing blocks from disk (default: %u)", DEFAULT_STOPAFTERBLOCKIMPORT));

        strUsage += HelpMessageOpt("-limitancestorcount=<n>",
            strprintf("Do not accept transactions if number of in-mempool ancestors is <n> or more (default: %u)",
                                       DEFAULT_ANCESTOR_LIMIT));
        strUsage += HelpMessageOpt(
            "-limitancestorsize=<n>", strprintf("Do not accept transactions whose size with all in-mempool ancestors "
                                                "exceeds <n> kilobytes (default: %u)",
                                          DEFAULT_ANCESTOR_SIZE_LIMIT));
        strUsage += HelpMessageOpt(
            "-limitdescendantcount=<n>", strprintf("Do not accept transactions if any ancestor would have <n> or more "
                                                   "in-mempool descendants (default: %u)",
                                             DEFAULT_DESCENDANT_LIMIT));
        strUsage += HelpMessageOpt(
            "-limitdescendantsize=<n>", strprintf("Do not accept transactions if any ancestor would have more than <n> "
                                                  "kilobytes of in-mempool descendants (default: %u).",
                                            DEFAULT_DESCENDANT_SIZE_LIMIT));
    }
    // Don't translate these and qt below
    std::string debugCategories = "addrman, alert, bench, coindb, db, lock, rand, rpc, selectcoins, mempool, "
                                  "mempoolrej, net, proxy, http, libevent, tor, zmq";
    debugCategories += ", qt";
    strUsage += HelpMessageOpt("-debug=<category>",
        strprintf(("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
            ("If <category> is not supplied or if <category> = 1, output all debugging information.") +
            ("<category> can be:") + " " + debugCategories + ".");
    if (showDebug)
        strUsage += HelpMessageOpt("-nodebug", "Turn off debugging messages, same as -debug=0");
    strUsage += HelpMessageOpt("-staking", strprintf(("Generate coins (default: %u)"), DEFAULT_GENERATE));
    strUsage += HelpMessageOpt("-help-debug", ("Show all debugging options (usage: --help -help-debug)"));
    strUsage +=
        HelpMessageOpt("-logips", strprintf(("Include IP addresses in debug output (default: %u)"), DEFAULT_LOGIPS));
    strUsage += HelpMessageOpt(
        "-logtimestamps", strprintf(("Prepend debug output with timestamp (default: %u)"), DEFAULT_LOGTIMESTAMPS));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-logtimemicros",
            strprintf("Add microsecond precision to debug timestamps (default: %u)", DEFAULT_LOGTIMEMICROS));
        strUsage += HelpMessageOpt("-mocktime=<n>", "Replace actual time with <n> seconds since epoch (default: 0)");
        strUsage += HelpMessageOpt("-limitfreerelay=<n>",
            strprintf("Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)",
                                       DEFAULT_LIMITFREERELAY));
        strUsage += HelpMessageOpt("-maxsigcachesize=<n>",
            strprintf("Limit size of signature cache to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE));
    }
    strUsage += HelpMessageOpt(
        "-minrelaytxfee=<amt>", strprintf(("Fees (in %s/kB) smaller than this are considered zero fee for relaying, "
                                           "mining and transaction creation (default: %s)"),
                                    CURRENCY_UNIT, FormatMoney(DEFAULT_MIN_RELAY_TX_FEE)));
    strUsage += HelpMessageOpt("-printtoconsole", ("Send trace/debug info to console instead of debug.log file"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt(
            "-printpriority", strprintf("Log transaction priority and fee per kB when mining blocks (default: %u)",
                                  DEFAULT_PRINTPRIORITY));

        strUsage += HelpMessageOpt("-privdb",
            strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)", DEFAULT_WALLET_PRIVDB));
    }

    strUsage += HelpMessageGroup(("Node relay options:"));

    /// TODO: fix this as it is temporarily disabled
    /*
    if (showDebug)
        strUsage += HelpMessageOpt("-acceptnonstdtxn", strprintf("Relay and mine \"non-standard\" transactions
    (%sdefault: %u)", "testnet/regtest only; ", !Params(CNetMan::TESTNET).RequireStandard()));
        */
    strUsage += HelpMessageOpt(
        "-bytespersigop", strprintf(("Minimum bytes per sigop in transactions we relay and mine (default: %u)"),
                              DEFAULT_BYTES_PER_SIGOP));
    strUsage += HelpMessageOpt("-datacarrier",
        strprintf(("Relay and mine data carrier transactions (default: %u)"), DEFAULT_ACCEPT_DATACARRIER));
    strUsage += HelpMessageOpt("-datacarriersize",
        strprintf(("Maximum size of data in data carrier transactions we relay and mine (default: %u)"),
                                   MAX_OP_RETURN_RELAY));

    strUsage += HelpMessageGroup(("Block creation options:"));
    if (showDebug)
        strUsage += HelpMessageOpt("-blockversion=<n>", "Override block version to test forking scenarios");

    strUsage += HelpMessageGroup(("RPC server options:"));
    strUsage += HelpMessageOpt("-server", ("Accept command line and JSON-RPC commands"));
    strUsage += HelpMessageOpt(
        "-rpcbind=<addr>", ("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for "
                            "IPv6. This option can be specified multiple times (default: bind to all interfaces)"));
    strUsage += HelpMessageOpt("-rpccookiefile=<loc>", ("Location of the auth cookie (default: data dir)"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", ("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", ("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt(
        "-rpcauth=<userpw>", ("Username and hashed password for JSON-RPC connections. The field <userpw> comes in the "
                              "format: <USERNAME>:<SALT>$<HASH>. A canonical python script is included in "
                              "share/rpcuser. This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(("Listen for JSON-RPC connections on <port> (default: %u)"),
                                                      pnetMan->getActivePaymentNetwork()->GetRPCPort()));
    strUsage += HelpMessageOpt(
        "-rpcallowip=<ip>", ("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. "
                             "1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. "
                             "1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcthreads=<n>",
        strprintf(("Set the number of threads to service RPC calls (default: %d)"), DEFAULT_HTTP_THREADS));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-rpcworkqueue=<n>",
            strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-rpcservertimeout=<n>",
            strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT));
    }

    return strUsage;
}

std::string LicenseInfo()
{
    // todo: remove urls from translations on next change
    return FormatParagraph(strprintf(("Copyright (C) 2014-%i The Eccoin Developers"), COPYRIGHT_YEAR)) + "\n" + "\n" +
           FormatParagraph(("This is experimental software.")) + "\n" + "\n" +
           FormatParagraph(("Distributed under the MIT software license, see the accompanying file COPYING or "
                            "<http://www.opensource.org/licenses/mit-license.php>.")) +
           "\n" + "\n" + FormatParagraph(("This product includes software developed by the OpenSSL Project for use in "
                                          "the OpenSSL Toolkit <https://www.openssl.org/> and cryptographic software "
                                          "written by Eric Young and UPnP software written by Thomas Bernard.")) +
           "\n";
}

void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex)
{
    if (!gArgs.IsArgSet("-blocknotify"))
    {
        return;
    }

    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = gArgs.GetArg("-blocknotify", "");

    boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex());
    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
}

struct CImportingNow
{
    CImportingNow()
    {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow()
    {
        assert(fImporting == true);
        fImporting = false;
    }
};

void ThreadImport(std::vector<fs::path> vImportFiles)
{
    const CNetworkTemplate &chainparams = pnetMan->getActivePaymentNetwork();
    RenameThread("bitcoin-loadblk");
    // -reindex
    if (fReindex)
    {
        CImportingNow imp;
        int nFile = 0;
        GetMainSignals().SystemMessage("REINDEX: STARTED");
        while (true)
        {
            CDiskBlockPos pos(nFile, 0);
            if (!fs::exists(GetBlockPosFilename(pos, "blk")))
            {
                break; // No block files left to reindex
            }
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
            {
                break; // This error is logged in OpenBlockFile
            }
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            GetMainSignals().SystemMessage(strprintf("REINDEX: BLOCK FILE blk%05u.dat", (unsigned int)nFile));
            pnetMan->getChainActive()->LoadExternalBlockFile(chainparams, file, &pos);
            nFile++;
        }
        pblocktree->WriteReindexing(false);
        fReindex = false;
        LogPrintf("Reindexing finished\n");
        GetMainSignals().SystemMessage("REINDEX: COMPLETE");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        pnetMan->getChainActive()->InitBlockIndex(chainparams);
    }

    // hardcoded $DATADIR/bootstrap.dat
    fs::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (fs::exists(pathBootstrap))
    {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file)
        {
            CImportingNow imp;
            fs::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            pnetMan->getChainActive()->LoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
        else
        {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock=
    for (auto const &path : vImportFiles)
    {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file)
        {
            CImportingNow imp;
            LogPrintf("Importing blocks file %s...\n", path.string());
            pnetMan->getChainActive()->LoadExternalBlockFile(chainparams, file);
        }
        else
        {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

    if (gArgs.GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT))
    {
        LogPrintf("Stopping after block import\n");
        StartShutdown();
    }
}

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if (!ECC_InitSanityCheck())
    {
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }
    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    return true;
}

bool AppInitServers(thread_group &threadGroup)
{
    RPCServer::OnStopped(&OnRPCStopped);
    RPCServer::OnPreCommand(&OnRPCPreCommand);
    if (!InitHTTPServer())
        return false;
    if (!StartRPC())
        return false;
    if (!StartHTTPRPC())
        return false;
    if (!StartHTTPServer())
        return false;
    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction()
{
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (gArgs.IsArgSet("-bind"))
    {
        if (gArgs.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (gArgs.IsArgSet("-whitebind"))
    {
        if (gArgs.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (gArgs.IsArgSet("-connect") && gArgs.IsArgSet("-connect"))
    {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (gArgs.SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (gArgs.IsArgSet("-proxy"))
    {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (gArgs.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (gArgs.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!gArgs.GetBoolArg("-listen", DEFAULT_LISTEN))
    {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (gArgs.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (gArgs.IsArgSet("-externalip"))
    {
        // if an explicit public IP is specified, do not try to find others
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (gArgs.GetBoolArg("-salvagewallet", false))
    {
        // Rewrite just private keys: rescan to find transactions
        if (gArgs.SoftSetBoolArg("-rescan", true))
            LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan
    if (gArgs.GetBoolArg("-zapwallettxes", false))
    {
        if (gArgs.SoftSetBoolArg("-rescan", true))
            LogPrintf("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (gArgs.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY))
    {
        if (gArgs.SoftSetBoolArg("-whitelistrelay", true))
            LogPrintf("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }
}

static std::string ResolveErrMsg(const char *const optname, const std::string &strBind)
{
    return strprintf(("Cannot resolve -%s address: '%s'"), optname, strBind);
}

void InitLogging()
{
    g_logger->fPrintToConsole = gArgs.GetBoolArg("-printtoconsole", false);
    g_logger->fLogTimestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    g_logger->fLogTimeMicros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    g_logger->fLogIPs = gArgs.GetBoolArg("-logips", DEFAULT_LOGIPS);

    if (g_logger->fPrintToDebugLog)
    {
        g_logger->OpenDebugLog();
    }

    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    LogPrintf("Eccoin version %s (%s)\n", FormatFullVersion(), CLIENT_DATE);
}

int initMaxConnections;
int initUserMaxConnections;
int initFD;


void GenerateNetworkTemplates()
{
    pnetMan = new CNetworkManager();
    pnetMan->SetParams(ChainNameFromCommandLine());
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2(thread_group &threadGroup)
{
// ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
// Enable Data Execution Prevention (DEP)
// Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
// A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL(WINAPI * PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol =
        (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL)
        setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking())
        return InitError("Initializing networking failed");

#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#endif

    // ********************************************************* Step 2: parameter interactions
    const CNetworkTemplate &chainparams = pnetMan->getActivePaymentNetwork();

    // also see: InitParameterInteraction()

    // Make sure enough file descriptors are available
    int nBind = std::max((int)gArgs.IsArgSet("-bind") + (int)gArgs.IsArgSet("-whitebind"), 1);
    int nUserMaxConnections = gArgs.GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    initMaxConnections = std::max(nUserMaxConnections, 0);

    // Trim requested connection counts, to fit into system limitations
    initMaxConnections =
        std::max(std::min(initMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0);
    int nFD = RaiseFileDescriptorLimit(initMaxConnections + MIN_CORE_FILEDESCRIPTORS);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
    {
        return InitError("Not enough file descriptors available.");
    }
    initMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS, initMaxConnections);

    if (initMaxConnections < nUserMaxConnections)
    {
        InitWarning(strprintf("Reducing -maxconnections from %d to %d, because of system limitations.",
            nUserMaxConnections, initMaxConnections));
    }

    // ********************************************************* Step 3: parameter-to-internal-flags

    fBeta.store(gArgs.IsArgSet("-beta"));

    g_logger->fDebug = gArgs.IsArgSet("-debug");
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages
    const std::vector<std::string> &categories = gArgs.GetArgs("-debug");
    if (gArgs.GetBoolArg("-nodebug", false) ||
        find(categories.begin(), categories.end(), std::string("0")) != categories.end())
        g_logger->fDebug = false;

    // Check for -debugnet
    if (gArgs.GetBoolArg("-debugnet", false))
        InitWarning(("Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here
    if (gArgs.IsArgSet("-socks"))
        return InitError(("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only "
                          "SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here
    if (gArgs.GetBoolArg("-tor", false))
        return InitError(("Unsupported argument -tor found, use -onion."));

    if (gArgs.GetBoolArg("-benchmark", false))
        InitWarning(("Unsupported argument -benchmark ignored, use -debug=bench."));

    if (gArgs.GetBoolArg("-whitelistalwaysrelay", false))
        InitWarning(
            ("Unsupported argument -whitelistalwaysrelay ignored, use -whitelistrelay and/or -whitelistforcerelay."));

    // Checkmempool and checkblockindex default to true in regtest mode
    int ratio = std::min<int>(
        std::max<int>(gArgs.GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000);
    if (ratio != 0)
    {
        mempool.setSanityCheck(1.0 / ratio);
    }
    fCheckBlockIndex = gArgs.GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    fCheckpointsEnabled = gArgs.GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED);

    // mempool limits
    int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    int64_t nMempoolSizeMin = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000 * 40;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency
    nScriptCheckThreads = gArgs.GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores();
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS;

    fServer = gArgs.GetBoolArg("-server", false);

    nConnectTimeout = gArgs.GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Fee-per-kilobyte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    if (gArgs.IsArgSet("-minrelaytxfee"))
    {
        CAmount n = 0;
        std::string minrelay = gArgs.GetArg("-minrelaytxfee", std::to_string(DEFAULT_TRANSACTION_MINFEE));
        if (ParseMoney(minrelay, n) && n > 0)
            ::minRelayTxFee = CFeeRate(n);
        else
            return InitError(strprintf(("Invalid amount for -minrelaytxfee=<amount>: '%i'"),
                gArgs.GetArg("-minrelaytxfee", DEFAULT_TRANSACTION_MINFEE)));
    }

    fRequireStandard = !gArgs.GetBoolArg("-acceptnonstdtxn", !pnetMan->getActivePaymentNetwork()->RequireStandard());
    if (pnetMan->getActivePaymentNetwork()->RequireStandard() && !fRequireStandard)
        return InitError(
            strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.NetworkIDString()));
    nBytesPerSigOp = gArgs.GetArg("-bytespersigop", nBytesPerSigOp);


    if (gArgs.IsArgSet("-mintxfee"))
    {
        CAmount n = 0;
        std::string minfee = gArgs.GetArg("-mintxfee", std::to_string(DEFAULT_TRANSACTION_MINFEE));
        if (ParseMoney(minfee, n) && n > 0)
            CWallet::minTxFee = CFeeRate(n);
        else
            return InitError(strprintf(("Invalid amount for -mintxfee=<amount>: '%i'"),
                gArgs.GetArg("-mintxfee", DEFAULT_TRANSACTION_MINFEE)));
    }
    if (gArgs.IsArgSet("-fallbackfee"))
    {
        CAmount nFeePerK = 0;
        std::string fallback = gArgs.GetArg("-fallbackfee", std::to_string(DEFAULT_TRANSACTION_MINFEE));
        if (!ParseMoney(fallback, nFeePerK))
            return InitError(strprintf(("Invalid amount for -fallbackfee=<amount>: '%s'"),
                gArgs.GetArg("-fallbackfee", DEFAULT_TRANSACTION_MINFEE)));
        if (nFeePerK > nHighTransactionFeeWarning)
            InitWarning(("-fallbackfee is set very high! This is the transaction fee you may pay when fee estimates "
                         "are not available."));
        CWallet::fallbackFee = CFeeRate(nFeePerK);
    }
    if (gArgs.IsArgSet("-paytxfee"))
    {
        CAmount nFeePerK = 0;
        std::string payfee = gArgs.GetArg("-paytxfee", std::to_string(DEFAULT_TRANSACTION_MINFEE));
        if (!ParseMoney(payfee, nFeePerK))
            return InitError(strprintf(("Invalid amount for -paytxfee=<amount>: '%i'"),
                gArgs.GetArg("-paytxfee", DEFAULT_TRANSACTION_MINFEE)));
        if (nFeePerK > nHighTransactionFeeWarning)
            InitWarning(
                ("-paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
        payTxFee = CFeeRate(nFeePerK, 1000);
        if (payTxFee < ::minRelayTxFee)
        {
            return InitError(strprintf(("Invalid amount for -paytxfee=<amount>: '%i' (must be at least %s)"),
                gArgs.GetArg("-paytxfee", DEFAULT_TRANSACTION_MINFEE), ::minRelayTxFee.ToString()));
        }
    }
    if (gArgs.IsArgSet("-maxtxfee"))
    {
        CAmount nMaxFee = 0;
        std::string maxfee = gArgs.GetArg("-maxtxfee", std::to_string(DEFAULT_TRANSACTION_MINFEE));
        if (!ParseMoney(maxfee, nMaxFee))
            return InitError(strprintf(("Invalid amount for -maxtxfee=<amount>: '%i'"),
                gArgs.GetArg("-maxtxfee", DEFAULT_TRANSACTION_MAXFEE)));
        if (nMaxFee > HIGH_MAX_TX_FEE)
            InitWarning(("-maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        maxTxFee = nMaxFee;
        if (CFeeRate(maxTxFee, 1000) < ::minRelayTxFee)
        {
            return InitError(strprintf(("Invalid amount for -maxtxfee=<amount>: '%i' (must be at least the minrelay "
                                        "fee of %s to prevent stuck transactions)"),
                gArgs.GetArg("-maxtxfee", DEFAULT_TRANSACTION_MAXFEE), ::minRelayTxFee.ToString()));
        }
    }
    nTxConfirmTarget = gArgs.GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    bSpendZeroConfChange = gArgs.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    fSendFreeTransactions = gArgs.GetBoolArg("-sendfreetransactions", DEFAULT_SEND_FREE_TRANSACTIONS);

    std::string strWalletFile = gArgs.GetArg("-wallet", "wallet.dat");

    fIsBareMultisigStd = gArgs.GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = gArgs.GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = gArgs.GetArg("-datacarriersize", nMaxDatacarrierBytes);

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(gArgs.GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    // ********************************************************* Step 4: application initialization: dir lock,
    // daemonize, pidfile, debug log

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return InitError(("Initialization sanity check failed. Bitcoin Core is shutting down."));

    std::string strDataDir = GetDataDir().string();

    // Wallet file must be a plain filename without a directory
    if (strWalletFile != fs::basename(strWalletFile) + fs::extension(strWalletFile))
        return InitError(strprintf(("Wallet %s resides outside data directory %s"), strWalletFile, strDataDir));
    // Make sure only a single Bitcoin process is using the data directory.
    fs::path pathLockFile = GetDataDir() / ".lock";
    FILE *file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file)
        fclose(file);

    try
    {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
        if (!lock.try_lock())
            return InitError(strprintf(
                ("Cannot obtain a lock on data directory %s. Eccoind is probably already running."), strDataDir));
    }
    catch (const boost::interprocess::interprocess_exception &e)
    {
        return InitError(
            strprintf("Cannot obtain a lock on data directory %s. Eccoind is probably already running. %s.", strDataDir,
                e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid());
#endif

    LogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0));
    if (!g_logger->fLogTimestamps)
    {
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    }
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string());
    LogPrintf("Using data directory %s\n", strDataDir);
    LogPrintf("Using config file %s\n", gArgs.GetConfigFile().string());
    LogPrintf("Using at most %i connections (%i file descriptors available)\n", initMaxConnections, initFD);
    std::ostringstream strErrors;

    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
    if (nScriptCheckThreads)
    {
        for (int i = 0; i < nScriptCheckThreads - 1; i++)
        {
            threadGroup.create_thread(&ThreadScriptCheck);
        }
    }

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (fServer)
    {
        if (!AppInitServers(threadGroup))
            return InitError(("Unable to start HTTP server. See debug log for details."));
    }

    int64_t nStart;

    // ********************************************************* Step 5: verify wallet database integrity


    LogPrintf("Using wallet %s\n", strWalletFile);
    LogPrintf("Verifying wallet...");

    std::string warningString;
    std::string errorString;

    if (!CWallet::Verify(strWalletFile, warningString, errorString))
        return false;
    if (!warningString.empty())
        InitWarning(warningString);
    if (!errorString.empty())
        return InitError(errorString);

    // ********************************************************* Step 6: network initialization

    assert(!g_connman);
    g_connman = std::unique_ptr<CConnman>(
        new CConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
    CConnman &connman = *g_connman;

    peerLogic.reset(new PeerLogicValidation(&connman));
    RegisterValidationInterface(peerLogic.get());
    RegisterNodeSignals(GetNodeSignals());

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<std::string> uacomments;
    for (auto cmt : gArgs.GetArgs("-uacomment"))
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH)
    {
        return InitError(strprintf(("Total length of network version string (%i) exceeds maximum length (%i). Reduce "
                                    "the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (gArgs.IsArgSet("-onlynet"))
    {
        std::set<enum Network> nets;
        for (auto const &snet : gArgs.GetArgs("-onlynet"))
        {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++)
        {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    if (gArgs.IsArgSet("-whitelist"))
    {
        for (const std::string &net : gArgs.GetArgs("-whitelist"))
        {
            CSubNet subnet;
            LookupSubNet(net.c_str(), subnet);
            if (!subnet.IsValid())
                return InitError(strprintf(("Invalid netmask specified in -whitelist: '%s'"), net));
            connman.AddWhitelistedRange(subnet);
        }
    }

    bool proxyRandomize = gArgs.GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set
    // a proxy, this is the default
    std::string proxyArg = gArgs.GetArg("-proxy", "");
    SetLimited(NET_TOR);
    if (proxyArg != "" && proxyArg != "0")
    {
        CService resolved(LookupNumeric(proxyArg.c_str(), 9050));
        proxyType addrProxy = proxyType(resolved, proxyRandomize);
        if (!addrProxy.IsValid())
        {
            return InitError(strprintf(("Invalid -proxy address: '%s'"), proxyArg));
        }

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_TOR, false); // by default, -proxy sets onion as
        // reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal
    // proxy for .onion addresses.
    // -noonion (or -onion=0) disables connecting to .onion entirely. An empty
    // string is used to not override the onion proxy (in which case it defaults
    // to -proxy set above, or none)
    std::string onionArg = gArgs.GetArg("-onion", "");
    if (onionArg != "")
    {
        if (onionArg == "0")
        { // Handle -noonion/-onion=0
            SetLimited(NET_TOR); // set onions as unreachable
        }
        else
        {
            CService resolved(LookupNumeric(onionArg.c_str(), 9050));
            proxyType addrOnion = proxyType(resolved, proxyRandomize);
            if (!addrOnion.IsValid())
            {
                return InitError(strprintf(("Invalid -onion address: '%s'"), onionArg));
            }
            SetProxy(NET_TOR, addrOnion);
            SetLimited(NET_TOR, false);
        }
    }


    // see Step 2: parameter interactions for more information about these
    fListen = gArgs.GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = gArgs.GetBoolArg("-discover", true);
    fNameLookup = gArgs.GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    bool fBound = false;
    if (fListen)
    {
        if (gArgs.IsArgSet("-bind") || gArgs.IsArgSet("-whitebind"))
        {
            for (auto const &strBind : gArgs.GetArgs("-bind"))
            {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(strprintf(("Cannot resolve -bind address: '%s'"), strBind));
                fBound |= Bind(connman, addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
            }
            for (auto const &strBind : gArgs.GetArgs("-whitebind"))
            {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(strprintf(("Cannot resolve -whitebind address: '%s'"), strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(("Need to specify a port with -whitebind: '%s'"), strBind));
                fBound |= Bind(connman, addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
            }
        }
        else
        {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
            fBound |= Bind(connman, CService(in6addr_any, GetListenPort()), BF_NONE);
            fBound |= Bind(connman, CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
        }
        if (!fBound)
            return InitError(("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (gArgs.IsArgSet("-externalip"))
    {
        for (const std::string &strAddr : gArgs.GetArgs("-externalip"))
        {
            CService addrLocal;
            if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
            {
                AddLocal(addrLocal, LOCAL_MANUAL);
            }
            else
            {
                return InitError(ResolveErrMsg("externalip", strAddr));
            }
        }
    }

    if (gArgs.IsArgSet("-seednode"))
    {
        for (const std::string &strDest : gArgs.GetArgs("-seednode"))
        {
            connman.AddOneShot(strDest);
        }
    }

    // ********************************************************* Step 7: load block chain

    fReindex = gArgs.GetBoolArg("-reindex", false);

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    fs::path blocksDir = GetDataDir() / "blocks";
    if (!fs::exists(blocksDir))
    {
        fs::create_directories(blocksDir);
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++)
        {
            fs::path source = GetDataDir() / strprintf("blk%04u.dat", i);
            if (!fs::exists(source))
                break;
            fs::path dest = blocksDir / strprintf("blk%05u.dat", i - 1);
            try
            {
                fs::create_hard_link(source, dest);
                LogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true;
            }
            catch (const fs::filesystem_error &e)
            {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                LogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked)
        {
            fReindex = true;
        }
    }

    // cache size calculations
    int64_t nTotalCache = (gArgs.GetArg("-dbcache", nDefaultDbCache) << 20);
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greated than nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    if (nBlockTreeDBCache > (1 << 21) && !gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    // use 25%-50% of the remainder for disk cache
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23));
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    bool fLoaded = false;
    while (!fLoaded)
    {
        bool fReset = fReindex;
        std::string strLoadError;

        LogPrintf("Loading block index...");
        nStart = GetTimeMillis();
        do
        {
            try
            {
                pnetMan->getChainActive()->UnloadBlockIndex();
                pcoinsTip.reset();
                pcoinsdbview.reset();
                pcoinscatcher.reset();
                pblocktree.reset();

                pblocktree.reset(new CBlockTreeDB(nBlockTreeDBCache, false, fReindex));
                pcoinsdbview.reset(new CCoinsViewDB(nCoinDBCache, false, fReset));
                pcoinscatcher.reset(new CCoinsViewErrorCatcher(pcoinsdbview.get()));
                pcoinsTip.reset(new CCoinsViewCache(pcoinscatcher.get()));

                if (fReindex)
                {
                    pblocktree->WriteReindexing(true);
                }
                else
                {
                    // If necessary, upgrade from older database format.
                    if (!pcoinsdbview->Upgrade())
                    {
                        strLoadError = ("Error upgrading chainstate database");
                        break;
                    }
                }

                if (!pnetMan->getChainActive()->LoadBlockIndex())
                {
                    strLoadError = ("Error loading block database");
                    break;
                }
                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                {
                    RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
                    if (!pnetMan->getChainActive()->mapBlockIndex.empty() &&
                        pnetMan->getChainActive()->mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) ==
                            0)
                    {
                        return InitError("Incorrect or no genesis block found. Wrong datadir for network?");
                    }
                }

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!pnetMan->getChainActive()->InitBlockIndex(chainparams))
                {
                    strLoadError = ("Error initializing block database");
                    break;
                }

                // verify the blocks
                LogPrintf("Verifying blocks...");

                {
                    CBlockIndex *tip = pnetMan->getChainActive()->chainActive.Tip();
                    if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60)
                    {
                        strLoadError = ("The block database contains a block which appears to be from the future. "
                                        "This may be due to your computer's date and time being set incorrectly. "
                                        "Only rebuild the block database if you are sure that your computer's "
                                        "date and time are correct");
                        break;
                    }
                }

                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview.get(),
                        gArgs.GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                        gArgs.GetArg("-checkblocks", DEFAULT_CHECKBLOCKS)))
                {
                    strLoadError = ("Corrupted block database detected");
                    break;
                }
            }
            catch (const std::exception &e)
            {
                if (g_logger->fDebug)
                    LogPrintf("%s\n", e.what());
                strLoadError = ("Error opening block database");
                break;
            }

            fLoaded = true;
        } while (false);

        if (!fLoaded)
        {
            // first suggest a reindex
            if (!fReset)
            {
                LogPrintf("Aborted block database rebuild. Exiting.\n");
                return false;
            }
            else
            {
                return InitError(strLoadError);
            }
        }
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (shutdown_threads.load())
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    LogPrintf("total time for block index %15dms\n", GetTimeMillis() - nStart);

    fs::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;

    // ********************************************************* Step 8: load wallet

    CWallet::InitLoadWallet();
    if (!pwalletMain)
        return false;

    // ********************************************************* Step 10: import blocks

    LogPrintf("Activating best chain...\n");

    std::vector<fs::path> vImportFiles;
    if (gArgs.IsArgSet("-loadblock"))
    {
        for (auto const &strFile : gArgs.GetArgs("-loadblock"))
            vImportFiles.push_back(strFile);
    }
    threadGroup.create_thread(&ThreadImport, vImportFiles);

    if (pnetMan->getChainActive()->chainActive.Tip() == nullptr)
    {
        LogPrintf("Waiting for genesis block to be imported...\n");
        while (!shutdown_threads.load() && pnetMan->getChainActive()->chainActive.Tip() == nullptr)
        {
            MilliSleep(10);
        }
    }

#if ENABLE_ZMQ
    g_zmq_notification_interface = CZMQNotificationInterface::CreateWithArguments(gArgs.GetMapArgs());
    if (g_zmq_notification_interface)
    {
        RegisterValidationInterface(g_zmq_notification_interface);
    }
#endif

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
        return false;

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    RandAddSeedPerfmon();

    //// debug print
    LogPrintf("mapBlockIndex.size() = %u\n", pnetMan->getChainActive()->mapBlockIndex.size());
    LogPrintf("nBestHeight = %d\n", pnetMan->getChainActive()->chainActive.Height());

    LogPrintf("setKeyPool.size() = %u\n", pwalletMain ? pwalletMain->setKeyPool.size() : 0);
    LogPrintf("mapWallet.size() = %u\n", pwalletMain ? pwalletMain->mapWallet.size() : 0);
    LogPrintf("mapAddressBook.size() = %u\n", pwalletMain ? pwalletMain->mapAddressBook.size() : 0);

    if (gArgs.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup);

    Discover(threadGroup);

    // Map ports with UPnP
    MapPort(gArgs.GetBoolArg("-upnp", DEFAULT_UPNP));

    std::string strNodeError;
    if (!connman.Start(strNodeError))
    {
        return InitError(strNodeError);
    }

    // Generate coins in the background
    if (gArgs.GetBoolArg("-gen", false))
    {
        ThreadGeneration(pwalletMain, false, true);
    }
    if (gArgs.GetBoolArg("-staking", false))
    {
        ThreadGeneration(pwalletMain, false, true);
    }

    // ********************************************************* Step 12: finished

    SetRPCWarmupFinished();
    LogPrintf("Done loading\n");
    GetMainSignals().SystemMessage("STARTUP: RPC AVAILABLE");


    if (pwalletMain)
    {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile));
    }

    return !shutdown_threads.load();
}
