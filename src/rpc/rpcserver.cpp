// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcserver.h"

#include "rpcclient.h"

#include "args.h"
#include "base58.h"
#include "init.h"
#include "random.h"
#include "sync.h"

#include "util/util.h"
#include "util/utilstrencodings.h"

#include "events.h"
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

#include <boost/algorithm/string/case_conv.hpp>

static const char DEFAULT_RPCCONNECT[] = "127.0.0.1";
static const int DEFAULT_HTTP_CLIENT_TIMEOUT = 900;
static const bool DEFAULT_NAMED = false;
static const int CONTINUE_EXECUTION = -1;

using namespace RPCServer;

extern bool fRPCRunning;
extern bool fRPCInWarmup;
extern std::string rpcWarmupStatus;
extern CCriticalSection cs_rpcWarmup;
/* Timer-creating functions */
std::vector<RPCTimerInterface *> timerInterfaces;
/* Map of name to timer.
 * @note Can be changed to std::unique_ptr when C++11 */
std::map<std::string, boost::shared_ptr<RPCTimerBase> > deadlineTimers;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:
    explicit inline CConnectionFailed(const std::string &msg) : std::runtime_error(msg) {}
};

static struct CRPCSignals
{
    boost::signals2::signal<void()> Started;
    boost::signals2::signal<void()> Stopped;
    boost::signals2::signal<void(const CRPCCommand &)> PreCommand;
} g_rpcSignals;

void RPCServer::OnStarted(boost::function<void()> slot) { g_rpcSignals.Started.connect(slot); }
void RPCServer::OnStopped(boost::function<void()> slot) { g_rpcSignals.Stopped.connect(slot); }
void RPCServer::OnPreCommand(boost::function<void(const CRPCCommand &)> slot)
{
    g_rpcSignals.PreCommand.connect(boost::bind(slot, _1));
}

void RPCTypeCheck(const UniValue &params, const std::list<UniValue::VType> &typesExpected, bool fAllowNull)
{
    unsigned int i = 0;
    for (auto t : typesExpected)
    {
        if (params.size() <= i)
            break;

        const UniValue &v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.isNull()))))
        {
            std::string err = strprintf("Expected type %s, got %s", uvTypeName(t), uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheckObj(const UniValue &o, const std::map<std::string, UniValue::VType> &typesExpected, bool fAllowNull)
{
    for (auto const &t : typesExpected)
    {
        const UniValue &v = find_value(o, t.first);
        if (!fAllowNull && v.isNull())
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first));

        if (!((v.type() == t.second) || (fAllowNull && (v.isNull()))))
        {
            std::string err =
                strprintf("Expected type %s for %s, got %s", uvTypeName(t.second), t.first, uvTypeName(v.type()));
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}


const std::string TruncateDecimals(const std::string valstr)
{
    std::string fixedNum = "";
    bool decimalFound = false;
    int remainingPrecision = 6;
    for (unsigned int pos = 0; pos < valstr.length(); pos++)
    {
        if (decimalFound)
        {
            remainingPrecision--;
        }
        if (valstr[pos] == '.')
        {
            decimalFound = true;
        }
        fixedNum = fixedNum + valstr[pos];
        if (remainingPrecision <= 0)
        {
            break;
        }
    }
    const std::string result = fixedNum;
    return result;
}

CAmount AmountFromValue(const UniValue &value)
{
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(TruncateDecimals(value.getValStr()), 6, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

// NOTE originally used 8 not 6
CAmount AmountFromValue_Original(const UniValue &value)
{
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 6, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

UniValue ValueFromAmount(const CAmount &amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return UniValue(UniValue::VNUM, strprintf("%s%d.%06d", sign ? "-" : "", quotient, remainder));
}

uint256 ParseHashV(const UniValue &v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const UniValue &o, std::string strKey) { return ParseHashV(find_value(o, strKey), strKey); }
std::vector<unsigned char> ParseHexV(const UniValue &v, std::string strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName + " must be hexadecimal string (not '" + strHex + "')");
    return ParseHex(strHex);
}
std::vector<unsigned char> ParseHexO(const UniValue &o, std::string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

/**
 * Note: This interface may still be subject to change.
 */

std::string CRPCTable::help(const std::string &strCommand) const
{
    std::string strRet;
    std::string category;
    std::set<rpcfn_type> setDone;
    std::vector<std::pair<std::string, const CRPCCommand *> > vCommands;

    for (std::map<std::string, const CRPCCommand *>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end();
         ++mi)
        vCommands.push_back(make_pair(mi->second->category + mi->first, mi->second));
    std::sort(vCommands.begin(), vCommands.end());

    for (auto const &command : vCommands)
    {
        const CRPCCommand *pcmd = command.second;
        std::string strMethod = pcmd->name;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != std::string::npos)
            continue;
        if ((strCommand != "" || pcmd->category == "hidden") && strMethod != strCommand)
            continue;
        try
        {
            UniValue params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (const std::exception &e)
        {
            // Help text is returned in an exception
            std::string strHelp = std::string(e.what());
            if (strCommand == "")
            {
                if (strHelp.find('\n') != std::string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));

                if (category != pcmd->category)
                {
                    if (!category.empty())
                        strRet += "\n";
                    category = pcmd->category;
                    std::string firstLetter = category.substr(0, 1);
                    boost::to_upper(firstLetter);
                    strRet += "== " + firstLetter + category.substr(1) + " ==\n";
                }
            }
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand);
    strRet = strRet.substr(0, strRet.size() - 1);
    return strRet;
}

UniValue help(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error("help ( \"command\" )\n"
                                 "\nList all commands, or get help for a specified command.\n"
                                 "\nArguments:\n"
                                 "1. \"command\"     (string, optional) The command to get help on\n"
                                 "\nResult:\n"
                                 "\"text\"     (string) The help text\n");

    std::string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return tableRPC.help(strCommand);
}


UniValue stop(const UniValue &params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
    if (fHelp || params.size() > 1)
        throw std::runtime_error("stop\n"
                                 "\nStop Eccoind server.");
    // Event loop will exit after current HTTP requests have been handled, so
    // this reply will get back to the client.
    StartShutdown();
    return "Eccoind server stopping";
}

/**
 * Call Table
 */
static const CRPCCommand vRPCCommands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    /* Overall control/query calls */
    {"control", "getinfo", &getinfo, true}, /* uses wallet if enabled */
    {"control", "help", &help, true}, {"control", "stop", &stop, true},

    /* P2P networking */
    {"network", "getnetworkinfo", &getnetworkinfo, true}, {"network", "addnode", &addnode, true},
    {"network", "disconnectnode", &disconnectnode, true}, {"network", "getaddednodeinfo", &getaddednodeinfo, true},
    {"network", "getconnectioncount", &getconnectioncount, true}, {"network", "getnettotals", &getnettotals, true},
    {"network", "getpeerinfo", &getpeerinfo, true}, {"network", "ping", &ping, true},
    {"network", "setban", &setban, true}, {"network", "listbanned", &listbanned, true},
    {"network", "clearbanned", &clearbanned, true}, {"network", "getaodvtable", &getaodvtable, true},
    {"network", "getaodvkeyentry", &getaodvkeyentry, true}, {"network", "getaodvidentry", &getaodvidentry, true},
    {"network", "getroutingpubkey", &getroutingpubkey, true}, {"network", "findroute", &findroute, true},
    {"network", "haveroute", &haveroute, true}, {"network", "sendpacket", &sendpacket, true},
    {"network", "getbuffer", &getbuffer, true}, {"network", "tagsignmessage", &tagsignmessage, true},
    {"network", "tagverifymessage", &tagverifymessage, true},

    /* Block chain and UTXO */
    {"blockchain", "getblockchaininfo", &getblockchaininfo, true},
    {"blockchain", "getbestblockhash", &getbestblockhash, true}, {"blockchain", "getblockcount", &getblockcount, true},
    {"blockchain", "getblock", &getblock, true}, {"blockchain", "getblockhash", &getblockhash, true},
    {"blockchain", "getblockheader", &getblockheader, true}, {"blockchain", "getchaintips", &getchaintips, true},
    {"blockchain", "getdifficulty", &getdifficulty, true}, {"blockchain", "getmempoolinfo", &getmempoolinfo, true},
    {"blockchain", "getrawmempool", &getrawmempool, true}, {"blockchain", "gettxout", &gettxout, true},
    {"blockchain", "gettxoutproof", &gettxoutproof, true}, {"blockchain", "verifytxoutproof", &verifytxoutproof, true},
    {"blockchain", "gettxoutsetinfo", &gettxoutsetinfo, true}, {"blockchain", "verifychain", &verifychain, true},

    /* Mining */
    {"mining", "getblocktemplate", &getblocktemplate, true}, {"mining", "getmininginfo", &getmininginfo, true},
    {"mining", "getnetworkhashps", &getnetworkhashps, true},
    {"mining", "prioritisetransaction", &prioritisetransaction, true}, {"mining", "submitblock", &submitblock, true},

    /* Coin generation */
    {"generating", "getgenerate", &getgenerate, true}, {"generating", "setgenerate", &setgenerate, true},
    {"generating", "getgeneratepos", &getgeneratepos, true}, {"generating", "setgeneratepos", &setgeneratepos, true},
    {"generating", "generate", &generate, true}, {"generating", "generatepos", &generatepos, true},
    {"generating", "generatetoaddress", &generatetoaddress, true},
    {"generating", "generatepostoaddress", &generatepostoaddress, true},

    /* Raw transactions */
    {"rawtransactions", "createrawtransaction", &createrawtransaction, true},
    {"rawtransactions", "decoderawtransaction", &decoderawtransaction, true},
    {"rawtransactions", "decodescript", &decodescript, true},
    {"rawtransactions", "getrawtransaction", &getrawtransaction, true},
    {"rawtransactions", "sendrawtransaction", &sendrawtransaction, false},
    {"rawtransactions", "signrawtransaction", &signrawtransaction, false}, /* uses wallet if enabled */
    {"rawtransactions", "fundrawtransaction", &fundrawtransaction, false},

    /* Utility functions */
    {"util", "createmultisig", &createmultisig, true},
    {"util", "validateaddress", &validateaddress, true}, /* uses wallet if enabled */
    {"util", "verifymessage", &verifymessage, true}, {"util", "estimatefee", &estimatefee, true},
    {"util", "estimatesmartfee", &estimatesmartfee, true},

    /* Not shown in help */
    {"hidden", "invalidateblock", &invalidateblock, true}, {"hidden", "reconsiderblock", &reconsiderblock, true},
    {"hidden", "setmocktime", &setmocktime, true},
    {"hidden", "resendwallettransactions", &resendwallettransactions, true},

    /* Wallet */
    {"wallet", "addmultisigaddress", &addmultisigaddress, true}, {"wallet", "backupwallet", &backupwallet, true},
    {"wallet", "dumpprivkey", &dumpprivkey, true}, {"wallet", "dumpwallet", &dumpwallet, true},
    {"wallet", "listaddresses", &listaddresses, true}, {"wallet", "encryptwallet", &encryptwallet, true},
    {"wallet", "getbalance", &getbalance, false}, {"wallet", "getnewaddress", &getnewaddress, true},
    {"wallet", "getrawchangeaddress", &getrawchangeaddress, true},
    {"wallet", "getreceivedbyaddress", &getreceivedbyaddress, false},
    {"wallet", "gettransaction", &gettransaction, false}, {"wallet", "abandontransaction", &abandontransaction, false},
    {"wallet", "getunconfirmedbalance", &getunconfirmedbalance, false},
    {"wallet", "getwalletinfo", &getwalletinfo, false}, {"wallet", "importprivkey", &importprivkey, true},
    {"wallet", "importwallet", &importwallet, true}, {"wallet", "importaddress", &importaddress, true},
    {"wallet", "importpubkey", &importpubkey, true}, {"wallet", "keypoolrefill", &keypoolrefill, true},
    {"wallet", "listaddressgroupings", &listaddressgroupings, false},
    {"wallet", "listlockunspent", &listlockunspent, false},
    {"wallet", "listreceivedbyaddress", &listreceivedbyaddress, false},
    {"wallet", "listsinceblock", &listsinceblock, false}, {"wallet", "listtransactions", &listtransactions, false},
    {"wallet", "listunspent", &listunspent, false}, {"wallet", "lockunspent", &lockunspent, true},
    {"wallet", "sendmany", &sendmany, false}, {"wallet", "sendtoaddress", &sendtoaddress, false},
    {"wallet", "settxfee", &settxfee, true}, {"wallet", "signmessage", &signmessage, true},
    {"wallet", "walletlock", &walletlock, true}, {"wallet", "walletpassphrasechange", &walletpassphrasechange, true},
    {"wallet", "walletpassphrase", &walletpassphrase, true},

#if ENABLE_ZMQ
    /* ZMQ */
    {"zmq", "getzmqnotifications", &getzmqnotifications, true},
#endif
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](const std::string &name) const
{
    std::map<std::string, const CRPCCommand *>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

bool StartRPC()
{
    LogPrint("rpc", "Starting RPC\n");
    fRPCRunning = true;
    g_rpcSignals.Started();
    return true;
}

void InterruptRPC()
{
    LogPrint("rpc", "Interrupting RPC\n");
    // Interrupt e.g. running longpolls
    fRPCRunning = false;
}

void StopRPC()
{
    LogPrint("rpc", "Stopping RPC\n");
    deadlineTimers.clear();
    g_rpcSignals.Stopped();
}

bool IsRPCRunning() { return fRPCRunning; }
void SetRPCWarmupStatus(const std::string &newStatus)
{
    LOCK(cs_rpcWarmup);
    rpcWarmupStatus = newStatus;
}

void SetRPCWarmupFinished()
{
    LOCK(cs_rpcWarmup);
    assert(fRPCInWarmup);
    fRPCInWarmup = false;
}

bool RPCIsInWarmup(std::string *outStatus)
{
    LOCK(cs_rpcWarmup);
    if (outStatus)
        *outStatus = rpcWarmupStatus;
    return fRPCInWarmup;
}

void JSONRequest::parse(const UniValue &valRequest)
{
    // Parse request
    if (!valRequest.isObject())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const UniValue &request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    UniValue valMethod = find_value(request, "method");
    if (valMethod.isNull())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (!valMethod.isStr())
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    if (strMethod != "getblocktemplate")
        LogPrint("rpc", "ThreadRPCServer method=%s\n", SanitizeString(strMethod));

    // Parse params
    UniValue valParams = find_value(request, "params");
    if (valParams.isArray())
        params = valParams.get_array();
    else if (valParams.isNull())
        params = UniValue(UniValue::VARR);
    else
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static UniValue JSONRPCExecOne(const UniValue &req)
{
    UniValue rpc_result(UniValue::VOBJ);

    JSONRequest jreq;
    try
    {
        jreq.parse(req);

        UniValue result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, NullUniValue, jreq.id);
    }
    catch (const UniValue &objError)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, objError, jreq.id);
    }
    catch (const std::exception &e)
    {
        rpc_result = JSONRPCReplyObj(NullUniValue, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

std::string JSONRPCExecBatch(const UniValue &vReq)
{
    UniValue ret(UniValue::VARR);
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return ret.write() + "\n";
}

UniValue CRPCTable::execute(const std::string &strMethod, const UniValue &params) const
{
    // Return immediately if in warmup
    {
        LOCK(cs_rpcWarmup);
        if (fRPCInWarmup)
            throw JSONRPCError(RPC_IN_WARMUP, rpcWarmupStatus);
    }

    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");


    g_rpcSignals.PreCommand(*pcmd);

    try
    {
        // Execute
        return pcmd->actor(params, false);
    }
    catch (const std::exception &e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}

std::string HelpExampleCli(const std::string &methodname, const std::string &args)
{
    return "> eccoind " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(const std::string &methodname, const std::string &args)
{
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
           "\"method\": \"" +
           methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/\n";
}

void RPCRegisterTimerInterface(RPCTimerInterface *iface) { timerInterfaces.push_back(iface); }
void RPCUnregisterTimerInterface(RPCTimerInterface *iface)
{
    std::vector<RPCTimerInterface *>::iterator i = std::find(timerInterfaces.begin(), timerInterfaces.end(), iface);
    assert(i != timerInterfaces.end());
    timerInterfaces.erase(i);
}

void RPCRunLater(const std::string &name, boost::function<void(void)> func, int64_t nSeconds)
{
    if (timerInterfaces.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No timer handler registered for RPC");
    deadlineTimers.erase(name);
    RPCTimerInterface *timerInterface = timerInterfaces.back();
    LogPrint("rpc", "queue run of timer %s in %i seconds (using %s)\n", name, nSeconds, timerInterface->Name());
    deadlineTimers.insert(
        std::make_pair(name, boost::shared_ptr<RPCTimerBase>(timerInterface->NewTimer(func, nSeconds * 1000))));
}

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply() : status(0), error(-1) {}
    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch (code)
    {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply *>(ctx);

    if (req == nullptr)
    {
        /* If req is nullptr, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char *)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply *>(ctx);
    reply->error = err;
}
#endif

/** Class that handles the conversion from a command-line to a JSON-RPC request,
 * as well as converting back to a JSON object that can be shown as result.
 */
class BaseRequestHandler
{
public:
    virtual UniValue PrepareRequest(const std::string &method, const std::vector<std::string> &args) = 0;
    virtual UniValue ProcessReply(const UniValue &batch_in) = 0;
};

/** Process getinfo requests */
class GetinfoRequestHandler : public BaseRequestHandler
{
public:
    const int ID_NETWORKINFO = 0;
    const int ID_BLOCKCHAININFO = 1;
    const int ID_WALLETINFO = 2;

    /** Create a simulated `getinfo` request. */
    UniValue PrepareRequest(const std::string &method, const std::vector<std::string> &args) override
    {
        if (!args.empty())
        {
            throw std::runtime_error("-getinfo takes no arguments");
        }
        UniValue result(UniValue::VARR);
        result.push_back(JSONRPCRequestObj("getnetworkinfo", NullUniValue, ID_NETWORKINFO));
        result.push_back(JSONRPCRequestObj("getblockchaininfo", NullUniValue, ID_BLOCKCHAININFO));
        result.push_back(JSONRPCRequestObj("getwalletinfo", NullUniValue, ID_WALLETINFO));
        return result;
    }

    /** Collect values from the batch and form a simulated `getinfo` reply. */
    UniValue ProcessReply(const UniValue &batch_in) override
    {
        UniValue result(UniValue::VOBJ);
        std::vector<UniValue> batch = JSONRPCProcessBatchReply(batch_in, 3);
        // Errors in getnetworkinfo() and getblockchaininfo() are fatal, pass them on
        // getwalletinfo() is allowed to fail in case there is no wallet.
        if (!batch[ID_NETWORKINFO]["error"].isNull())
        {
            return batch[ID_NETWORKINFO];
        }
        if (!batch[ID_BLOCKCHAININFO]["error"].isNull())
        {
            return batch[ID_BLOCKCHAININFO];
        }
        result.pushKV("version", batch[ID_NETWORKINFO]["result"]["version"]);
        result.pushKV("protocolversion", batch[ID_NETWORKINFO]["result"]["protocolversion"]);
        if (!batch[ID_WALLETINFO].isNull())
        {
            result.pushKV("walletversion", batch[ID_WALLETINFO]["result"]["walletversion"]);
            result.pushKV("balance", batch[ID_WALLETINFO]["result"]["balance"]);
        }
        result.pushKV("blocks", batch[ID_BLOCKCHAININFO]["result"]["blocks"]);
        result.pushKV("timeoffset", batch[ID_NETWORKINFO]["result"]["timeoffset"]);
        result.pushKV("connections", batch[ID_NETWORKINFO]["result"]["connections"]);
        result.pushKV("proxy", batch[ID_NETWORKINFO]["result"]["networks"][0]["proxy"]);
        result.pushKV("difficulty", batch[ID_BLOCKCHAININFO]["result"]["difficulty"]);
        result.pushKV("testnet", UniValue(batch[ID_BLOCKCHAININFO]["result"]["chain"].get_str() == "test"));
        if (!batch[ID_WALLETINFO].isNull())
        {
            result.pushKV("walletversion", batch[ID_WALLETINFO]["result"]["walletversion"]);
            result.pushKV("balance", batch[ID_WALLETINFO]["result"]["balance"]);
            result.pushKV("keypoololdest", batch[ID_WALLETINFO]["result"]["keypoololdest"]);
            result.pushKV("keypoolsize", batch[ID_WALLETINFO]["result"]["keypoolsize"]);
            if (!batch[ID_WALLETINFO]["result"]["unlocked_until"].isNull())
            {
                result.pushKV("unlocked_until", batch[ID_WALLETINFO]["result"]["unlocked_until"]);
            }
            result.pushKV("paytxfee", batch[ID_WALLETINFO]["result"]["paytxfee"]);
        }
        result.pushKV("relayfee", batch[ID_NETWORKINFO]["result"]["relayfee"]);
        result.pushKV("warnings", batch[ID_NETWORKINFO]["result"]["warnings"]);
        return JSONRPCReplyObj(result, NullUniValue, 1);
    }
};

/** Process default single requests */
class DefaultRequestHandler : public BaseRequestHandler
{
public:
    UniValue PrepareRequest(const std::string &method, const std::vector<std::string> &args) override
    {
        UniValue params;
        params = RPCConvertValues(method, args);
        return JSONRPCRequestObj(method, params, 1);
    }

    UniValue ProcessReply(const UniValue &reply) override { return reply.get_obj(); }
};

static UniValue CallRPC(BaseRequestHandler *rh, const std::string &strMethod, const std::vector<std::string> &args)
{
    std::string host;
    // In preference order, we choose the following for the port:
    //     1. -rpcport
    //     2. port in -rpcconnect (ie following : in ipv4 or ]: in ipv6)
    //     3. default port for chain
    int port = RPCPortFromCommandLine();
    SplitHostPort(gArgs.GetArg("-rpcconnect", DEFAULT_RPCCONNECT), port, host);
    port = gArgs.GetArg("-rpcport", port);

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), gArgs.GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void *)&response);
    if (req == nullptr)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Get credentials
    std::string strRPCUserColonPass;
    if (gArgs.GetArg("-rpcpassword", "") == "")
    {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass))
        {
            throw std::runtime_error(
                strprintf("Could not locate RPC credentials. No authentication cookie could be found, and RPC "
                          "password is not set.  See -rpcpassword and -stdinrpcpass.  Configuration file: (%s)",
                    gArgs.GetConfigFile().string().c_str()));
        }
    }
    else
    {
        strRPCUserColonPass = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    }

    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(
        output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = rh->PrepareRequest(strMethod, args).write() + "\n";
    struct evbuffer *output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    // check if we should use a special wallet endpoint
    std::string endpoint = "/";
    std::string walletName = gArgs.GetArg("-rpcwallet", "");
    if (!walletName.empty())
    {
        char *encodedURI = evhttp_uriencode(walletName.c_str(), walletName.size(), false);
        if (encodedURI)
        {
            endpoint = "/wallet/" + std::string(encodedURI);
            free(encodedURI);
        }
        else
        {
            throw CConnectionFailed("uri-encode failed");
        }
    }
    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, endpoint.c_str());
    req.release(); // ownership moved to evcon in above call
    if (r != 0)
    {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and "
                                          "you are connecting to the correct RPC port)",
            http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND &&
             response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue reply = rh->ProcessReply(valReply);
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

int CommandLineRPC(int argc, char *argv[])
{
    std::string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }
        std::string rpcPass;
        if (gArgs.GetBoolArg("-stdinrpcpass", false))
        {
            if (!std::getline(std::cin, rpcPass))
            {
                throw std::runtime_error("-stdinrpcpass specified but failed to read from standard input");
            }
            gArgs.ForceSetArg("-rpcpassword", rpcPass);
        }
        std::vector<std::string> args = std::vector<std::string>(&argv[1], &argv[argc]);
        if (gArgs.GetBoolArg("-stdin", false))
        {
            // Read one arg per line from stdin and append
            std::string line;
            while (std::getline(std::cin, line))
            {
                args.push_back(line);
            }
        }
        std::unique_ptr<BaseRequestHandler> rh;
        std::string method;
        if (gArgs.GetBoolArg("-getinfo", false))
        {
            rh.reset(new GetinfoRequestHandler());
            method = "";
        }
        else
        {
            rh.reset(new DefaultRequestHandler());
            if (args.size() < 1)
            {
                throw std::runtime_error("too few parameters (need at least command)");
            }
            method = args[0];
            args.erase(args.begin()); // Remove trailing method name from arguments vector
        }

        // Execute and handle connection failures with -rpcwait
        const bool fWait = gArgs.GetBoolArg("-rpcwait", false);
        do
        {
            try
            {
                const UniValue reply = CallRPC(rh.get(), method, args);

                // Parse reply
                const UniValue &result = find_value(reply, "result");
                const UniValue &error = find_value(reply, "error");

                if (!error.isNull())
                {
                    // Error
                    int code = error["code"].get_int();
                    if (fWait && code == RPC_IN_WARMUP)
                        throw CConnectionFailed("server in warmup");
                    strPrint = "error: " + error.write();
                    nRet = abs(code);
                    if (error.isObject())
                    {
                        UniValue errCode = find_value(error, "code");
                        UniValue errMsg = find_value(error, "message");
                        strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                        if (errMsg.isStr())
                            strPrint += "error message:\n" + errMsg.get_str();
                    }
                }
                else
                {
                    // Result
                    if (result.isNull())
                        strPrint = "";
                    else if (result.isStr())
                        strPrint = result.get_str();
                    else
                        strPrint = result.write(2);
                }
                // Connection succeeded, no need to retry.
                break;
            }
            catch (const CConnectionFailed &)
            {
                if (fWait)
                    MilliSleep(1000);
                else
                    throw;
            }
        } while (fWait);
    }
    catch (const boost::thread_interrupted &)
    {
        throw;
    }
    catch (std::exception &e)
    {
        strPrint = std::string("error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}

const CRPCTable tableRPC;
