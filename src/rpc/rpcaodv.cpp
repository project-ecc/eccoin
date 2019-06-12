#include "net/aodv.h"
#include "rpcserver.h"
#include "util/logger.h"
#include "util/utilstrencodings.h"
#include <univalue.h>

extern CCriticalSection cs_main;

UniValue getaodvtable(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getaodvtable\n"
            "\nreturns the aodv routing table.\n"
            "\nResult:\n"
            "{\n"
            "   \"mapidkey\" : {\n"
            "       \"NodeId : Key,\"\n"
            "       ...\n"
            "   },\n"
            "   \"mapkeyid\" : {\n"
            "       \"Key : NodeId,\"\n"
            "       ...\n"
            "   }\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getaodvtable", "") +
            HelpExampleRpc("getaodvtable", "")
        );
    std::map<NodeId, CPubKey> IdKey;
    std::map<CPubKey, NodeId> KeyId;
    g_aodvtable.GetRoutingTables(IdKey, KeyId);
    UniValue obj(UniValue::VOBJ);
    UniValue IdKeyObj(UniValue::VOBJ);
    for (auto &entry : IdKey)
    {
        IdKeyObj.push_back(Pair(std::to_string(entry.first), entry.second.Raw64Encoded()));
    }
    UniValue KeyIdObj(UniValue::VOBJ);
    for (auto &entry : KeyId)
    {
        KeyIdObj.push_back(Pair(entry.first.Raw64Encoded(), entry.second));
    }
    obj.push_back(Pair("mapidkey", IdKeyObj));
    obj.push_back(Pair("mapkeyid", KeyIdObj));
    return obj;
}


UniValue getaodvkeyentry(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getaodvkeyentry \"keyhash\" \n"
            "\nChecks AODV routing table for a key with a hash that matches keyhash, returns its NodeId.\n"
            "\nArguments:\n"
            "1. \"keyhash\"   (string, required) The hash of the key of the desired entry\n"
            "\nNote: This call is fairly expensive due to number of hashes being done.\n"
            "\nExamples:\n"+
            HelpExampleCli("getaodvkeyentry", "\"keyhash\"") +
            HelpExampleRpc("getaodvkeyentry", "\"keyhash\""));

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("Error", "this rpc call is currently disabled"));
    return obj;
}

UniValue getaodvidentry(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getaodvidentry \"nodeid\" \n"
            "\nChecks AODV routing table for the desired nodeid, returns its keys hash.\n"
            "\nArguments:\n"
            "1. \"nodeid\"   (number, required) The nodeid of the desired entry\n"
            "\nExamples:\n"+
            HelpExampleCli("getaodvidentry", "12") +
            HelpExampleRpc("getaodvidentry", "32"));

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("Error", "this rpc call is currently disabled"));
    return obj;
}

UniValue getroutingpubkey(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getroutingpubkey\n"
            "\nreturns the routing public key used by this node.\n"
            "\nResult:\n"
            "\"Key\" (string)\n"
            "\nExamples:\n" +
            HelpExampleCli("getroutingpubkey", "") +
            HelpExampleRpc("getroutingpubkey", "")
        );

    LOCK(cs_main);
    if (!g_connman)
    {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    return g_connman->GetRoutingKey().Raw64Encoded();
}


UniValue findroute(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "findroute\n"
            "\nattempts to find a route to the node with the given pub key.\n"
            "\nResult:\n"
            "\"None\n"
            "\nExamples:\n" +
            HelpExampleCli("findroute", "1139d39a984a0ff431c467f738d534c36824401a4735850561f7ac64e4d49f5b") +
            HelpExampleRpc("findroute", "1139d39a984a0ff431c467f738d534c36824401a4735850561f7ac64e4d49f5b")
        );

    LOCK(cs_main);
    if (!g_connman)
    {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    bool fInvalid = false;
    std::vector<unsigned char> vPubKey = DecodeBase64(params[0].get_str().c_str(), &fInvalid);
    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed pubkey base64 encoding");
    if (g_aodvtable.HaveKeyEntry(CPubKey(vPubKey.begin(), vPubKey.end())))
    {
        return NullUniValue;
    }
    uint64_t nonce = 0;
    GetRandBytes((uint8_t *)&nonce, sizeof(nonce));
    CPubKey key;
    RequestRouteToPeer(g_connman.get(), key, nonce, CPubKey(vPubKey.begin(), vPubKey.end()));
    LogPrintf("done sending route requests \n");
    return NullUniValue;
}

UniValue haveroute(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "haveroute\n"
            "\nchecks if a route to the node with the given pub key is known.\n"
            "\nResult:\n"
            "\"true/false\n"
            "\nExamples:\n" +
            HelpExampleCli("haveroute", "1139d39a984a0ff431c467f738d534c36824401a4735850561f7ac64e4d49f5b") +
            HelpExampleRpc("haveroute", "1139d39a984a0ff431c467f738d534c36824401a4735850561f7ac64e4d49f5b")
        );

    LOCK(cs_main);
    if (!g_connman)
    {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }
    LogPrintf("have route was given pubkey %s \n", params[0].get_str());
    bool fInvalid = false;
    std::vector<unsigned char> vPubKey = DecodeBase64(params[0].get_str().c_str(), &fInvalid);
    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed pubkey base64 encoding");
    if (g_aodvtable.HaveKeyEntry(CPubKey(vPubKey.begin(), vPubKey.end())))
    {
        return true;
    }
    return g_aodvtable.HaveKeyRoute(CPubKey(vPubKey.begin(), vPubKey.end()));
}
