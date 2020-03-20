// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "beta.h"
#include "net/aodv.h"
#include "net/packetmanager.h"
#include "rpcserver.h"
#include "util/logger.h"
#include "util/utilstrencodings.h"
#include <univalue.h>

#include "main.h"

#include <sstream>

extern CCriticalSection cs_main;

UniValue getaodvtable(const UniValue &params, bool fHelp)
{
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

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
    std::map<NodeId, std::set<CPubKey> > IdKey;
    std::map<CPubKey, NodeId> KeyId;
    g_aodvtable.GetRoutingTables(IdKey, KeyId);
    UniValue obj(UniValue::VOBJ);
    UniValue IdKeyObj(UniValue::VOBJ);
    for (auto &entry : IdKey)
    {
        for (auto &path : entry.second)
        {
            IdKeyObj.push_back(Pair(std::to_string(entry.first), path.Raw64Encoded()));
        }
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
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

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
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

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
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

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

    return g_connman->GetPublicTagPubKey().Raw64Encoded();
}


UniValue findroute(const UniValue &params, bool fHelp)
{
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

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
    if (g_aodvtable.HaveRoute(CPubKey(vPubKey.begin(), vPubKey.end())))
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
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

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
    if (g_aodvtable.HaveRoute(CPubKey(vPubKey.begin(), vPubKey.end())))
    {
        return true;
    }
    return g_aodvtable.HaveRoute(CPubKey(vPubKey.begin(), vPubKey.end()));
}

UniValue sendpacket(const UniValue &params, bool fHelp)
{
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

    if (fHelp || params.size() != 4)
    {
        throw std::runtime_error(
            "sendpacket\n"
            "\nattempts to send a network packet to the destination\n"
            "\nArguments:\n"
            "1. \"key\"   (string, required) The key of the desired recipient\n"
            "2. \"protocolId\"   (number, required) The id of the protocol being used for the data\n"
            "3. \"protocolVersion\"   (number, required) The protocol version being used\n"
            "4. \"Data\"   (vector of bytes, required) The desired data to be sent \n"
            "\nExamples:\n" +
            HelpExampleCli("sendpacket", "\"1139d39a984a0ff431c467f738d534c36824401a4735850561f7ac64e4d49f5b\" 1 1 \"this is example data\"") +
            HelpExampleRpc("sendpacket", "\"1139d39a984a0ff431c467f738d534c36824401a4735850561f7ac64e4d49f5b\", 1, 1, \"this is example data\"")
        );
    }
    bool fInvalid = false;
    std::vector<unsigned char> vPubKey = DecodeBase64(params[0].get_str().c_str(), &fInvalid);
    // TODO : import unsigned values for univalue from upstream, change thse calls to get_uint8
    uint8_t nProtocolId = (uint8_t)params[1].get_int();
    uint8_t nProtocolVersion = (uint8_t)params[2].get_int();

    std::vector<uint8_t> vData = StrToBytes(params[3].get_str());

    bool result = g_packetman.SendPacket(vPubKey, nProtocolId, nProtocolVersion, vData);
    return result;
}

UniValue getbuffer(const UniValue &params, bool fHelp)
{
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

    if (fHelp || params.size() != 1)
    {
        throw std::runtime_error(
            "getbuffer\n"
            "\nattempts to get the buffer for a network service protocol\n"
            "\nArguments:\n"
            "1. \"protocolId\"   (number, required) The id of the protocol being requested\n"
            "\nExamples:\n" +
            HelpExampleCli("getbuffer", "1") +
            HelpExampleRpc("getbuffer", "1")
        );
    }
    uint8_t nProtocolId = (uint8_t)params[0].get_int();
    PacketBuffer buffer;
    UniValue obj(UniValue::VOBJ);
    if (g_packetman.GetBuffer(nProtocolId, buffer))
    {
        uint64_t counter = 0;
        for (auto &entry: buffer.vRecievedPackets)
        {
            std::stringstream hexstream;
            hexstream << std::hex;
            for (uint8_t &byte : entry.GetData())
            {
                hexstream << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            obj.push_back(Pair(std::to_string(counter), hexstream.str()));
            counter++;
        }
    }
    return obj;
}

UniValue tagsignmessage(const UniValue &params, bool fHelp)
{
    if (!IsBetaEnabled())
    {
        return "This rpc call requires beta features to be enabled (-beta or beta=1) \n";
    }

    if (fHelp || params.size() != 1)
    {
        throw std::runtime_error(
            "tagsignmessage\n"
            "\nsigns a message with your public tag\n"
            "\nArguments:\n"
            "1. \"message\"   (string, required) The message to be signed\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n" +
            HelpExampleCli("tagsignmessage", "hello. sign this message") +
            HelpExampleRpc("tagsignmessage", "hello. sign this message")
        );
    }

    std::string strMessage = params[0].get_str();

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    LOCK(cs_main);
    if (!g_connman)
    {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    CRoutingTag pubtag;
    if (!g_connman->tagstore->GetTag(g_connman->tagstore->GetCurrentPublicTagPubKey().GetID(), pubtag))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed, Tag error");
    }
    std::vector<unsigned char> vchSig;
    // TODO : look into if sign or signcompact should be used here
    // if (!pubtag.SignCompact(ss.GetHash(), vchSig))
    if (!pubtag.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue tagverifymessage(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "tagverifymessage \"ecc address\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"pubkey\"  (string, required) The base64 encoded tag pubkey to use for the signature\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see "
            "signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n" +
            HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") + "\nCreate the signature\n" +
            HelpExampleCli("signmessage", "\"BHcOxO9SxZshlmXffMFdJYuAXqusM3zVS7Ary66j5SiupLsnGeMONwmM/qG6zIEJpoGznWtmFFZ63mo5YXGWBcU=\" \"my message\"") +
            "\nVerify the signature\n" +
            HelpExampleCli("tagverifymessage", "\"BHcOxO9SxZshlmXffMFdJYuAXqusM3zVS7Ary66j5SiupLsnGeMONwmM/qG6zIEJpoGznWtmFFZ63mo5YXGWBcU=\" \"signature\" \"my message\"") +
            "\nAs json rpc\n" +
            HelpExampleRpc("tagverifymessage", "\"BHcOxO9SxZshlmXffMFdJYuAXqusM3zVS7Ary66j5SiupLsnGeMONwmM/qG6zIEJpoGznWtmFFZ63mo5YXGWBcU=\", \"signature\", \"my message\""));

    std::string strPubKey_base64 = params[0].get_str();
    std::string strSign = params[1].get_str();
    std::string strMessage = params[2].get_str();

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    bool fInvalid = false;
    std::vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CPubKey pubcompare(strPubKey_base64);
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == pubcompare.GetID());
}
