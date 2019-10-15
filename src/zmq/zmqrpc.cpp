// This file is part of the Eccoin project
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/rpcserver.h"
#include "util/logger.h"
#include "util/utilstrencodings.h"
#include <univalue.h>

#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqnotificationinterface.h>

#include <univalue.h>

UniValue getzmqnotifications(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error("getzmqnotifications\n"
                                 "\nReturns information about the active ZeroMQ notifications.\n"
                                 "\nResult:\n"
                                 "[\n"
                                 "  {                        (json object)\n"
                                 "    \"type\": \"pubhashtx\",   (string) Type of notification\n"
                                 "    \"address\": \"...\",      (string) Address of the publisher\n"
                                 "  },\n"
                                 "  ...\n"
                                 "]\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("getzmqnotifications", "") + HelpExampleRpc("getzmqnotifications", ""));

    UniValue ret(UniValue::VARR);
    if (g_zmq_notification_interface != NULL) {
        for (const auto* n : g_zmq_notification_interface->GetActiveNotifiers()) {
            UniValue obj(UniValue::VOBJ);
            obj.push_back(Pair("type", n->GetType()));
            obj.push_back(Pair("address", n->GetAddress()));
            ret.push_back(obj);
        }
    }

    return ret;
}