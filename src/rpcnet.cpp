// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net.h"
#include "bitcoinrpc.h"
#include "wallet.h"
#include "db.h"
#include "walletdb.h"

using namespace json_spirit;
using namespace std;

Value getconnectioncount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getconnectioncount\n"
            "Returns the number of connections to other nodes.");

    LOCK(cs_vNodes);
    return (int)vNodes.size();
}

static void CopyNodeStats(std::vector<CNodeStats>& vstats)
{
    vstats.clear();

    LOCK(cs_vNodes);
    vstats.reserve(vNodes.size());
    BOOST_FOREACH(CNode* pnode, vNodes) {
        CNodeStats stats;
        pnode->copyStats(stats);
        vstats.push_back(stats);
    }
}

Value getpeerinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpeerinfo\n"
            "Returns data about each connected network node.");

    vector<CNodeStats> vstats;
    CopyNodeStats(vstats);

    Array ret;

    BOOST_FOREACH(const CNodeStats& stats, vstats) {
        Object obj;

        obj.push_back(Pair_Type("addr", stats.addrName));
        obj.push_back(Pair_Type("services", strprintf("%llx", stats.nServices)));
        obj.push_back(Pair_Type("lastsend", (boost::int64_t)stats.nLastSend));
        obj.push_back(Pair_Type("lastrecv", (boost::int64_t)stats.nLastRecv));
        obj.push_back(Pair_Type("conntime", (boost::int64_t)stats.nTimeConnected));
        obj.push_back(Pair_Type("version", stats.nVersion));
        obj.push_back(Pair_Type("subver", stats.strSubVer));
        obj.push_back(Pair_Type("inbound", stats.fInbound));
        obj.push_back(Pair_Type("startingheight", stats.nStartingHeight));
        obj.push_back(Pair_Type("banscore", stats.nMisbehavior));

        ret.push_back(obj);
    }

    return ret;
}
