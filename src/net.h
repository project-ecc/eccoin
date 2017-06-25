// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#ifdef _MSC_VER
# include <winsock2.h>
# include <Windows.h>
#endif

#include <deque>
#include <boost/array.hpp>
#include <boost/foreach.hpp>
#include <openssl/rand.h>
#include <atomic>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include "mruset.h"
#include "network/service.h"
#include "network/node.h"
#include "network/protocol.h"
#include "network/addrman.h"
#include "transaction.h"

class CRequestTracker;
class CNode;
class CBlockIndex;

extern std::set<CNetAddr> setservAddNodeAddresses;
extern CCriticalSection cs_setservAddNodeAddresses;
extern CSemaphore *semOutbound;

inline unsigned int ReceiveBufferSize() { return 1000*GetArg("-maxreceivebuffer", 5*1000); }
inline unsigned int SendBufferSize() { return 1000*GetArg("-maxsendbuffer", 1*1000); }

bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound = NULL, const char *strDest = NULL);

void AddOneShot(std::string strDest);
bool RecvLine(SOCKET hSocket, std::string& strLine);
bool GetMyExternalIP(CNetAddr& ipRet);
void AddressCurrentlyConnected(const CService& addr);
CNode* FindNode(const CNetAddr& ip);
CNode* FindNode(const CService& ip);
CNode* FindNode(std::string addrName);
CNode* ConnectNode(CAddress addrConnect, const char *strDest = NULL);
void MapPort();
unsigned short GetListenPort();
bool BindListenPort(const CService &bindAddr, std::string& strError=REF(std::string()));
void StartNode();
bool StopNode();

/** Maximum length of strSubVer in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;

static const ServiceFlags REQUIRED_SERVICES = NODE_NETWORK;

/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;

/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;

enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // address reported by UPnP
    LOCAL_IRC,    // address reported by IRC (deprecated)
    LOCAL_HTTP,   // address reported by whatismyip.com and similar
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};

void SetLimited(enum Network net, bool fLimited = true);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr& addr);
bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
bool SeenLocal(const CService& addr);
bool IsLocal(const CService& addr);
bool IsReachable(const CNetAddr &addr);
void SetReachable(enum Network net, bool fFlag = true);


enum
{
    MSG_TX = 1,
    MSG_BLOCK = 2,
};


/** Thread types */
enum threadId
{
    THREAD_SOCKETHANDLER,
    THREAD_OPENCONNECTIONS,
    THREAD_MESSAGEHANDLER,
    THREAD_RPCLISTENER,
    THREAD_UPNP,
    THREAD_DNSSEED,
    THREAD_ADDEDCONNECTIONS,
    THREAD_DUMPADDRESS,
    THREAD_RPCHANDLER,
    THREAD_SCRYPT_MINER,
    THREAD_MINTER, //scrypt stake mining

    THREAD_MAX
};

extern bool fClient;
extern bool fDiscover;
extern bool fUseUPnP;
extern CAddress addrSeenByPeer;
extern boost::array<int, THREAD_MAX> vnThreadsRunning;
extern CAddrMan addrman;

extern std::vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern std::map<CInv, CDataStream> mapRelay;
extern std::deque<std::pair<int64_t, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;



extern int highestAskedFor;
extern bool isSynced;


inline void RelayInventory(const CInv& inv)
{
    // Put on lists to offer to the other nodes
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            std::vector<CInv> vInv;
            vInv.push_back(inv);
            LOCK(pnode->cs_vSend);
            pnode->PushMessage("inv", vInv);
        }
    }
}

void RelayTransaction(const CTransaction& tx, const uint256& hash);
void RelayTransaction(const CTransaction& tx, const uint256& hash, const CDataStream& ss);


#endif
