/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <stdint.h>
#include <thread>

#include "addrdb.h"
#include "amount.h"
#include "bloom.h"
#include "compat.h"
#include "crypto/hash.h"
#include "limitedmap.h"
#include "net/addrman.h"
#include "net/netbase.h"
#include "net/protocol.h"
#include "networks/netman.h"
#include "random.h"
#include "streams.h"
#include "sync.h"
#include "threadgroup.h"
#include "uint256.h"

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include <boost/filesystem/path.hpp>
#include <boost/signals2/signal.hpp>


/** Time between pings automatically sent out for latency probing and keepalive
 * (in seconds). */
static const int PING_INTERVAL = 2 * 60;
/** Time after which to disconnect, after waiting for a ping response (or
 * inactivity). */
static const int TIMEOUT_INTERVAL = 20 * 60;
/** Run the feeler connection loop once every 2 minutes or 120 seconds. **/
static const int FEELER_INTERVAL = 120;
/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = 50000;
/** The maximum number of new addresses to accumulate before announcing. */
static const unsigned int MAX_ADDR_TO_SEND = 1000;
/** Maximum length of incoming protocol messages (no message over 32 MB is
 * currently acceptable). */
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 32 * 1000 * 1000;
/** Maximum length of strSubVer in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;
/** The maximum number of peer connections to maintain. */
static const unsigned int DEFAULT_MAX_PEER_CONNECTIONS = 125;
/** Maximum number of automatic outgoing nodes */
static const int MAX_OUTBOUND_CONNECTIONS = 75;
/** Maximum number of addnode outgoing nodes */
static const int MAX_ADDNODE_CONNECTIONS = 16;
/** -listen default */
static const bool DEFAULT_LISTEN = true;
/** -upnp default */
#ifdef USE_UPNP
static const bool DEFAULT_UPNP = USE_UPNP;
#else
static const bool DEFAULT_UPNP = false;
#endif
/** The maximum number of entries in mapAskFor */
static const size_t MAPASKFOR_MAX_SZ = MAX_INV_SZ;
/** The maximum number of entries in setAskFor (larger due to getdata latency)*/
static const size_t SETASKFOR_MAX_SZ = 2 * MAX_INV_SZ;
/** The default for -maxuploadtarget. 0 = Unlimited */
static const uint64_t DEFAULT_MAX_UPLOAD_TARGET = 0;
/** The default timeframe for -maxuploadtarget. 1 day. */
static const uint64_t MAX_UPLOAD_TIMEFRAME = 60 * 60 * 24;
/** Default for blocks only*/
static const bool DEFAULT_BLOCKSONLY = false;

// Force DNS seed use ahead of UAHF fork, to ensure peers are found
// as long as seeders are working.
// TODO: Change this back to false after the forked network is stable.
static const bool DEFAULT_FORCEDNSSEED = true;
static const size_t DEFAULT_MAXRECEIVEBUFFER = 5 * 1000;
static const size_t DEFAULT_MAXSENDBUFFER = 1 * 1000;

static const ServiceFlags REQUIRED_SERVICES = ServiceFlags(NODE_NETWORK);

// Default 24-hour ban.
// NOTE: When adjusting this, update rpcnet:setban's help ("24h")
static const unsigned int DEFAULT_MISBEHAVING_BANTIME = 60 * 60 * 24;

/** Subversion as sent to the P2P network in `version` messages */
extern std::string strSubVersion;

extern CNetworkManager *pnetMan;

typedef int64_t NodeId;
// Command, total bytes
typedef std::map<std::string, uint64_t> mapMsgCmdSize;

struct AddedNodeInfo
{
    std::string strAddedNode;
    CService resolvedAddress;
    bool fConnected;
    bool fInbound;
};

class CTransaction;
class CNodeStats;
class CClientUIInterface;


class CNetMessage
{
private:
    mutable CHash256 hasher;
    mutable uint256 data_hash;

public:
    // Parsing header (false) or data (true)
    bool in_data;

    // Partially received header.
    CDataStream hdrbuf;
    // Complete header.
    CMessageHeader hdr;
    unsigned int nHdrPos;

    // Received message data.
    CDataStream vRecv;
    unsigned int nDataPos;

    // Time (in microseconds) of message receipt.
    int64_t nTime;

    CNetMessage(const CMessageHeader::MessageMagic &pchMessageStartIn, int nTypeIn, int nVersionIn)
        : hdrbuf(nTypeIn, nVersionIn), hdr(pchMessageStartIn), vRecv(nTypeIn, nVersionIn)
    {
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        nTime = 0;
    }

    bool complete() const
    {
        if (!in_data)
        {
            return false;
        }

        return (hdr.nMessageSize == nDataPos);
    }

    const uint256 &GetMessageHash() const;

    void SetVersion(int nVersionIn)
    {
        hdrbuf.SetVersion(nVersionIn);
        vRecv.SetVersion(nVersionIn);
    }

    int readHeader(const char *pch, unsigned int nBytes);
    int readData(const char *pch, unsigned int nBytes);
};

/** Information about a peer */
class CNode
{
    friend class CConnman;

public:
    // socket
    std::atomic<ServiceFlags> nServices;
    // Services expected from a peer, otherwise it will be disconnected
    ServiceFlags nServicesExpected;
    SOCKET hSocket;
    // Total size of all vSendMsg entries.
    size_t nSendSize;
    // Offset inside the first vSendMsg already sent.
    size_t nSendOffset;
    uint64_t nSendBytes;
    // Total bytes sent and received
    uint64_t nActivityBytes;
    std::deque<std::vector<uint8_t> > vSendMsg;
    CCriticalSection cs_vSend;
    CCriticalSection cs_hSocket;
    CCriticalSection cs_vRecv;

    CCriticalSection cs_vProcessMsg;
    std::list<CNetMessage> vProcessMsg;
    size_t nProcessQueueSize;

    CCriticalSection cs_sendProcessing;

    CCriticalSection csRecvGetData;
    std::deque<CInv> vRecvGetData;
    uint64_t nRecvBytes;
    std::atomic<int> nRecvVersion;

    std::atomic<int64_t> nLastSend;
    std::atomic<int64_t> nLastRecv;
    const int64_t nTimeConnected;
    std::atomic<int64_t> nTimeOffset;
    const CAddress addr;
    std::atomic<int> nVersion;
    // strSubVer is whatever byte array we read from the wire. However, this
    // field is intended to be printed out, displayed to humans in various forms
    // and so on. So we sanitize it and store the sanitized version in
    // cleanSubVer. The original should be used when dealing with the network or
    // wire types and the cleaned string used when displayed or logged.
    std::string strSubVer, cleanSubVer;
    // Used for both cleanSubVer and strSubVer.
    CCriticalSection cs_SubVer;
    // This peer can bypass DoS banning.
    bool fWhitelisted;
    // If true this node is being used as a short lived feeler.
    bool fFeeler;
    bool fOneShot;
    bool fAddnode;
    bool fClient;
    const bool fInbound;
    std::atomic_bool fSuccessfullyConnected;
    std::atomic_bool fDisconnect;
    // We use fRelayTxes for two purposes -
    // a) it allows us to not relay tx invs before receiving the peer's version
    // message.
    // b) the peer may tell us in its version message that we should not relay
    // tx invs unless it loads a bloom filter.

    // protected by cs_filter
    bool fRelayTxes;
    bool fSentAddr;
    CSemaphoreGrant grantOutbound;
    CCriticalSection cs_filter;
    CBloomFilter *pfilter;
    std::atomic<int> nRefCount;
    const NodeId id;

    const uint64_t nKeyedNetGroup;
    std::atomic_bool fPauseRecv;
    std::atomic_bool fPauseSend;

protected:
    mapMsgCmdSize mapSendBytesPerMsgCmd;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;

public:
    std::atomic<int> nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    CRollingBloomFilter addrKnown;
    bool fGetAddr;
    std::set<uint256> setKnown;
    int64_t nNextAddrSend;
    int64_t nNextLocalAddrSend;

    // Inventory based relay.
    CRollingBloomFilter filterInventoryKnown;
    // Set of transaction ids we still have to announce. They are sorted by the
    // mempool before relay, so the order is not important.
    std::set<uint256> setInventoryTxToSend;
    // List of block ids we still have announce. There is no final sorting
    // before sending, as they are always sent immediately and in the order
    // requested.
    std::vector<uint256> vInventoryBlockToSend;
    CCriticalSection cs_inventory;
    std::set<uint256> setAskFor;
    std::multimap<int64_t, CInv> mapAskFor;
    int64_t nNextInvSend;
    // Used for headers announcements - unfiltered blocks to relay. Also
    // protected by cs_inventory.
    std::vector<uint256> vBlockHashesToAnnounce;
    // Used for BIP35 mempool sending, also protected by cs_inventory.
    bool fSendMempool;

    // Last time a "MEMPOOL" request was serviced.
    std::atomic<int64_t> timeLastMempoolReq;

    // Block and TXN accept times
    std::atomic<int64_t> nLastBlockTime;
    std::atomic<int64_t> nLastTXTime;

    // Ping time measurement:
    // The pong reply we're expecting, or 0 if no pong expected.
    std::atomic<uint64_t> nPingNonceSent;
    // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
    std::atomic<int64_t> nPingUsecStart;
    // Last measured round-trip time.
    std::atomic<int64_t> nPingUsecTime;
    // Best measured round-trip time.
    std::atomic<int64_t> nMinPingUsecTime;
    // Whether a ping is requested.
    std::atomic<bool> fPingQueued;

    CNode(NodeId id,
        ServiceFlags nLocalServicesIn,
        SOCKET hSocketIn,
        const CAddress &addrIn,
        uint64_t nKeyedNetGroupIn,
        uint64_t nLocalHostNonceIn,
        const std::string &addrNameIn = "",
        bool fInboundIn = false);
    ~CNode();

private:
    CNode(const CNode &);
    void operator=(const CNode &);

    // Services offered to this peer
    const ServiceFlags nLocalServices;
    int nSendVersion;
    // Used only by SocketHandler thread.
    std::list<CNetMessage> vRecvMsg;

    mutable CCriticalSection cs_addrName;
    std::string addrName;

    CService addrLocal;
    mutable CCriticalSection cs_addrLocal;

public:
    NodeId GetId() const { return id; }
    int GetRefCount()
    {
        assert(nRefCount >= 0);
        return nRefCount;
    }

    bool ReceiveMsgBytes(const char *pch, unsigned int nBytes, bool &complete);

    void SetRecvVersion(int nVersionIn) { nRecvVersion = nVersionIn; }
    int GetRecvVersion() { return nRecvVersion; }
    void SetSendVersion(int nVersionIn);
    int GetSendVersion() const;

    CService GetAddrLocal() const;
    //! May not be called more than once
    void SetAddrLocal(const CService &addrLocalIn);

    CNode *AddRef()
    {
        nRefCount++;
        return this;
    }

    void Release() { nRefCount--; }
    void AddAddressKnown(const CAddress &_addr) { addrKnown.insert(_addr.GetKey()); }
    void PushAddress(const CAddress &_addr, FastRandomContext &insecure_rand)
    {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (_addr.IsValid() && !addrKnown.contains(_addr.GetKey()))
        {
            if (vAddrToSend.size() >= MAX_ADDR_TO_SEND)
            {
                vAddrToSend[insecure_rand.randrange(vAddrToSend.size())] = _addr;
            }
            else
            {
                vAddrToSend.push_back(_addr);
            }
        }
    }

    void AddInventoryKnown(const CInv &inv)
    {
        LOCK(cs_inventory);
        filterInventoryKnown.insert(inv.hash);
    }

    void PushInventory(const CInv &inv)
    {
        LOCK(cs_inventory);
        if (inv.type == MSG_TX)
        {
            if (!filterInventoryKnown.contains(inv.hash))
            {
                setInventoryTxToSend.insert(inv.hash);
            }
        }
        else if (inv.type == MSG_BLOCK)
        {
            vInventoryBlockToSend.push_back(inv.hash);
        }
    }

    void PushBlockHash(const uint256 &hash)
    {
        LOCK(cs_inventory);
        vBlockHashesToAnnounce.push_back(hash);
    }

    void AskFor(const CInv &inv);

    void CloseSocketDisconnect();

    void copyStats(CNodeStats &stats);

    ServiceFlags GetLocalServices() const { return nLocalServices; }
    std::string GetAddrName() const;
    //! Sets the addrName only if it was not previously set
    void MaybeSetAddrName(const std::string &addrNameIn);
};

class CConnman
{
public:
    enum NumConnections
    {
        CONNECTIONS_NONE = 0,
        CONNECTIONS_IN = (1U << 0),
        CONNECTIONS_OUT = (1U << 1),
        CONNECTIONS_ALL = (CONNECTIONS_IN | CONNECTIONS_OUT),
    };

    CConnman(uint64_t seed0, uint64_t seed1);
    ~CConnman();
    bool Start(std::string &strNodeError);
    void Stop();
    void Interrupt();
    bool BindListenPort(const CService &bindAddr, std::string &strError, bool fWhitelisted = false);
    bool OpenNetworkConnection(const CAddress &addrConnect,
        bool fCountFailure,
        CSemaphoreGrant *grantOutbound = nullptr,
        const char *strDest = nullptr,
        bool fOneShot = false,
        bool fFeeler = false,
        bool fAddnode = false);

    bool ForNode(NodeId id, std::function<bool(CNode *pnode)> func);

    template <typename... Args>
    void PushMessage(CNode *pnode, std::string sCommand, Args &&... args)
    {
        std::vector<uint8_t> data;
        CVectorWriter{SER_NETWORK, pnode->GetSendVersion(), data, 0, std::forward<Args>(args)...};
        size_t nMessageSize = data.size();
        size_t nTotalSize = nMessageSize + CMessageHeader::HEADER_SIZE;
        LogPrint("net", "sending %s (%d bytes) peer=%d\n", SanitizeString(sCommand.c_str()), nMessageSize, pnode->id);

        std::vector<uint8_t> serializedHeader;
        serializedHeader.reserve(CMessageHeader::HEADER_SIZE);
        uint256 hash = Hash(data.data(), data.data() + nMessageSize);
        CMessageHeader hdr(pnetMan->getActivePaymentNetwork()->MessageStart(), sCommand.c_str(), nMessageSize);
        memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

        CVectorWriter{SER_NETWORK, MIN_PROTO_VERSION, serializedHeader, 0, hdr};

        size_t nBytesSent = 0;
        {
            LOCK(pnode->cs_vSend);
            bool optimisticSend(pnode->vSendMsg.empty());

            // log total amount of bytes per command
            pnode->mapSendBytesPerMsgCmd[sCommand] += nTotalSize;
            pnode->nSendSize += nTotalSize;

            if (pnode->nSendSize > nSendBufferMaxSize)
            {
                pnode->fPauseSend = true;
            }
            pnode->vSendMsg.push_back(std::move(serializedHeader));
            if (nMessageSize)
            {
                pnode->vSendMsg.push_back(std::move(data));
            }
            const char *strCommand = sCommand.c_str();
            if (strcmp(strCommand, NetMsgType::PING) != 0 && strcmp(strCommand, NetMsgType::PONG) != 0 &&
                strcmp(strCommand, NetMsgType::ADDR) != 0 && strcmp(strCommand, NetMsgType::VERSION) != 0 &&
                strcmp(strCommand, NetMsgType::VERACK) != 0 && strcmp(strCommand, NetMsgType::INV) != 0)
            {
                pnode->nActivityBytes += nMessageSize;
            }

            // If write queue empty, attempt "optimistic write"
            if (optimisticSend == true)
            {
                nBytesSent = SocketSendData(pnode);
            }
        }
        if (nBytesSent)
        {
            RecordBytesSent(nBytesSent);
        }
    }

    template <typename Callable>
    void ForEachNode(Callable &&func)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                func(node);
        }
    };

    template <typename Callable>
    void ForEachNode(Callable &&func) const
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                func(node);
        }
    };

    template <typename Callable, typename CallableAfter>
    void ForEachNodeThen(Callable &&pre, CallableAfter &&post)
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                pre(node);
        }
        post();
    };

    template <typename Callable, typename CallableAfter>
    void ForEachNodeThen(Callable &&pre, CallableAfter &&post) const
    {
        LOCK(cs_vNodes);
        for (auto &&node : vNodes)
        {
            if (NodeFullyConnected(node))
                pre(node);
        }
        post();
    };

    // Addrman functions
    size_t GetAddressCount() const;
    void SetServices(const CService &addr, ServiceFlags nServices);
    void MarkAddressGood(const CAddress &addr);
    void AddNewAddress(const CAddress &addr, const CAddress &addrFrom, int64_t nTimePenalty = 0);
    void AddNewAddresses(const std::vector<CAddress> &vAddr, const CAddress &addrFrom, int64_t nTimePenalty = 0);
    std::vector<CAddress> GetAddresses();
    void AddressCurrentlyConnected(const CService &addr);

    // Denial-of-service detection/prevention. The idea is to detect peers that
    // are behaving badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network way.
    // IMPORTANT: There should be nothing I can give a node that it will forward
    // on that will make that node's peers drop it. If there is, an attacker can
    // isolate a node and/or try to split the network. Dropping a node for
    // sending stuff that is invalid now but might be valid in a later version
    // is also dangerous, because it can cause a network split between nodes
    // running old code and nodes running new code.
    void Ban(const CNetAddr &netAddr, const BanReason &reason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    void Ban(const CSubNet &subNet, const BanReason &reason, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    // Needed for unit testing.
    void ClearBanned();
    bool IsBanned(CNetAddr ip);
    bool IsBanned(CSubNet subnet);
    bool Unban(const CNetAddr &ip);
    bool Unban(const CSubNet &ip);
    void GetBanned(banmap_t &banmap);
    void SetBanned(const banmap_t &banmap);

    void AddOneShot(const std::string &strDest);

    bool AddNode(const std::string &node);
    bool RemoveAddedNode(const std::string &node);
    std::vector<AddedNodeInfo> GetAddedNodeInfo();

    size_t GetNodeCount(NumConnections num);
    void GetNodeStats(std::vector<CNodeStats> &vstats);
    bool DisconnectNode(const std::string &node);
    bool DisconnectNode(NodeId id);

    unsigned int GetSendBufferSize() const;

    void AddWhitelistedRange(const CSubNet &subnet);

    ServiceFlags GetLocalServices() const;

    //! set the max outbound target in bytes.
    void SetMaxOutboundTarget(uint64_t limit);
    uint64_t GetMaxOutboundTarget();

    //! set the timeframe for the max outbound target.
    void SetMaxOutboundTimeframe(uint64_t timeframe);
    uint64_t GetMaxOutboundTimeframe();

    //! check if the outbound target is reached.
    // If param historicalBlockServingLimit is set true, the function will
    // response true if the limit for serving historical blocks has been
    // reached.
    bool OutboundTargetReached(bool historicalBlockServingLimit);

    //! response the bytes left in the current max outbound cycle
    // in case of no limit, it will always response 0
    uint64_t GetOutboundTargetBytesLeft();

    //! response the time in second left in the current max outbound cycle
    // in case of no limit, it will always response 0
    uint64_t GetMaxOutboundTimeLeftInCycle();

    uint64_t GetTotalBytesRecv();
    uint64_t GetTotalBytesSent();

    void SetBestHeight(int height);
    int GetBestHeight() const;

    /** Get a unique deterministic randomizer. */
    CSipHasher GetDeterministicRandomizer(uint64_t id) const;

    unsigned int GetReceiveFloodSize() const;

private:
    struct ListenSocket
    {
        SOCKET socket;
        bool whitelisted;

        ListenSocket(SOCKET socket_, bool whitelisted_) : socket(socket_), whitelisted(whitelisted_) {}
    };

    void ThreadOpenAddedConnections();
    void ProcessOneShot();
    void ThreadOpenConnections();
    void ThreadMessageHandler();
    void AcceptConnection(const ListenSocket &hListenSocket);
    void ThreadSocketHandler();
    void ThreadDNSAddressSeed();

    uint64_t CalculateKeyedNetGroup(const CAddress &ad) const;

    CNode *FindNode(const CNetAddr &ip);
    CNode *FindNode(const CSubNet &subNet);
    CNode *FindNode(const std::string &addrName);
    CNode *FindNode(const CService &addr);

    bool AttemptToEvictConnection();
    CNode *ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure);
    bool IsWhitelistedRange(const CNetAddr &addr);

    void DeleteNode(CNode *pnode);

    NodeId GetNewNodeId();

    size_t SocketSendData(CNode *pnode) const;
    //! check is the banlist has unwritten changes
    bool BannedSetIsDirty();
    //! set the "dirty" flag for the banlist
    void SetBannedSetDirty(bool dirty = true);
    //! clean unused entries (if bantime has expired)
    void SweepBanned();
    void DumpAddresses();
    void _DumpData();
    void DumpData(int64_t seconds_between_runs);
    void DumpBanlist();

    // Network stats
    void RecordBytesRecv(uint64_t bytes);
    void RecordBytesSent(uint64_t bytes);

    // Whether the node should be passed out in ForEach* callbacks
    static bool NodeFullyConnected(const CNode *pnode);

    // Network usage totals
    CCriticalSection cs_totalBytesRecv;
    CCriticalSection cs_totalBytesSent;
    uint64_t nTotalBytesRecv;
    uint64_t nTotalBytesSent;

    // outbound limit & stats
    uint64_t nMaxOutboundTotalBytesSentInCycle;
    uint64_t nMaxOutboundCycleStartTime;
    uint64_t nMaxOutboundLimit;
    uint64_t nMaxOutboundTimeframe;

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    std::vector<CSubNet> vWhitelistedRange;
    CCriticalSection cs_vWhitelistedRange;

    unsigned int nSendBufferMaxSize;
    unsigned int nReceiveFloodSize;

    std::vector<ListenSocket> vhListenSocket;
    banmap_t setBanned;
    CCriticalSection cs_setBanned;
    bool setBannedIsDirty;
    bool fAddressesInitialized;
    CAddrMan addrman;
    std::deque<std::string> vOneShots;
    CCriticalSection cs_vOneShots;
    std::vector<std::string> vAddedNodes;
    CCriticalSection cs_vAddedNodes;
    std::vector<CNode *> vNodes;
    std::list<CNode *> vNodesDisconnected;
    mutable CCriticalSection cs_vNodes;
    std::atomic<NodeId> nLastNodeId;

    /** Services this instance offers */
    ServiceFlags nLocalServices;

    /** Services this instance cares about */
    ServiceFlags nRelevantServices;

    std::unique_ptr<CSemaphore> semOutbound;
    std::unique_ptr<CSemaphore> semAddnode;
    int nMaxConnections;
    int nMaxOutbound;
    int nMaxAddnode;
    int nMaxFeeler;
    std::atomic<int> nBestHeight;

    /** SipHasher seeds for deterministic randomness */
    const uint64_t nSeed0, nSeed1;

    std::atomic<bool> interruptNet;
    thread_group netThreads;
};

extern std::unique_ptr<CConnman> g_connman;

void Discover(thread_group &threadGroup);
void MapPort(bool fUseUPnP);
unsigned short GetListenPort();
bool BindListenPort(const CService &bindAddr, std::string &strError, bool fWhitelisted = false);

struct CombinerAll
{
    typedef bool result_type;

    template <typename I>
    bool operator()(I first, I last) const
    {
        while (first != last)
        {
            if (!(*first))
            {
                return false;
            }
            ++first;
        }
        return true;
    }
};

// Signals for message handling
struct CNodeSignals
{
    boost::signals2::signal<bool(CNode *, CConnman &), CombinerAll> ProcessMessages;
    boost::signals2::signal<bool(CNode *, CConnman &), CombinerAll> SendMessages;
    boost::signals2::signal<void(CNode *, CConnman &)> InitializeNode;
    boost::signals2::signal<void(NodeId, bool &)> FinalizeNode;
};

CNodeSignals &GetNodeSignals();

enum
{
    // unknown
    LOCAL_NONE,
    // address a local interface listens on
    LOCAL_IF,
    // address explicit bound to
    LOCAL_BIND,
    // address reported by UPnP
    LOCAL_UPNP,
    // address explicitly specified (-externalip=)
    LOCAL_MANUAL,

    LOCAL_MAX
};

bool IsPeerAddrLocalGood(CNode *pnode);
void AdvertiseLocal(CNode *pnode);
void SetLimited(enum Network net, bool fLimited = true);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr &addr);
bool AddLocal(const CService &addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr &addr, int nScore = LOCAL_NONE);
bool RemoveLocal(const CService &addr);
bool SeenLocal(const CService &addr);
bool IsLocal(const CService &addr);
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = nullptr);
bool IsReachable(enum Network net);
bool IsReachable(const CNetAddr &addr);
CAddress GetLocalAddress(const CNetAddr *paddrPeer, ServiceFlags nLocalServices);

extern bool fDiscover;
extern bool fListen;
extern bool fRelayTxes;

extern limitedmap<uint256, int64_t> mapAlreadyAskedFor;

struct LocalServiceInfo
{
    int nScore;
    int nPort;
};

extern CCriticalSection cs_mapLocalHost;
extern std::map<CNetAddr, LocalServiceInfo> mapLocalHost;

class CNodeStats
{
public:
    NodeId nodeid;
    ServiceFlags nServices;
    bool fRelayTxes;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    std::string addrName;
    int nVersion;
    std::string cleanSubVer;
    bool fInbound;
    bool fAddnode;
    int nStartingHeight;
    uint64_t nSendBytes;
    mapMsgCmdSize mapSendBytesPerMsgCmd;
    uint64_t nRecvBytes;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;
    bool fWhitelisted;
    double dPingTime;
    double dPingWait;
    double dMinPing;
    std::string addrLocal;
    CAddress addr;
};

// Exception-safe class for holding a reference to a CNode
class CNodeRef
{
    void AddRef()
    {
        if (_pnode)
            _pnode->AddRef();
    }

    void Release()
    {
        if (_pnode)
        {
            // Make the noderef null before releasing, to ensure a user can't get freed memory from us
            CNode *tmp = _pnode;
            _pnode = nullptr;
            tmp->Release();
        }
    }

public:
    CNodeRef(CNode *pnode = nullptr) : _pnode(pnode) { AddRef(); }
    CNodeRef(const CNodeRef &other) : _pnode(other._pnode) { AddRef(); }
    ~CNodeRef() { Release(); }
    CNode &operator*() const { return *_pnode; };
    CNode *operator->() const { return _pnode; };
    // Returns true if this reference is not null
    explicit operator bool() const { return _pnode; }
    // Access the raw pointer
    CNode *get() const { return _pnode; }
    // Assignment -- destroys any reference to the current node and adds a ref to the new one
    CNodeRef &operator=(CNode *pnode)
    {
        if (pnode != _pnode)
        {
            Release();
            _pnode = pnode;
            AddRef();
        }
        return *this;
    }
    // Assignment -- destroys any reference to the current node and adds a ref to the new one
    CNodeRef &operator=(const CNodeRef &other) { return operator=(other._pnode); }
private:
    CNode *_pnode;
};

// Connection Slot mitigation - used to track connection attempts and evictions
struct ConnectionHistory
{
    double nConnections; // number of connection attempts made within 1 minute
    int64_t nLastConnectionTime; // the time the last connection attempt was made

    double nEvictions; // number of times a connection was de-prioritized and disconnected in last 30 minutes
    int64_t nLastEvictionTime; // the time the last eviction occurred.
};

/**
 * Return a timestamp in the future (in microseconds) for exponentially
 * distributed events.
 */
int64_t PoissonNextSend(int64_t nNow, int average_interval_seconds);

#endif // BITCOIN_NET_H
