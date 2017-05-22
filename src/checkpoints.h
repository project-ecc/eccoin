// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include <map>

#include "net.h"
#include "util.h"

#define CHECKPOINT_MAX_SPAN (60 * 60) // max 1 hour before latest block

#ifdef WIN32
#undef STRICT
#undef PERMISSIVE
#undef ADVISORY
#endif

class uint256;
class CBlockIndex;
class CSyncCheckpoint;

typedef std::map<int, uint256> MapCheckpoints;

//
// What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
//
static MapCheckpoints mapCheckpoints = boost::assign::map_list_of
        (     0, uint256("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1"))
        (     1, uint256("0x00000762d19a3a38458e73de6c937fd483f17bd75f55d7fe4e95713f51d6b816"))
        (     2, uint256("0x00000ea50ea0cae64779ff4bb4a0ee94841e2ee20642641a062cbdd342e0a3c5"))
        (     3, uint256("0x00000513cc6f4bec8d7e7bd0ded854200b6c784c8c830a3e4fd0cccc2cb9e58c"))
        (  1000, uint256("0x000000000df3f7a5f719c247782d7a43d75186ebc043341e2668320f9d940bcd"))
        ( 10000, uint256("0x00000000076d45a9579c879d46354dd81eeba7060a9a065e13c9dd1c28f474d1"))
        ( 23920, uint256("0x000000000331540c766c4ac667a6fbc65ff93f5a30fbb0c6822986885b1b56c0"))
        ( 36918, uint256("0x0000000001353725582b099cdd3c89933bbd08a17ace464fba935ecfc41572ef"))
        ( 50000, uint256("0x0000000001c770384cd12a74eb5456358425fc6a94a250c3466aaa2ca7460131"))
        ( 86401, uint256("0x51bb1ac3ffd009c12791b9d4320dec0ba69e15c8b6d03d17889b0c09fb5b05a4"))
        ( 86402, uint256("0xa9f3141e571231e02b4fb649370af6173e1a80a9e0d21aa8859bd17ce1260a05"))
        ( 86403, uint256("0xf6c11aadca44fce2390107e229d4d0d70f7cf64266b959672711c68e0f411af5"))
        ( 86759, uint256("0x5c6ed2e23ccc27d59a0659a9a32a4c0ca97d829249277c6a35918f4ec94b1748"))
        ( 86761, uint256("0xca305a45c9f8a89c050f004d0438b38f190fe6bfe51128f0c3e864ddcf2c765c"))
        ( 86901, uint256("0xe769d38b7e140267b688f9d9cc6b58d38185427facb6a1aa719db60a0d54f3f7"))
        ( 87000, uint256("0xbb069ba59aa5a6acc68413ef7c2d0c009b061daf160edf958738d197a059f11d"))
        ( 87101, uint256("0x1ffbfd2a70e626d5f848775851e6f89bee6f2225ed78131b16f9547449d2e2ee"))
        ( 96500, uint256("0x13f0755045a3ae90d33c4bcf6ba1581025fc6e0caf46f7624063cb59dcc3d27c"))
        (100000, uint256("0x28a483386650a188c3346fd5e329e2c8cc137cf3557547e8525f5cdea601501a"))
        (136500, uint256("0x7e4ec82a165762e8a324038ef1cdd0b83e603f4737ae6f9e5967b13b8b6ace5c"))
        (150000, uint256("0xfee6d00910e8d0aa2f0ca8a447b4de366a12f9df2521f77c5a97a5ae0af8834e"))
        (185000, uint256("0xce904504a0df58944c6a633b739abcec3bbb256b510a616b465c24525d564828"))
        (197712, uint256("0x7576d0f370b1efdce01075a9491fb8d2f98af485f78d170196270f1eb156ee40"))
        (200000, uint256("0x1f1ea51aee8a7456655e31857c7cd4a9f494556438485abd4c60d86cacf24b44"))
        (205000, uint256("0x9e4528bc818bb1ee2cdf44ba7805e88b4fc85bbf496516f35d4d642c6812503e"))
        (209762, uint256("0x49448f382f9ec8f126542244573e7349c7b07db0cbdc2ab8326942cbfff603b3"))
        (209786, uint256("0x28558eedf7f5c049e9f2ea61da270fffc5b50310aafb29c7595840784e8b1d61"))
        (215650, uint256("0xd7fb37df6be4bf2c5c9ea47ba4a14f9af35c326cd225122b03f61b74d1283d09"))
        (215690, uint256("0x8af4d5450c238460a4775b19c94872eaf5664657f702bef53576bc9f77af319d"))
        (220504, uint256("0x5781d160a46a6631a21e62a9a67932d0f9b8636c8f5241973b076db3854de405"))
        (221000, uint256("0x51cd22cde58a3738e851f155a282b4624d3e18e84fbcb02de5006029dec8f7e3"))
        (233855, uint256("0x77c1312f0b4ba0fc34cb7a0f3472012739bbd22c317add69edaa4908e83b00eb"))
        (236850, uint256("0x139203f72c943433880c4f8d3581a4cb7ee0877f341639cd4c7810edc7fc7d80"))
        (237000, uint256("0x70fdb4f39e571afff137c7bd40c4df98ccab32cec1d305074bac9fca30754bc0"))
        (241130, uint256("0xdd900777cb9e2ea2cae0bf410ce2f2484a415c7bf7af59d9492868195583e3b2"))
        (242150, uint256("0xba96de8da95ac53cedc7fd0cd3c17b32f5d3a04f33a544060606c095b28bf4c1"))
        (300000, uint256("0x2c654dfa9f1ab51a64509910b1f053fc20d572022480814988c36f042cb3010b"))
        (350000, uint256("0xfdb1df53f4365d494d9fa54247a533cbfcd9b6992491f40c8ccfeed454932a70"))
        (400000, uint256("0xc04d360938d5ff66294100a10424f7e284abe76d117f28460e16752edeb03444"))
        (435000, uint256("0x801a211aa479129e42554bc812d624e585e1b0dd608e23b1a7f87a9d14e7fdec"))
        (450000, uint256("0x53e21a2574ff6acc0f31640c4058554dde2fe8972ec72867403e8b88e9ba1bc6"))
        (500000, uint256("0x779f22407cf9fa0adb8a361918ccf249ef913070ce368070c1ac5063005e3e3c"))
        (550000, uint256("0xf340b738c21c0a9b6b2eff0f40d9ab3fca9830d8597131680cd5a2615594cfb0"))
        (600000, uint256("0x589fc3d25c15caaa468dc8b4249e1cbb6ea18368897bd3b1d80f1404486e3783"))
        (650000, uint256("0xc28634f7211ff0582dfe8df1849711a9bd7815005e59dff0059a20876c465f51"))
        (675000, uint256("0xe1aca23bd72ad9d153767272f43d33a0542d2a61a78e281341d0f12cd0521024"))
        (675500, uint256("0x26ccdf8bcb1a50ecef8f507de74ff030789aa1b52491fc4a4de4e4679d53a398"))
        (687345, uint256("0xae2e43c35a3346fa798a0a356ca7a4bce57885ee64e4319295f7f3b7210944f1"))
        (700000, uint256("0x0ab361e8acd391c6b5e726eb4704dd8d60e2e3b3f8856e2f7d6373c9a3e0da36"))
        (702950, uint256("0x26d2cd7b13f1aaa34ffc379696d0e5b14c2ddf8ef2c2c78348fec23f8b55e8ff"))
        (1030250,uint256("0x434ee5c39b6ba186d66cbfaaa8004910b3556726f990b9f33bb48b9fc280c5de"))

            ;

// TestNet has no checkpoints
static MapCheckpoints mapCheckpointsTestnet = boost::assign::map_list_of
        ( 0, uint256("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1"))
        ;

extern uint256 hashSyncCheckpoint;
extern CSyncCheckpoint checkpointMessage;
extern uint256 hashInvalidCheckpoint;
extern CCriticalSection cs_hashSyncCheckpoint;
bool WriteSyncCheckpoint(const uint256& hashCheckpoint);

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
class Checkpoints
{

    bool IsMatureSyncCheckpoint();

public:
    /** Checkpointing mode */
    enum CPMode
    {
        // Scrict checkpoints policy, perform conflicts verification and resolve conflicts
        STRICT_X = 0,
        // Advisory checkpoints policy, perform conflicts verification but don't try to resolve them
        ADVISORY = 1,
        // Permissive checkpoints policy, don't perform any checking
        PERMISSIVE = 2
    };
    bool SetCheckpointPrivKey(std::string strPrivKey);
    enum CPMode CheckpointsMode;

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex);
    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();
    CBlockIndex* GetLastSyncCheckpoint();
    bool WantedByPendingSyncCheckpoint(uint256 hashBlock);
    bool ResetSyncCheckpoint();
    void AskForPendingSyncCheckpoint(CNode* pfrom);
    uint256 AutoSelectSyncCheckpoint();
    bool SendSyncCheckpoint(uint256 hashCheckpoint);
    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);
    bool AcceptPendingSyncCheckpoint();
    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev);


};

// ppcoin: synchronized checkpoint
class CUnsignedSyncCheckpoint
{
public:
    int nVersion;
    uint256 hashCheckpoint;      // checkpoint block

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashCheckpoint);
    )

    void SetNull()
    {
        nVersion = 1;
        hashCheckpoint = 0;
    }

    std::string ToString() const
    {
        return strprintf(
                "CSyncCheckpoint(\n"
                "    nVersion       = %d\n"
                "    hashCheckpoint = %s\n"
                ")\n",
            nVersion,
            hashCheckpoint.ToString().c_str());
    }

    void print() const
    {
        LogPrintf("%s", ToString().c_str());
    }
};

class CSyncCheckpoint : public CUnsignedSyncCheckpoint
{
public:
    static const std::string strMasterPubKey;
    static std::string strMasterPrivKey;

    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CSyncCheckpoint()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchMsg);
        READWRITE(vchSig);
    )

    void SetNull()
    {
        CUnsignedSyncCheckpoint::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (hashCheckpoint == 0);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool RelayTo(CNode* pnode) const
    {
        // returns true if wasn't already sent
        if (pnode->hashCheckpointKnown != hashCheckpoint)
        {
            pnode->hashCheckpointKnown = hashCheckpoint;
            pnode->PushMessage("checkpoint", *this);
            return true;
        }
        return false;
    }

    bool CheckSignature();
    bool ProcessSyncCheckpoint(CNode* pfrom);
};

#endif
