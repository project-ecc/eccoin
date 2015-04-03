#ifndef ECCOININFO
#define ECCOININFO

#include "uint256.h"
#include "util.h"

#include <list>
#include <string>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

using namespace std;

typedef std::map<int, uint256> MapCheckpoints;

/*

static const uint256 ECChashGenesisBlockHex("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1");
static const uint256 ECChashGenesisBlockTestNetHex("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1");
static const uint256 ECCMerkleRootHex("4db82fe8b45f3dae2b7c7b8be5ec4c37e72e25eaf989b9db24ce1d0fd37eed8b");

MapCheckpoints eccCheckpoints = boost::assign::map_list_of
   (     0, uint256("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1"))
   (  1000, uint256("0x000000000df3f7a5f719c247782d7a43d75186ebc043341e2668320f9d940bcd"))
   ( 10000, uint256("0x00000000076d45a9579c879d46354dd81eeba7060a9a065e13c9dd1c28f474d1"))
   ( 50000, uint256("0x0000000001c770384cd12a74eb5456358425fc6a94a250c3466aaa2ca7460131"))
   ( 86401, uint256("0x51bb1ac3ffd009c12791b9d4320dec0ba69e15c8b6d03d17889b0c09fb5b05a4"))
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
   (450000, uint256("0x53e21a2574ff6acc0f31640c4058554dde2fe8972ec72867403e8b88e9ba1bc6"))
   (500000, uint256("0x779f22407cf9fa0adb8a361918ccf249ef913070ce368070c1ac5063005e3e3c"))
   (550000, uint256("0xf340b738c21c0a9b6b2eff0f40d9ab3fca9830d8597131680cd5a2615594cfb0"))
       ;

MapCheckpoints TNeccCheckpoints = boost::assign::map_list_of
        ( 0, uint256("0xa60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1"))
        ;

static const string ECCstrMasterPubKey = "04629f7808ddb28faefe3787f8e9ba5a34b189d1b7d625339980430d6f6d7dc55009e93db10a6c84b1b4602a26d1a090584ac7350ef716a67a68a50271ac9146ae";

*/
static const string ECCName = "ECCoin";



class ECCinfo
{
public:
    static const unsigned int CoinnStakeMinAge = 60 *60 * 2;	// minimum age for coin age: 2 hours
    static const unsigned int CoinnStakeMaxAge = 60 *60 * 24 * 84;	// stake age of full weight: 84 days
    static const unsigned int CoinnTargetSpacing = 45;			// 45 sec block spacing
    static const int64_t CoinnTargetTimespan = 10 * 60;
    static const int CoinnCoinbaseMaturity = 30;
    static const int CoinDAILY_BLOCKCOUNT = 1920;
    static const int CoinYEARLY_BLOCKCOUNT = 700800;	// 365 * 1920
    static const int CoinCUTOFF_HEIGHT = 86400;
    static const int CoinnMinSubsidy = 1 * COIN;
    static const int64_t CoinMIN_TX_FEE = 0.1;
    static const int64_t CoinMIN_RELAY_TX_FEE = 0.1;
    static const int64_t CoinMAX_MONEY = 50000000000;			// 50 bil
    static const double CoinTAX_PERCENTAGE = 0.0099;
    static const int64_t CoinMAX_MINT_PROOF_OF_STAKE = 0.1;
    static const unsigned short CoinRegPort = 19118;
    static const unsigned short CoinTestNetPort = 29118;
    static const int64_t CoinnTimeBestReceived = 0;
    static const unsigned int CoinModifierInterval = 6 * 60  * 60;
/*
    uint256 getHashGenBlock()
    {
        return ECChashGenesisBlockHex;
    }
    uint256 getHashGenBlockTest()
    {
        return ECChashGenesisBlockTestNetHex;
    }
    uint256 getMerkle()
    {
        return ECCMerkleRootHex;
    }

    MapCheckpoints getCoinCheckpoints()
    {
        return eccCheckpoints;
    }
    MapCheckpoints getTestNetCheckpoints()
    {
        return TNeccCheckpoints;
    }
    std::string getMasterKey()
    {
        return ECCstrMasterPubKey;
    }
    std::string getCoinName()
    {
        return ECCName;
    }

    */
};



#endif // ECCOININFO

