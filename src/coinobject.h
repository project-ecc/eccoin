#ifndef COINOBJECT
#define COINOBJECT

#include "util.h"

typedef std::map<int, uint256> MapCheckpoints;

class CoinObject
{
private:
    unsigned int nStakeMinAge;
    unsigned int nStakeMaxAge;
    unsigned int nTargetSpacing; // ideal amount of time before next block
    int64_t nTargetTimespan; // 10 minutes. used to see if nTargetSpacing is at correct time
    int DAILY_BLOCKCOUNT;
    int YEARLY_BLOCKCOUNT;
    int CUTOFF_HEIGHT;  // PoW end block - PoS start block
    int nMinSubsidy; // minimum return from a staking or block mined
    int nCoinbaseMaturity;
    int64_t MIN_TX_FEE;
    int64_t MIN_RELAY_TX_FEE;
    int64_t MAX_MONEY;
    double PREMINE_PERCENTAGE; // premine % //
    int64_t MAX_MINT_PROOF_OF_STAKE;   // % gain of of PoS per year
    std::string CoinName;
    unsigned short TestNetPort; //rpcport testnet
    unsigned short RegPort;   //rpcport
    MapCheckpoints coinCheckpoints;
    MapCheckpoints TestNetcoinCheckpoints;
    uint256 hashGenesisBlock;
    uint256 hashGenesisBlockTestNet;
    uint256 MerkleRoot;
    std::string strMasterPubKey;
    int64_t nTimeBestReceived;
    unsigned int nModifierInterval;



public:
///// GETTER FUNCTIONS /////
uint256 getGenesisBlock()
{
    return hashGenesisBlock;
}
uint256 getGenesisBlockTestNet()
{
    return hashGenesisBlockTestNet;
}
uint256 getMerkleRoot()
{
    return MerkleRoot;
}
MapCheckpoints getCheckpoints()
{
    return coinCheckpoints;
}
MapCheckpoints getCheckpointsTestNet()
{
    return TestNetcoinCheckpoints;
}
std::string getCoinName()
{
    return CoinName;
}
unsigned int getStakeMinAge()
{
    return nStakeMinAge;
}
unsigned int getStakeMaxAge()
{
    return nStakeMaxAge;
}
unsigned int getTargetSpacing()
{
    return nTargetSpacing;
}
int64_t getTargetTimespan()
{
    return nTargetTimespan;
}
int getDailyBlocks()
{
    return DAILY_BLOCKCOUNT;
}
int getYearlyBlocks()
{
    return YEARLY_BLOCKCOUNT;
}
int getCutoffHeight()
{
    return CUTOFF_HEIGHT;
}
int getMinSubsidy()
{
    return nMinSubsidy;
}
int64_t getMinTxFee()
{
    return MIN_TX_FEE;
}
int64_t getMinRelayTxFee()
{
    return MIN_RELAY_TX_FEE;
}
int64_t getMaxMoney()
{
    return MAX_MONEY;
}
double getPremine()
{
    return PREMINE_PERCENTAGE;
}
int64_t getMaxMintPos()
{
    return MAX_MINT_PROOF_OF_STAKE;
}
int getCoinbaseMaturity()
{
    return nCoinbaseMaturity;
}
std::string getMasterPubKey()
{
    return strMasterPubKey;
}
unsigned short getTestNetPort()
{
    return TestNetPort;
}
unsigned short getRegPort()
{
    return RegPort;
}
int64_t getTimeBestReceived()
{
    return nTimeBestReceived;
}
unsigned int getModifierInterval()
{
    return nModifierInterval;
}

////////////////////////////



///// SETTER FUNCTIONS /////
void setGenesisBlock(uint256 genesisBlockInput)
{
    hashGenesisBlock = genesisBlockInput;
}

void setGenesisBlockTestNet(uint256 genesisTestNetInput)
{
    hashGenesisBlockTestNet = genesisTestNetInput;
}
void setMerkleRoot(uint256 merkleInput)
{
    MerkleRoot = merkleInput;
}
void setCheckPoints(MapCheckpoints input)
{
    coinCheckpoints = input;
}
void setCheckPointsTestNet(MapCheckpoints input)
{
    TestNetcoinCheckpoints = input;
}
void setRPCport(unsigned short input)
{
    RegPort = input;
}
void setRPCportTestNet(unsigned short input)
{
    TestNetPort = input;
}
void setCoinName(std::string input)
{
    CoinName = input;
}
void setMaxMint(int64_t input)
{
    MAX_MINT_PROOF_OF_STAKE = input;
}
void setPremine(double input)
{
    PREMINE_PERCENTAGE = input;
}
void setMaxMoney(int64_t input)
{
    MAX_MONEY = input;
}
void setMinTxFee(int64_t input)
{
    MIN_TX_FEE = input;
}
void setMinTxRelayFee(int64_t input)
{
    MIN_RELAY_TX_FEE = input;
}
void setMinSubsidy(int input)
{
    nMinSubsidy = input;
}
void setCutoffHeight(int input)
{
    CUTOFF_HEIGHT = input;
}
void setYearlyBlockCount(int input)
{
    YEARLY_BLOCKCOUNT = input;
}
void setDailyBlockCount(int input)
{
    DAILY_BLOCKCOUNT = input;
}
void setTargetTimespan(int64_t input)
{
    nTargetTimespan = input;
}
void setTargetSpacing(unsigned int input)
{
    nTargetSpacing = input;
}
void setStakeMinAge(unsigned int input)
{
    nStakeMinAge = input;
}
void setStakeMaxAge(unsigned int input)
{
    nStakeMaxAge = input;
}
void setCoinbaseMaturity(int input)
{
    nCoinbaseMaturity = input;
}
void setMasterPubKey(std::string input)
{
    strMasterPubKey = input;
}
void setTimeBestReceived(int64_t input)
{
    nTimeBestReceived = input;
}
void setModifierInterval(unsigned int input)
{
    nModifierInterval = input;
}

////////////////////////////
};
#endif // COINOBJECT

