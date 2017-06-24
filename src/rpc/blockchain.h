#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "blockindex.h"

class CBlock;
class CBlockIndex;
class UniValue;

/**
 * Get the difficulty of the net wrt to the given block index, or the chain tip if
 * not provided.
 *
 * @return A floating point number that is a multiple of the main net minimum
 * difficulty (4295032833 hashes).
 */
double GetDifficulty(const CBlockIndex* blockindex = NULL);

/** Callback for when block tip changed. */
void RPCNotifyBlockChange(bool ibd, const CBlockIndex *);

double GetPoWMHashPS();
double GetPoSKernelPS();

#endif // BLOCKCHAIN_H
