// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coins.h"
#include "main.h"
#include "sync.h"
#include "txdb.h"


/**
 * Global state
 */

CCriticalSection cs_main;
CCriticalSection cs_orphans;
CCriticalSection cs_blockstorage;

/** Global variable that points to the active CCoinsView */
std::unique_ptr<CCoinsViewCache> pcoinsTip GUARDED_BY(cs_main);

/** Global variable that points to the active block tree */
std::unique_ptr<CBlockTreeDB> pblocktree GUARDED_BY(cs_main);

/**
 * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
 * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
 * missing the data for the block.
 */
std::set<CBlockIndex *, CBlockIndexWorkComparator> setBlockIndexCandidates GUARDED_BY(cs_main);
