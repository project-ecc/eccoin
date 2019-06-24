// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coins.h"
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
