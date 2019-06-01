// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sync.h"


/**
 * Global state
 */

CCriticalSection cs_main;
CCriticalSection cs_orphans;
CCriticalSection cs_blockstorage;
