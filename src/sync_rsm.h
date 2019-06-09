// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYNC_RSM_H
#define SYNC_RSM_H

#include "recursive_shared_mutex.h"
#include "sync.h"
#include "threadsafety.h"
#include "util/util.h"
#include "util/utiltime.h"

#include <mutex>

#ifndef DEBUG_LOCKORDER
typedef recursive_shared_mutex CRecursiveSharedCriticalSection;
/** Define a named, shared critical section that is named in debug builds.
    Named critical sections are useful in conjunction with a lock analyzer to discover bottlenecks. */
#define RSCRITSEC(x) CRecursiveSharedCriticalSection x
#else

class CRecursiveSharedCriticalSection : recursive_shared_mutex
{
public:
    const char *name;
    uint64_t exclusiveOwner;
    uint64_t exclusiveOwnerCount;
    CRecursiveSharedCriticalSection(const char *name);
    CRecursiveSharedCriticalSection();
    ~CRecursiveSharedCriticalSection();
    // shared lock functions
    void lock_shared() SHARED_LOCK_FUNCTION() { recursive_shared_mutex::lock_shared(); }
    bool try_lock_shared() SHARED_TRYLOCK_FUNCTION(true) { return recursive_shared_mutex::try_lock_shared(); }
    void unlock_shared() UNLOCK_FUNCTION() { recursive_shared_mutex::unlock_shared(); }
    // exclusive lock functions
    void lock() EXCLUSIVE_LOCK_FUNCTION() { recursive_shared_mutex::lock(); }
    bool try_lock() EXCLUSIVE_TRYLOCK_FUNCTION(true) { return recursive_shared_mutex::try_lock(); }
    void unlock() UNLOCK_FUNCTION() { recursive_shared_mutex::unlock(); }
};
#define RSCRITSEC(zzname) CRecursiveSharedCriticalSection zzname(#zzname)
#endif

typedef CMutexReadLock<CRecursiveSharedCriticalSection> CRecursiveReadBlock;
typedef CMutexLock<CRecursiveSharedCriticalSection> CRecursiveWriteBlock;

#define READLOCK_RECURSIVE(cs) CRecursiveReadBlock UNIQUIFY(readblock)(cs, #cs, __FILE__, __LINE__)
#define WRITELOCK_RECURSIVE(cs) CRecursiveWriteBlock UNIQUIFY(writeblock)(cs, #cs, __FILE__, __LINE__)
#define READLOCK2_RECURSIVE(cs1, cs2) \
    CRecursiveReadBlock UNIQUIFY(readblock1)(cs1, #cs1, __FILE__, __LINE__), UNIQUIFY(readblock2)(cs2, #cs2, __FILE__, __LINE__)
#define TRY_READ_LOCK_RECURSIVE(cs, name) CRecursiveReadBlock name(cs, #cs, __FILE__, __LINE__, true)


#endif // SYNC_RSM_H
