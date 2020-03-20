// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ECCOIN_THREAD_DEADLOCK_H
#define ECCOIN_THREAD_DEADLOCK_H

#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <mutex>
#include <string>

#include "lockorder.h"
#include "util/utilstrencodings.h"

#ifdef DEBUG_LOCKORDER
#include <sys/syscall.h>
#include <unistd.h> // for syscall definition
#ifdef __linux__
inline uint64_t getTid(void)
{
    // "native" thread id used so the number correlates with what is shown in gdb
    pid_t tid = (pid_t)syscall(SYS_gettid);
    return tid;
}
#else
inline uint64_t getTid(void)
{
    uint64_t tid = boost::lexical_cast<uint64_t>(boost::this_thread::get_id());
    return tid;
}
#endif


struct LockData
{
    // Very ugly hack: as the global constructs and destructors run single
    // threaded, we use this boolean to know whether LockData still exists,
    // as DeleteLock can get called by global CCriticalSection destructors
    // after LockData disappears.
    bool available;
    LockData() : available(true) {}
    ~LockData() { available = false; }
    ReadLocksWaiting readlockswaiting;
    WriteLocksWaiting writelockswaiting;

    ReadLocksHeld readlocksheld;
    WriteLocksHeld writelocksheld;
    LocksHeldByThread locksheldbythread;
    CLockOrderTracker ordertracker;
    std::mutex dd_mutex;
};

extern LockData lockdata;

void push_lock(void *c, const CLockLocation &locklocation, LockType type, OwnershipType isExclusive, bool fTry);
void DeleteLock(void *cs);
void remove_lock_critical_exit(void *cs);
std::string LocksHeld();
void SetWaitingToHeld(void *c, OwnershipType isExclusive);
std::string _LocksHeld();

#else // NOT DEBUG_LOCKORDER

static inline void SetWaitingToHeld(void *c, OwnershipType isExclusive) {}

#endif // END DEBUG_LOCKORDER

#endif
