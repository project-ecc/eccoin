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

#include "sync.h"

#include "util/logger.h"
#include "util/util.h"
#include "util/utilstrencodings.h"

#include <stdio.h>
#include <thread>

#ifdef DEBUG_LOCKCONTENTION
void PrintLockContention(const char *pszName, const char *pszFile, unsigned int nLine)
{
    LogPrintf("LOCKCONTENTION: %s\n", pszName);
    LogPrintf("Locker: %s:%d\n", pszFile, nLine);
}
#endif /* DEBUG_LOCKCONTENTION */

#ifdef DEBUG_LOCKORDER // this define covers the rest of the file
//
// Early deadlock detection.
// Problem being solved:
//    Thread 1 locks  A, then B, then C
//    Thread 2 locks  D, then C, then A
//     --> may result in deadlock between the two threads, depending on when they run.
// Solution implemented here:
// Keep track of pairs of locks: (A before B), (A before C), etc.
// Complain if any thread tries to lock in a different order.
//

struct CLockLocation
{
    CLockLocation(const char *pszName, const char *pszFile, int nLine, bool fTryIn)
    {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
        fTry = fTryIn;
    }

    std::string ToString() const
    {
        return mutexName + "  " + sourceFile + ":" + itostr(sourceLine) + (fTry ? " (TRY)" : "");
    }

    bool GetTry() const { return fTry; }
private:
    bool fTry;
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
};

typedef std::vector<std::pair<void *, CLockLocation> > LockStack;
typedef std::map<std::pair<void *, void *>, LockStack> LockOrders;
typedef std::set<std::pair<void *, void *> > InvLockOrders;

struct LockData
{
    // Very ugly hack: as the global constructs and destructors run single
    // threaded, we use this boolean to know whether LockData still exists,
    // as DeleteLock can get called by global CCriticalSection destructors
    // after LockData disappears.
    bool available;
    LockData() : available(true) {}
    ~LockData() { available = false; }
    LockOrders lockorders;
    InvLockOrders invlockorders;
    std::mutex dd_mutex;
} static lockdata;

static thread_local std::unique_ptr<LockStack> lockstack;

static void potential_deadlock_detected(const std::pair<void *, void *> &mismatch,
    const LockStack &s1,
    const LockStack &s2)
{
    // We attempt to not assert on probably-not deadlocks by assuming that
    // a try lock will immediately have otherwise bailed if it had
    // failed to get the lock
    // We do this by, for the locks which triggered the potential deadlock,
    // in either lockorder, checking that the second of the two which is locked
    // is only a TRY_LOCK, ignoring locks if they are reentrant.
    bool firstLocked = false;
    bool secondLocked = false;
    bool onlyMaybeDeadlock = false;

    LogPrintf("POTENTIAL DEADLOCK DETECTED\n");
    LogPrintf("Previous lock order was:\n");
    for (const PAIRTYPE(void *, CLockLocation) & i : s2)
    {
        if (i.first == mismatch.first)
        {
            LogPrintf(" (1)");
            if (!firstLocked && secondLocked && i.second.GetTry())
                onlyMaybeDeadlock = true;
            firstLocked = true;
        }
        if (i.first == mismatch.second)
        {
            LogPrintf(" (2)");
            if (!secondLocked && firstLocked && i.second.GetTry())
                onlyMaybeDeadlock = true;
            secondLocked = true;
        }
        LogPrintf(" %s\n", i.second.ToString());
    }
    firstLocked = false;
    secondLocked = false;
    LogPrintf("Current lock order is:\n");
    for (const PAIRTYPE(void *, CLockLocation) & i : s1)
    {
        if (i.first == mismatch.first)
        {
            LogPrintf(" (1)");
            if (!firstLocked && secondLocked && i.second.GetTry())
                onlyMaybeDeadlock = true;
            firstLocked = true;
        }
        if (i.first == mismatch.second)
        {
            LogPrintf(" (2)");
            if (!secondLocked && firstLocked && i.second.GetTry())
                onlyMaybeDeadlock = true;
            secondLocked = true;
        }
        LogPrintf(" %s\n", i.second.ToString());
    }
    assert(onlyMaybeDeadlock);
}

static void push_lock(void *c, const CLockLocation &locklocation, bool fTry)
{
    if (lockstack.get() == nullptr)
        lockstack.reset(new LockStack);

    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);

    (*lockstack).push_back(std::make_pair(c, locklocation));
    // If this is a blocking lock operation, we want to make sure that the locking order between 2 mutexes is consistent
    // across the program
    if (!fTry)
    {
        for (const PAIRTYPE(void *, CLockLocation) & i : (*lockstack))
        {
            if (i.first == c)
                break;

            std::pair<void *, void *> p1 = std::make_pair(i.first, c);
            // If this order has already been placed into the order map, we've already tested it
            if (lockdata.lockorders.count(p1))
                continue;
            lockdata.lockorders[p1] = (*lockstack);
            // check to see if the opposite order has ever occurred, if so flag a possible deadlock
            std::pair<void *, void *> p2 = std::make_pair(c, i.first);
            lockdata.invlockorders.insert(p2);
            if (lockdata.lockorders.count(p2))
                potential_deadlock_detected(p1, lockdata.lockorders[p1], lockdata.lockorders[p2]);
        }
    }
}

static void pop_lock() { (*lockstack).pop_back(); }
void EnterCritical(const char *pszName, const char *pszFile, unsigned int nLine, void *cs, bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine, fTry), fTry);
}

void LeaveCritical() { pop_lock(); }
std::string LocksHeld()
{
    std::string result;
    for (const PAIRTYPE(void *, CLockLocation) & i : *lockstack)
        result += i.second.ToString() + std::string("\n");
    return result;
}

void AssertLockHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs)
{
    for (const PAIRTYPE(void *, CLockLocation) & i : *lockstack)
        if (i.first == cs)
            return;
    fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
        LocksHeld().c_str());
    abort();
}

void AssertLockNotHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs)
{
    for (const std::pair<void *, CLockLocation> &i : *lockstack)
    {
        if (i.first == cs)
        {
            fprintf(stderr, "Assertion failed: lock %s held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
                LocksHeld().c_str());
            abort();
        }
    }
}

void AssertWriteLockHeldInternal(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    CSharedCriticalSection *cs)
{
    if (cs->try_lock()) // It would be better to check that this thread has the lock
    {
        fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
            LocksHeld().c_str());
        fflush(stderr);
        abort();
    }
}

void AssertRecursiveWriteLockHeldinternal(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    CRecursiveSharedCriticalSection *cs)
{
    if (cs->try_lock()) // It would be better to check that this thread has the lock
    {
        fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
            LocksHeld().c_str());
        fflush(stderr);
        abort();
    }
}

// BU normally CCriticalSection is a typedef, but when lockorder debugging is on we need to delete the critical
// section from the lockorder map
CCriticalSection::CCriticalSection() : name(NULL) {}
CCriticalSection::CCriticalSection(const char *n) : name(n)
{
// print the address of named critical sections so they can be found in the mutrace output
#ifdef ENABLE_MUTRACE
    if (name)
    {
        LogPrintf("CCriticalSection %s at %p\n", name, this);
        fflush(stdout);
    }
#endif
}

CCriticalSection::~CCriticalSection()
{
#ifdef ENABLE_MUTRACE
    if (name)
    {
        LogPrintf("Destructing %s\n", name);
        fflush(stdout);
    }
#endif
    DeleteLock((void *)this);
}

// BU normally CSharedCriticalSection is a typedef, but when lockorder debugging is on we need to delete the critical
// section from the lockorder map
CSharedCriticalSection::CSharedCriticalSection() : name(NULL), exclusiveOwner(0) {}
CSharedCriticalSection::CSharedCriticalSection(const char *n) : name(n), exclusiveOwner(0)
{
// print the address of named critical sections so they can be found in the mutrace output
#ifdef ENABLE_MUTRACE
    if (name)
    {
        LogPrintf("CSharedCriticalSection %s at %p\n", name, this);
        fflush(stdout);
    }
#endif
}

CSharedCriticalSection::~CSharedCriticalSection()
{
#ifdef ENABLE_MUTRACE
    if (name)
    {
        LogPrintf("Destructing CSharedCriticalSection %s\n", name);
        fflush(stdout);
    }
#endif
    DeleteLock((void *)this);
}


void CSharedCriticalSection::lock_shared()
{
    uint64_t tid = getTid();
    // detect recursive locking
    {
        std::unique_lock<std::mutex> lock(setlock);
        assert(exclusiveOwner != tid);
        auto alreadyLocked = sharedowners.find(tid);
        if (alreadyLocked != sharedowners.end())
        {
            LockInfo li = alreadyLocked->second;
            LogPrintf("already locked at %s:%d\n", li.file, li.line);
            assert(alreadyLocked == sharedowners.end());
        }
        sharedowners[tid] = LockInfo("", 0);
    }
    boost::shared_mutex::lock_shared();
}

void CSharedCriticalSection::unlock_shared()
{
    // detect recursive locking
    uint64_t tid = getTid();
    {
        std::unique_lock<std::mutex> lock(setlock);
        auto alreadyLocked = sharedowners.find(tid);
        if (alreadyLocked == sharedowners.end())
        {
            LockInfo li = alreadyLocked->second;
            LogPrintf("never locked at %s:%d\n", li.file, li.line);
            assert(alreadyLocked != sharedowners.end());
        }
        sharedowners.erase(tid);
    }
    boost::shared_mutex::unlock_shared();
}

bool CSharedCriticalSection::try_lock_shared()
{
    // detect recursive locking
    uint64_t tid = getTid();
    std::unique_lock<std::mutex> lock(setlock);
    assert(exclusiveOwner != tid);
    assert(sharedowners.find(tid) == sharedowners.end());

    bool result = boost::shared_mutex::try_lock_shared();
    if (result)
    {
        sharedowners[tid] = LockInfo("", 0);
    }
    return result;
}
void CSharedCriticalSection::lock()
{
    boost::shared_mutex::lock();
    exclusiveOwner = getTid();
}
void CSharedCriticalSection::unlock()
{
    uint64_t tid = getTid();
    assert(exclusiveOwner == tid);
    exclusiveOwner = 0;
    boost::shared_mutex::unlock();
}

bool CSharedCriticalSection::try_lock()
{
    bool result = boost::shared_mutex::try_lock();
    if (result)
    {
        exclusiveOwner = getTid();
    }
    return result;
}

void DeleteLock(void *cs)
{
    if (!lockdata.available)
    {
        // We're already shutting down.
        return;
    }

    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    std::pair<void *, void *> item = std::make_pair(cs, nullptr);
    LockOrders::iterator it = lockdata.lockorders.lower_bound(item);
    while (it != lockdata.lockorders.end() && it->first.first == cs)
    {
        std::pair<void *, void *> invitem = std::make_pair(it->first.second, it->first.first);
        lockdata.invlockorders.erase(invitem);
        lockdata.lockorders.erase(it++);
    }
    InvLockOrders::iterator invit = lockdata.invlockorders.lower_bound(item);
    while (invit != lockdata.invlockorders.end() && invit->first == cs)
    {
        std::pair<void *, void *> invinvitem = std::make_pair(invit->second, invit->first);
        lockdata.lockorders.erase(invinvitem);
        lockdata.invlockorders.erase(invit++);
    }
}

CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection() : name(nullptr) {}
CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection(const char *n) : name(n)
{
// print the address of named critical sections so they can be found in the mutrace output
#ifdef ENABLE_MUTRACE
    if (name)
    {
        LogPrintf("CRecursiveSharedCriticalSection %s at %p\n", name, this);
        fflush(stdout);
    }
#endif
}

CRecursiveSharedCriticalSection::~CRecursiveSharedCriticalSection()
{
#ifdef ENABLE_MUTRACE
    if (name)
    {
        LogPrintf("Destructing CRecursiveSharedCriticalSection %s\n", name);
        fflush(stdout);
    }
#endif
    DeleteLock((void *)this);
}


#endif /* DEBUG_LOCKORDER */
