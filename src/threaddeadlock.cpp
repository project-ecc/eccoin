// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Copyright (c) 2019 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "threaddeadlock.h"

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>
#include <utility>

#include "util/logger.h"
#include "util/util.h"

#ifdef DEBUG_LOCKORDER // covers the entire file

// pair ( cs : lock location )
typedef std::pair<void *, CLockLocation> LockStackEntry;
typedef std::vector<LockStackEntry> LockStack;

// cs : set of thread ids
typedef std::map<void *, std::set<uint64_t> > ReadLocksHeld;
// cs : set of thread ids
typedef std::map<void *, std::set<uint64_t> > WriteLocksHeld;

// cs : set of thread ids
typedef std::map<void *, std::set<uint64_t> > ReadLocksWaiting;
// cs : set of thread ids
typedef std::map<void *, std::set<uint64_t> > WriteLocksWaiting;

// thread id : vector of locks held (both shared and exclusive, waiting and held)
typedef std::map<uint64_t, LockStack> LocksHeldByThread;


struct LockData
{
    // Very ugly hack: as the global constructs and destructors run single
    // threaded, we use this boolean to know whether LockData still exists,
    // as DeleteLock can get called by global CCriticalSection destructors
    // after LockData disappears.
    bool available;
    LockData() : available(true) {}
    ~LockData() { available = false; }

    ReadLocksHeld readlocksheld;
    WriteLocksHeld writelocksheld;
    LocksHeldByThread locksheldbythread;
    std::mutex dd_mutex;
} static lockdata;

void potential_deadlock_detected(LockStack &deadlocks)
{
    // We attempt to not assert on probably-not deadlocks by assuming that
    // a try lock will immediately have otherwise bailed if it had
    // failed to get the lock
    // We do this by, for the locks which triggered the potential deadlock,
    // in either lockorder, checking that the second of the two which is locked
    // is only a TRY_LOCK, ignoring locks if they are reentrant.
/*
    bool firstLocked = false;
    bool secondLocked = false;
    bool onlyMaybeDeadlock = false;
*/

    LogPrintf("POTENTIAL DEADLOCK DETECTED\n");
    LogPrintf("The locks involved are:\n");
    for (auto &lock : deadlocks)
    {
        LogPrintf(" %s\n", lock.second.ToString());
    }

    //LogPrintf("Previous lock order was:\n");
/*
    for (const std::pair<void *, CLockLocation> & i : s2)
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
    for (const std::pair<void *, CLockLocation> & i : s1)
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
*/
    assert(false);
}

static bool ReadRecursiveCheck(const uint64_t &tid, const void *c, uint64_t lastTid, void* lastLock, bool firstRun, LockStack &deadlocks)
{
    if (!firstRun && c == lastLock && tid == lastTid)
    {
        // we are back where we started, infinite loop means there is a deadlock
        return true;
    }
    // first check if we currently have any exclusive ownerships
    bool haveExclusives = false;
    size_t selfOtherLockCount = 0;
    std::set<void *> selfExclusiveLocks;
    auto self_iter = lockdata.locksheldbythread.find(lastTid);
    if (self_iter != lockdata.locksheldbythread.end() && self_iter->second.empty() == false)
    {
        selfOtherLockCount = self_iter->second.size();
        for (auto &lockStackLock : self_iter->second)
        {
            if (lockStackLock.second.GetExclusive() == true)
            {
                haveExclusives = true;
                // keep track of the mutexs with which we have exclusive ownership
                selfExclusiveLocks.emplace(lockStackLock.first);
            }
        }
    }
    // we cant deadlock if we dont own any other mutexs
    if (selfOtherLockCount == 0)
    {
        return false;
    }
    // at this point we have at least 1 lock for a mutex somewhere

    // if we do not have any exclusive locks and we arent requesting an exclusive lock...
    if (!haveExclusives)
    {
        // then we cant block
        return false;
    }

    // check if a thread has an ownership of c
    auto writeiter = lockdata.writelocksheld.find(lastLock);
    auto readiter = lockdata.readlocksheld.find(lastLock);

    // NOTE: be careful when adjusting these booleans, the order of the checks is important
    bool readIsEnd = ((readiter == lockdata.readlocksheld.end()) || readiter->second.empty());
    bool writeIsEnd = ((writeiter == lockdata.writelocksheld.end()) || writeiter->second.empty());
    if (writeIsEnd)
    {
        // no exclusive owners, no deadlock possible
        return false;
    }

    // we have other locks, so check if we have any in common with the holder(s) of the write lock
    for (auto &threadId : writeiter->second)
    {
        auto other_iter = lockdata.locksheldbythread.find(threadId);
        // we dont need to check empty here, other thread has at least 1 lock otherwise we wouldnt be checking it
        if (other_iter->second.size() == 1)
        {
            // it does not have any locks aside from known exclusive, no deadlock possible
            // we can just wait until that exclusive lock is released
            return false;
        }
        // if the other thread has 1+ other locks aside from the known exclusive, check them for matches with our own locks
        for (auto &lock : other_iter->second)
        {
            // if they have a lock that is on a lock that we have exclusive ownership for
            if (selfExclusiveLocks.count(lock.first) != 0)
            {
                // and their lock is waiting...
                if (lock.second.GetWaiting() == true)
                {
                    if (other_iter->first == tid && lock.first == c)
                    {
                        // we are back where we started and there is a deadlock
                        return true;
                    }
                    if(ReadRecursiveCheck(tid, c, other_iter->first, lock.first, false, deadlocks))
                    {
                        return true;
                    }
                }
                // no deadlock, other lock is not waiting, we simply have to wait until they release that lock
            }
        }
    }
    return false;
}

static bool WriteRecursiveCheck(const uint64_t &tid, const void *c, uint64_t lastTid, void* lastLock, bool firstRun, LockStack &deadlocks)
{
    if (!firstRun && c == lastLock && tid == lastTid)
    {
        // we are back where we started, infinite loop means there is a deadlock
        return true;
    }
    // first check if we currently have any exclusive ownerships
    bool haveExclusives = false;
    size_t selfOtherLockCount = 0;
    std::set<void *> selfExclusiveLocks;
    auto self_iter = lockdata.locksheldbythread.find(lastTid);
    if (self_iter != lockdata.locksheldbythread.end() && self_iter->second.empty() == false)
    {
        selfOtherLockCount = self_iter->second.size();
        for (auto &lockStackLock : self_iter->second)
        {
            if (lockStackLock.second.GetExclusive() == true)
            {
                haveExclusives = true;
                // keep track of the mutexs with which we have exclusive ownership
                selfExclusiveLocks.emplace(lockStackLock.first);
            }
        }
    }
    // we cant deadlock if we dont own any other mutexs
    if (selfOtherLockCount == 0)
    {
        return false;
    }
    // at this point we have at least 1 lock for a mutex somewhere

    // if we do not have any exclusive locks and we arent requesting an exclusive lock...
    if (!haveExclusives)
    {
        // then we cant block
        return false;
    }

    // check if a thread has an ownership of c
    auto writeiter = lockdata.writelocksheld.find(lastLock);
    auto readiter = lockdata.readlocksheld.find(lastLock);

    // NOTE: be careful when adjusting these booleans, the order of the checks is important
    bool readIsEnd = ((readiter == lockdata.readlocksheld.end()) || readiter->second.empty());
    bool writeIsEnd = ((writeiter == lockdata.writelocksheld.end()) || writeiter->second.empty());
    if (writeIsEnd)
    {
        // no exclusive owners, no deadlock possible
        return false;
    }

    // we have other locks, so check if we have any in common with the holder(s) of the write lock
    for (auto &threadId : writeiter->second)
    {
        auto other_iter = lockdata.locksheldbythread.find(threadId);
        // we dont need to check empty here, other thread has at least 1 lock otherwise we wouldnt be checking it
        if (other_iter->second.size() == 1)
        {
            // it does not have any locks aside from known exclusive, no deadlock possible
            // we can just wait until that exclusive lock is released
            return false;
        }
        // if the other thread has 1+ other locks aside from the known exclusive, check them for matches with our own locks
        for (auto &lock : other_iter->second)
        {
            // if they have a lock that is on a lock that we have exclusive ownership for
            if (selfExclusiveLocks.count(lock.first) != 0)
            {
                // and their lock is waiting...
                if (lock.second.GetWaiting() == true)
                {
                    if (other_iter->first == tid && lock.first == c)
                    {
                        // we are back where we started and there is a deadlock
                        return true;
                    }
                    if(ReadRecursiveCheck(tid, c, other_iter->first, lock.first, false, deadlocks))
                    {
                        return true;
                    }
                }
                // no deadlock, other lock is not waiting, we simply have to wait until they release that lock
            }
        }
    }
    return false;
}

// for recrusive locking issues with a non recrusive mutex
static void self_deadlock_detected(LockStackEntry now, LockStackEntry previous)
{
    LogPrintf("SELF DEADLOCK DETECTED FOR SHARED MUTEX\n");
    LogPrintf("Previous lock was: %s\n", previous.second.ToString());
    LogPrintf("Current lock is: %s\n", now.second.ToString());
    assert(false);
}

// c = the cs
// isExclusive = is the current lock exclusive, for a recursive mutex (CCriticalSection) this value should always be true
void push_lock(void *c, const CLockLocation &locklocation, LockType type, bool isExclusive, bool fTry)
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);

    LockStackEntry now = std::make_pair(c, locklocation);
    // If this is a blocking lock operation, we want to make sure that the locking order between 2 mutexes is consistent
    // across the program
    if (fTry)
    {
        return;
    }
    // tid of the originating request
    const uint64_t tid = getTid();

    // first check lock specific issues
    if(type == LockType::SHARED)
    {
        TEST_1_SM:
        TEST_2:
        TEST_3:
        TEST_4:
        // shared mutexs cant recursively lock at all, check if we already have a lock on the mutex
        auto it = lockdata.locksheldbythread.find(tid);
        if (it == lockdata.locksheldbythread.end() || it->second.empty())
        {
            // intentionally left blank
        }
        else
        {
            for (auto &lockStackLock : it->second)
            {
                // if it is c we are recursively locking a non recursive mutex, there is a deadlock
                if (lockStackLock.first == c)
                    self_deadlock_detected(now, lockStackLock);
            }
        }
    }
    else if (type == LockType::RECRUSIVESHARED)
    {
        TEST_1_RSM:
        // we cannot lock exclusive if we already hold shared, check for this scenario
        if (isExclusive)
        {
            auto it = lockdata.locksheldbythread.find(tid);
            if (it == lockdata.locksheldbythread.end() || it->second.empty())
            {
                // intentionally left blank
            }
            else
            {
                for (auto &lockStackLock : it->second)
                {
                    // if we have a lock and it isnt exclusive and we are attempting to get exclusive
                    // then we will deadlock ourself
                    if (lockStackLock.first == c && lockStackLock.second.GetExclusive() == false)
                        self_deadlock_detected(now, lockStackLock);
                }
            }
        }
        else
        {
            // intentionally left blank
        }
    }
    else if (type == LockType::RECURSIVE)
    {
        // this lock can not deadlock itself
        // intentionally left blank
    }

    // Begin general deadlock checks for all lock types

    // if we have exclusive lock(s) and we arent requesting an exclusive lock...
    if (!isExclusive)
    {
        TEST_5:
        TEST_8:
        std::vector<LockStackEntry> deadlocks;
        // then we can only deadlock if we are locking a thread that is currently held in exclusive state by someone else
        if (ReadRecursiveCheck(tid, c, tid, c, true, deadlocks))
        {
            // we have a deadlock where we are requesting shared ownership on a mutex that is exclusively owned by
            // another thread which has either a shared or exlcusive request on a mutex we have exclusive ownership over
            potential_deadlock_detected(deadlocks);
        }
    }
    // if we have exclusive lock(s) and we are requesting another exclusive lock
    if (isExclusive)
    {
        TEST_6:
        TEST_7:
        TEST_9:
        std::vector<LockStackEntry> deadlocks;
        if (WriteRecursiveCheck(tid, c, tid, c, true, deadlocks))
        {
            potential_deadlock_detected(deadlocks);
        }
    }
}

// remove removes 1 instance of the lock, delete removes all instances

void DeleteLock(void *cs)
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    uint64_t tid = getTid();

    // need to delete an entry from LocksHeldByThread matching the cs, and its type (shared or exclusive)
    // if we now have 0 entries for it, remove it from the held locks map as well (waiting is unaffected)
}

void remove_lock_critical_exit()
{
    // (*lockstack).pop_back();
}

std::string LocksHeld()
{
    std::string result;
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    uint64_t tid = getTid();
    auto self_iter = lockdata.locksheldbythread.find(tid);
    if (self_iter != lockdata.locksheldbythread.end() && self_iter->second.empty() == false)
    {
        for (auto &entry : self_iter->second)
        {
            result += entry.second.ToString() + std::string("\n");
        }
    }
    return result;
}

void AssertLockHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs)
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    uint64_t tid = getTid();
    auto self_iter = lockdata.locksheldbythread.find(tid);
    if (self_iter == lockdata.locksheldbythread.end() && self_iter->second.empty())
    {
        return;
    }
    fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
        LocksHeld().c_str());
    abort();
}

void AssertLockNotHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs)
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    uint64_t tid = getTid();
    auto self_iter = lockdata.locksheldbythread.find(tid);
    if (self_iter != lockdata.locksheldbythread.end() && self_iter->second.empty() == false)
    {
        for (auto &entry : self_iter->second)
        {
            if (entry.first == cs)
            {
                fprintf(stderr, "Assertion failed: lock %s held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
                    LocksHeld().c_str());
                abort();
            }
        }
    }
}

#endif // DEBUG_LOCKORDER
