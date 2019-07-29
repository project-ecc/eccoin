// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Copyright (c) 2019 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "threaddeadlock.h"

#include <inttypes.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

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
    ReadLocksWaiting readlockswaiting;
    WriteLocksWaiting writelockswaiting;

    ReadLocksHeld readlocksheld;
    WriteLocksHeld writelocksheld;
    LocksHeldByThread locksheldbythread;
    std::mutex dd_mutex;
} static lockdata;

void potential_deadlock_detected(LockStackEntry now, LockStack &deadlocks, std::set<uint64_t> &threads)
{
    LogPrintf("POTENTIAL DEADLOCK DETECTED\n");
    LogPrintf("This occurred while trying to lock: %s ", now.second.ToString().c_str());
    LogPrintf("which has:\n");

    auto rlw = lockdata.readlockswaiting.find(now.first);
    if (rlw != lockdata.readlockswaiting.end())
    {
        for (auto &entry : rlw->second)
        {
            LogPrintf("Read Lock Waiting for thread with id %" PRIu64 "\n", entry);
        }
    }

    auto wlw = lockdata.writelockswaiting.find(now.first);
    if (wlw != lockdata.writelockswaiting.end())
    {
        for (auto &entry : wlw->second)
        {
            LogPrintf("Write Lock Waiting for thread with id %" PRIu64 "\n", entry);
        }
    }

    auto rlh = lockdata.readlocksheld.find(now.first);
    if (rlh != lockdata.readlocksheld.end())
    {
        for (auto &entry : rlh->second)
        {
            LogPrintf("Read Lock Held for thread with id %" PRIu64 "\n", entry);
        }
    }

    auto wlh = lockdata.writelocksheld.find(now.first);
    if (wlh != lockdata.writelocksheld.end())
    {
        for (auto &entry : wlh->second)
        {
            LogPrintf("Write Lock Held for thread with id %" PRIu64 "\n", entry);
        }
    }

    LogPrintf("\nThe locks involved are:\n");
    for (auto &lock : deadlocks)
    {
        LogPrintf(" %s\n", lock.second.ToString().c_str());
    }
    for (auto &thread : threads)
    {
        LogPrintf("\nThread with tid %" PRIu64 " was involved. It held locks:\n", thread);
        auto iterheld = lockdata.locksheldbythread.find(thread);
        if (iterheld != lockdata.locksheldbythread.end())
        {
            for (auto &lockentry : iterheld->second)
            {
                LogPrintf(" %s\n", lockentry.second.ToString().c_str());
            }
        }
    }
    // clean up the lock before throwing
    _remove_lock_critical_exit(now.first);
    throw std::logic_error("potential deadlock detected");
}

static bool ReadRecursiveCheck(const uint64_t &tid,
    const void *c,
    uint64_t lastTid,
    void *lastLock,
    bool firstRun,
    LockStack &deadlocks,
    std::set<uint64_t> &threads)
{
    if (!firstRun && c == lastLock && tid == lastTid)
    {
        // we are back where we started, infinite loop means there is a deadlock
        return true;
    }
    // first check if we currently have any exclusive ownerships
    bool haveExclusives = false;
    size_t selfOtherLockCount = 0;
    auto self_iter = lockdata.locksheldbythread.find(lastTid);
    if (self_iter != lockdata.locksheldbythread.end())
    {
        selfOtherLockCount = self_iter->second.size();
        for (auto &lockStackLock : self_iter->second)
        {
            if (lockStackLock.second.GetExclusive() == true)
            {
                haveExclusives = true;
                break;
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

    // NOTE: be careful when adjusting these booleans, the order of the checks is important
    bool writeIsEnd = ((writeiter == lockdata.writelocksheld.end()) || writeiter->second.empty());
    if (writeIsEnd)
    {
        // no exclusive owners, no deadlock possible
        return false;
    }

    // we have other locks, so check if we have any in common with the holder(s) of the write lock
    for (auto &threadId : writeiter->second)
    {
        if (threadId == lastTid)
        {
            continue;
        }
        auto other_iter = lockdata.locksheldbythread.find(threadId);
        // we dont need to check empty here, other thread has at least 1 lock otherwise we wouldnt be checking it
        if (other_iter->second.size() == 1)
        {
            // it does not have any locks aside from known exclusive, no deadlock possible
            // we can just wait until that exclusive lock is released
            return false;
        }
        // if the other thread has 1+ other locks aside from the known exclusive, check them for matches with our own
        // locks
        for (auto &lock : other_iter->second)
        {
            // if they have a lock that is on a lock that we have exclusive ownership for
            if (HasAnyOwners(lock.first))
            {
                // and their lock is waiting...
                if (lock.second.GetWaiting() == true)
                {
                    deadlocks.push_back(lock);
                    threads.emplace(other_iter->first);
                    if (other_iter->first == tid && lock.first == c)
                    {
                        // we are back where we started and there is a deadlock
                        return true;
                    }
                    if (ReadRecursiveCheck(tid, c, other_iter->first, lock.first, false, deadlocks, threads))
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

static bool WriteRecursiveCheck(const uint64_t &tid,
    const void *c,
    uint64_t lastTid,
    void *lastLock,
    bool firstRun,
    LockStack &deadlocks,
    std::set<uint64_t> &threads)
{
    if (!firstRun && c == lastLock && tid == lastTid)
    {
        // we are back where we started, infinite loop means there is a deadlock
        return true;
    }
    // first check if we currently have any exclusive ownerships
    size_t selfOtherLockCount = 0;
    auto self_iter = lockdata.locksheldbythread.find(lastTid);
    if (self_iter != lockdata.locksheldbythread.end() && self_iter->second.empty() == false)
    {
        selfOtherLockCount = self_iter->second.size();
    }
    // we cant deadlock if we dont own any other mutexs
    if (selfOtherLockCount == 0)
    {
        return false;
    }
    // at this point we have at least 1 lock for a mutex somewhere

    // check if a thread has an ownership of c
    auto writeiter = lockdata.writelocksheld.find(lastLock);
    auto readiter = lockdata.readlocksheld.find(lastLock);

    // NOTE: be careful when adjusting these booleans, the order of the checks is important
    bool readIsEnd = ((readiter == lockdata.readlocksheld.end()) || readiter->second.empty());
    bool writeIsEnd = ((writeiter == lockdata.writelocksheld.end()) || writeiter->second.empty());
    if (writeIsEnd && readIsEnd)
    {
        // no owners, no deadlock possible
        return false;
    }
    // we have other locks, so check if we have any in common with the holder(s) of the other lock
    std::set<uint64_t> otherLocks;
    if (!writeIsEnd)
    {
        otherLocks.insert(writeiter->second.begin(), writeiter->second.end());
    }
    if (!readIsEnd)
    {
        otherLocks.insert(readiter->second.begin(), readiter->second.end());
    }
    for (auto &threadId : otherLocks)
    {
        if (threadId == lastTid)
        {
            continue;
        }
        auto other_iter = lockdata.locksheldbythread.find(threadId);
        // we dont need to check empty here, other thread has at least 1 lock otherwise we wouldnt be checking it
        if (other_iter->second.size() == 1)
        {
            // it does not have any locks aside from known exclusive, no deadlock possible
            // we can just wait until that exclusive lock is released
            return false;
        }
        // if the other thread has 1+ other locks aside from the known exclusive, check them for matches with our own
        // locks
        for (auto &lock : other_iter->second)
        {
            // if they have a lock that is on a lock that someone has a lock on
            if (HasAnyOwners(lock.first))
            {
                // and their lock is waiting...
                if (lock.second.GetWaiting() == true)
                {
                    deadlocks.push_back(lock);
                    threads.emplace(other_iter->first);
                    if (other_iter->first == tid && lock.first == c)
                    {
                        // we are back where we started and there is a deadlock
                        return true;
                    }
                    if (WriteRecursiveCheck(tid, c, other_iter->first, lock.first, false, deadlocks, threads))
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
    throw std::logic_error("self_deadlock_detected");
}

bool HasAnyOwners(void *c)
{
    auto iter = lockdata.writelocksheld.find(c);
    if (iter != lockdata.writelocksheld.end())
    {
        if (!iter->second.empty())
        {
            return true;
        }
    }

    auto iter2 = lockdata.readlocksheld.find(c);
    if (iter2 != lockdata.readlocksheld.end())
    {
        if (!iter2->second.empty())
        {
            return true;
        }
    }

    return false;
}

void AddNewLock(LockStackEntry newEntry, const uint64_t &tid)
{
    auto it = lockdata.locksheldbythread.find(tid);
    if (it == lockdata.locksheldbythread.end())
    {
        LockStack newLockStack;
        newLockStack.push_back(newEntry);
        lockdata.locksheldbythread.emplace(tid, newLockStack);
    }
    else
    {
        it->second.push_back(newEntry);
    }
}

void AddNewWaitingLock(void *c, const uint64_t &tid, bool &isExclusive)
{
    if (isExclusive)
    {
        auto it = lockdata.writelockswaiting.find(c);
        if (it == lockdata.writelockswaiting.end())
        {
            std::set<uint64_t> holders;
            holders.emplace(tid);
            lockdata.writelockswaiting.emplace(c, holders);
        }
        else
        {
            it->second.emplace(tid);
        }
    }
    else //  !isExclusive
    {
        auto it = lockdata.readlockswaiting.find(c);
        if (it == lockdata.readlockswaiting.end())
        {
            std::set<uint64_t> holders;
            holders.emplace(tid);
            lockdata.readlockswaiting.emplace(c, holders);
        }
        else
        {
            it->second.emplace(tid);
        }
    }
}

void SetWaitingToHeld(void *c, bool isExclusive)
{
	const uint64_t tid = getTid();
    if (isExclusive)
    {
        auto it = lockdata.writelockswaiting.find(c);
        if (it == lockdata.writelockswaiting.end())
        {
            return;
        }
        else
        {
            it->second.erase(tid);
            auto iter = lockdata.writelocksheld.find(c);
            if (iter == lockdata.writelocksheld.end())
            {
                std::set<uint64_t> holders;
                holders.emplace(tid);
                lockdata.writelocksheld.emplace(c, holders);
            }
            else
            {
                iter->second.emplace(tid);
            }
        }
    }
    else //  !isExclusive
    {
        auto it = lockdata.readlockswaiting.find(c);
        if (it == lockdata.readlockswaiting.end())
        {
            return;
        }
        else
        {
            it->second.erase(tid);
            auto iter = lockdata.readlocksheld.find(c);
            if (iter == lockdata.readlocksheld.end())
            {
                std::set<uint64_t> holders;
                holders.emplace(tid);
                lockdata.readlocksheld.emplace(c, holders);
            }
            else
            {
                iter->second.emplace(tid);
            }
        }
    }

    auto itheld = lockdata.locksheldbythread.find(tid);
    if (itheld != lockdata.locksheldbythread.end())
    {
        for (auto rit = itheld->second.rbegin(); rit != itheld->second.rend(); ++rit)
        {
            if (rit->first == c)
            {
                rit->second.ChangeWaitingToHeld();
                break;
            }
        }
    }
}

// c = the cs
// isExclusive = is the current lock exclusive, for a recursive mutex (CCriticalSection) this value should always be
// true
void push_lock(void *c, const CLockLocation &locklocation, LockType type, bool isExclusive, bool fTry)
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);

    LockStackEntry now = std::make_pair(c, locklocation);
    // tid of the originating request
    const uint64_t tid = getTid();
    // If this is a blocking lock operation, we want to make sure that the locking order between 2 mutexes is consistent
    // across the program
    if (fTry)
    {
        // a try lock will either get it, or it wont. so just add it.
        // if we dont get the lock this will be undone in destructor
        AddNewLock(now, tid);
        // AddNewWaitingLock(c, tid, isExclusive);
        return;
    }
    // first check lock specific issues
    if (type == LockType::SHARED)
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
                {
                    self_deadlock_detected(now, lockStackLock);
                }
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
                    {
                        self_deadlock_detected(now, lockStackLock);
                    }
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
    AddNewLock(now, tid);
    AddNewWaitingLock(c, tid, isExclusive);

    // if we have exclusive lock(s) and we arent requesting an exclusive lock...
    if (!isExclusive)
    {
    TEST_5:
    TEST_8:
        std::vector<LockStackEntry> deadlocks;
        std::set<uint64_t> threads;
        // then we can only deadlock if we are locking a thread that is currently held in exclusive state by someone
        // else
        if (ReadRecursiveCheck(tid, c, tid, c, true, deadlocks, threads))
        {
            // we have a deadlock where we are requesting shared ownership on a mutex that is exclusively owned by
            // another thread which has either a shared or exlcusive request on a mutex we have exclusive ownership over
            potential_deadlock_detected(now, deadlocks, threads);
        }
    }
    // if we have exclusive lock(s) and we are requesting another exclusive lock
    if (isExclusive)
    {
    TEST_6:
    TEST_7:
    TEST_9:
        std::vector<LockStackEntry> deadlocks;
        std::set<uint64_t> threads;
        if (WriteRecursiveCheck(tid, c, tid, c, true, deadlocks, threads))
        {
            potential_deadlock_detected(now, deadlocks, threads);
        }
    }
}

// remove removes 1 instance of the lock, delete removes all instances

void DeleteLock(void *cs)
{
    // remove all instances of the critical section from lockdata
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    if (!lockdata.available)
    {
        // lockdata was already deleted
        return;
    }
    if (lockdata.readlockswaiting.count(cs))
        lockdata.readlockswaiting.erase(cs);
    if (lockdata.writelockswaiting.count(cs))
        lockdata.writelockswaiting.erase(cs);
    if (lockdata.readlocksheld.count(cs))
        lockdata.readlocksheld.erase(cs);
    if (lockdata.writelocksheld.count(cs))
        lockdata.writelocksheld.erase(cs);
    for (auto &iter : lockdata.locksheldbythread)
    {
        LockStack newStack;
        for (auto &iter2 : iter.second)
        {
            if (iter2.first != cs)
            {
                newStack.emplace_back(std::make_pair(iter2.first, iter2.second));
            }
        }
        std::swap(iter.second, newStack);
    }
}

void _remove_lock_critical_exit(void *cs)
{
    if (!lockdata.available)
    {
        // lockdata was already deleted
        return;
    }
    uint64_t tid = getTid();
    bool isExclusive = false;
    bool fTry = false;
    auto it = lockdata.locksheldbythread.find(tid);
    if (it == lockdata.locksheldbythread.end())
    {
        throw std::logic_error("unlocking non-existant lock");
    }
    else
    {
        if (it->second.back().first != cs)
        {
            LogPrintf("got %s but was not expecting it\n", it->second.back().second.ToString().c_str());
            throw std::logic_error("unlock order inconsistant with lock order");
        }
        isExclusive = it->second.back().second.GetExclusive();
        fTry = it->second.back().second.GetTry();
        it->second.pop_back();
    }
    // remove from the other maps
    if (isExclusive)
    {
        if (fTry)
        {
            auto iter = lockdata.writelockswaiting.find(cs);
            if (iter != lockdata.writelockswaiting.end())
            {
                if (iter->second.empty())
                    return;
                if (iter->second.count(tid) != 0)
                {
                    iter->second.erase(tid);
                }
            }
        }
        else
        {
            auto iter = lockdata.writelocksheld.find(cs);
            if (iter != lockdata.writelocksheld.end())
            {
                if (iter->second.empty())
                    return;
                if (iter->second.count(tid) != 0)
                {
                    iter->second.erase(tid);
                }
            }
        }
    }
    else // !isExclusive
    {
        if (fTry)
        {
            auto iter = lockdata.readlockswaiting.find(cs);
            if (iter != lockdata.readlockswaiting.end())
            {
                if (iter->second.empty())
                    return;
                if (iter->second.count(tid) != 0)
                {
                    iter->second.erase(tid);
                }
            }
        }
        else
        {
            auto iter = lockdata.readlocksheld.find(cs);
            if (iter != lockdata.readlocksheld.end())
            {
                if (iter->second.empty())
                    return;
                if (iter->second.count(tid) != 0)
                {
                    iter->second.erase(tid);
                }
            }
        }
    }
}

void remove_lock_critical_exit(void *cs)
{
    // assuming we unlock in the reverse order of locks, we can simply pop back
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    _remove_lock_critical_exit(cs);
}

std::string _LocksHeld()
{
    std::string result;
    uint64_t tid = getTid();
    auto self_iter = lockdata.locksheldbythread.find(tid);
    if (self_iter != lockdata.locksheldbythread.end())
    {
        for (auto &entry : self_iter->second)
        {
            result += entry.second.ToString() + std::string("\n");
        }
    }
    return result;
}

std::string LocksHeld()
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    return _LocksHeld();
}

void AssertLockHeldInternal(const char *pszName, const char *pszFile, unsigned int nLine, void *cs)
{
    std::lock_guard<std::mutex> lock(lockdata.dd_mutex);
    uint64_t tid = getTid();
    auto self_iter = lockdata.locksheldbythread.find(tid);
    if (self_iter == lockdata.locksheldbythread.end())
    {
        return;
    }
    if (self_iter->second.empty())
    {
        return;
    }
    for (auto &entry : self_iter->second)
    {
        if (entry.first == cs)
        {
            // found the lock so return
            return;
        }
    }
    fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
        _LocksHeld().c_str());
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
                    _LocksHeld().c_str());
                abort();
            }
        }
    }
}

#endif // DEBUG_LOCKORDER
