#include "sync.h"
#include "sync_rsm.h"

#include "util/logger.h"
#include "util/util.h"
#include "util/utilstrencodings.h"

#include <stdio.h>
#include <thread>

#ifdef DEBUG_LOCKORDER
CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection() : name(NULL), exclusiveOwner(0) {}
CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection(const char *n) : name(n), exclusiveOwner(0)
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

void CRecursiveSharedCriticalSection::lock_shared()
{
    uint64_t tid = getTid();
    // detect recursive locking
    {
        std::unique_lock<std::mutex> lock(setlock);
        auto alreadyLocked = sharedowners.find(tid);
        if (alreadyLocked != sharedowners.end())
        {
            LockInfoRecursive li = alreadyLocked->second;
            LogPrintf("already locked at %s:%d, incrementing shared lock by 1 to %u\n", li.file, li.line, li.count++);
            alreadyLocked->second.count++;

        }
        else
        {
            sharedowners[tid] = LockInfoRecursive("", 0, 1);
        }
    }
    internal_lock.lock_shared();
}

void CRecursiveSharedCriticalSection::unlock_shared()
{
    // detect recursive locking
    uint64_t tid = getTid();
    {
        std::unique_lock<std::mutex> lock(setlock);
        auto alreadyLocked = sharedowners.find(tid);
        if (alreadyLocked == sharedowners.end())
        {
            LockInfoRecursive li = alreadyLocked->second;
            LogPrintf("never locked at %s:%d\n", li.file, li.line);
            assert(alreadyLocked != sharedowners.end());
        }
        alreadyLocked->second.count--;
        if (alreadyLocked->second.count == 0)
        {
            sharedowners.erase(tid);
        }
    }
    internal_lock.unlock_shared();
}

bool CRecursiveSharedCriticalSection::try_lock_shared()
{
    uint64_t tid = getTid();
    std::unique_lock<std::mutex> lock(setlock);

    bool result = internal_lock.try_lock_shared();
    if (result)
    {
        auto alreadyLocked = sharedowners.find(tid);
        if (alreadyLocked == sharedowners.end())
        {
            sharedowners[tid] = LockInfoRecursive("", 0, 1);
        }
        else
        {
            alreadyLocked->second.count++;
        }
    }
    return result;
}
void CRecursiveSharedCriticalSection::lock()
{
    internal_lock.lock();
    exclusiveOwner = getTid();
    exclusiveOwnerCount++;
}
void CRecursiveSharedCriticalSection::unlock()
{
    uint64_t tid = getTid();
    assert(exclusiveOwner == tid);
    exclusiveOwnerCount--;
    if (exclusiveOwnerCount == 0)
    {
        exclusiveOwner = 0;
    }
    internal_lock.unlock();
}

bool CRecursiveSharedCriticalSection::try_lock()
{
    bool result = internal_lock.try_lock();
    if (result)
    {
        exclusiveOwner = getTid();
        exclusiveOwnerCount++;
    }
    return result;
}
#endif
