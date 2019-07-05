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

void EnterCritical(const char *pszName, const char *pszFile, unsigned int nLine, void *cs, LockType type, bool isExclusive, bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine, fTry, isExclusive), type, isExclusive, fTry);
}

void LeaveCritical() { remove_lock_critical_exit(); }

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
