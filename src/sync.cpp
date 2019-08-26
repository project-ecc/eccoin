// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sync.h"

#include "util/logger.h"
#include "util/util.h"
#include "util/utilstrencodings.h"

#include <stdio.h>
#include <thread>

#ifdef DEBUG_LOCKORDER // this define covers the rest of the file

void EnterCritical(const char *pszName,
    const char *pszFile,
    unsigned int nLine,
    void *cs,
    LockType locktype,
    OwnershipType ownership,
    bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine, fTry, ownership, locktype), locktype, ownership, fTry);
}

void LeaveCritical(void *cs) { remove_lock_critical_exit(cs); }
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
CSharedCriticalSection::CSharedCriticalSection() : name(NULL) {}
CSharedCriticalSection::CSharedCriticalSection(const char *n) : name(n)
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

CRecursiveSharedCriticalSection::CRecursiveSharedCriticalSection() : name(NULL) {}
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
