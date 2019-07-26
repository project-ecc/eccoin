// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Copyright (c) 2019 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_THREAD_DEADLOCK_H
#define ECCOIN_THREAD_DEADLOCK_H

#include <string>

#include "util/utilstrencodings.h"

enum LockType
{
    RECURSIVE, // CCriticalSection
    SHARED, // CSharedCriticalSection
    RECRUSIVESHARED, // CRecursiveSharedCriticalSection
};

#ifdef DEBUG_LOCKORDER
#include <sys/syscall.h>
#endif
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

#ifdef DEBUG_LOCKORDER // covers the entire file

struct CLockLocation
{
    CLockLocation(const char *pszName, const char *pszFile, int nLine, bool fTryIn, bool fExclusiveIn)
    {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
        fTry = fTryIn;
        fExclusive = fExclusiveIn;
        fWaiting = true;
    }

    std::string ToString() const
    {
        return mutexName + "  " + sourceFile + ":" + itostr(sourceLine) + (fTry ? " (TRY)" : "") +
               (fExclusive ? " (EXCLUSIVE)" : "") + (fWaiting ? " (WAITING)" : "");
    }

    bool GetTry() const { return fTry; }
    bool GetExclusive() const { return fExclusive; }
    bool GetWaiting() const { return fWaiting; }
    void ChangeWaitingToHeld() { fWaiting = false; }
private:
    bool fTry;
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
    bool fExclusive; // signifies Exclusive Ownership, this is always true for a CCriticalSection
    bool fWaiting; // determines if lock is held or is waiting to be held
};

void push_lock(void *c, const CLockLocation &locklocation, LockType type, bool isExclusive, bool fTry);
void DeleteLock(void *cs);
void _remove_lock_critical_exit(void *cs);
void remove_lock_critical_exit(void *cs);
std::string LocksHeld();
void SetWaitingToHeld(void *c, const uint64_t &tid, bool isExclusive);
bool HasAnyOwners(void *c);

#else // NOT DEBUG_LOCKORDER

static inline void SetWaitingToHeld(void *c, const uint64_t &tid, bool isExclusive) {}

#endif // END DEBUG_LOCKORDER

#endif
