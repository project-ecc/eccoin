/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
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

#include "util/util.h"
#include "util/utilstrencodings.h"

#include <stdio.h>

#include <boost/thread.hpp>

#ifdef DEBUG_LOCKCONTENTION
void PrintLockContention(const char *pszName, const char *pszFile, int nLine)
{
    LogPrintf("LOCKCONTENTION: %s\n", pszName);
    LogPrintf("Locker: %s:%d\n", pszFile, nLine);
}
#endif /* DEBUG_LOCKCONTENTION */

#ifdef DEBUG_LOCKORDER
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

    std::string MutexName() const { return mutexName; }
    bool fTry;

private:
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
};

typedef std::vector<std::pair<void *, CLockLocation> > LockStack;

static boost::mutex dd_mutex;
static std::map<std::pair<void *, void *>, LockStack> lockorders;
static boost::thread_specific_ptr<LockStack> lockstack;


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
    for (auto const &i : s2)
    {
        if (i.first == mismatch.first)
        {
            LogPrintf(" (1)");
            if (!firstLocked && secondLocked && i.second.fTry)
                onlyMaybeDeadlock = true;
            firstLocked = true;
        }
        if (i.first == mismatch.second)
        {
            LogPrintf(" (2)");
            if (!secondLocked && firstLocked && i.second.fTry)
                onlyMaybeDeadlock = true;
            secondLocked = true;
        }
        LogPrintf(" %s\n", i.second.ToString());
    }
    firstLocked = false;
    secondLocked = false;
    LogPrintf("Current lock order is:\n");
    for (auto const &i : s1)
    {
        if (i.first == mismatch.first)
        {
            LogPrintf(" (1)");
            if (!firstLocked && secondLocked && i.second.fTry)
                onlyMaybeDeadlock = true;
            firstLocked = true;
        }
        if (i.first == mismatch.second)
        {
            LogPrintf(" (2)");
            if (!secondLocked && firstLocked && i.second.fTry)
                onlyMaybeDeadlock = true;
            secondLocked = true;
        }
        LogPrintf(" %s\n", i.second.ToString());
    }
    assert(onlyMaybeDeadlock);
}

static void push_lock(void *c, const CLockLocation &locklocation, bool fTry)
{
    if (lockstack.get() == NULL)
        lockstack.reset(new LockStack);

    dd_mutex.lock();

    (*lockstack).push_back(std::make_pair(c, locklocation));

    if (!fTry)
    {
        for (auto const &i : (*lockstack))
        {
            if (i.first == c)
                break;

            std::pair<void *, void *> p1 = std::make_pair(i.first, c);
            if (lockorders.count(p1))
                continue;
            lockorders[p1] = (*lockstack);

            std::pair<void *, void *> p2 = std::make_pair(c, i.first);
            if (lockorders.count(p2))
                potential_deadlock_detected(p1, lockorders[p2], lockorders[p1]);
        }
    }
    dd_mutex.unlock();
}

static void pop_lock()
{
    dd_mutex.lock();
    (*lockstack).pop_back();
    dd_mutex.unlock();
}

void EnterCritical(const char *pszName, const char *pszFile, int nLine, void *cs, bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine, fTry), fTry);
}

void LeaveCritical() { pop_lock(); }
std::string LocksHeld()
{
    std::string result;
    for (auto const &i : *lockstack)
        result += i.second.ToString() + std::string("\n");
    return result;
}

void AssertLockHeldInternal(const char *pszName, const char *pszFile, int nLine, void *cs)
{
    for (auto const &i : *lockstack)
        if (i.first == cs)
            return;
    fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine,
        LocksHeld().c_str());
    abort();
}

#endif /* DEBUG_LOCKORDER */
