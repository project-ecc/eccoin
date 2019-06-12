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
#endif
