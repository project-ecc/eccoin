// Copyright (c) 2019 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sync.h"

#include "test/test_bitcoin.h"

struct EmptySuite
{
    EmptySuite()
    {
        ECC_Start();
        SetupEnvironment();
        SetupNetworking();
        g_logger->fPrintToDebugLog = false; // don't want to write to debug.log file
    }

    ~EmptySuite() { ECC_Stop(); }
};
