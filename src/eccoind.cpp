// This file is part of the Eccoin project
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "args.h"
#include "clientversion.h"
#include "httprpc.h"
#include "httpserver.h"
#include "init.h"
#include "networks/netman.h"
#include "rpc/rpcserver.h"
#include "sync.h"
#include "threadgroup.h"
#include "util/logger.h"
#include "util/util.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#include <stdio.h>

void WaitForShutdown(thread_group *threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (fShutdown == false)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char *argv[])
{
    shutdown_threads.store(false);
    thread_group threadGroup(&shutdown_threads);

    bool fRet = false;

    //
    // Parameters
    //
    gArgs.ParseParameters(argc, argv);

    // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    try
    {
        CheckParams(ChainNameFromCommandLine());
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }
    try
    {
        gArgs.ReadConfigFile();
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Error reading configuration file: %s\n", e.what());
        return false;
    }

    GenerateNetworkTemplates();

    // Process help and version before taking care about datadir
    if (gArgs.IsArgSet("-?") || gArgs.IsArgSet("-h") || gArgs.IsArgSet("-help") || gArgs.IsArgSet("-version"))
    {
        std::string strUsage = "Eccoind version " + FormatFullVersion() + "\n";

        if (gArgs.IsArgSet("-version"))
        {
            strUsage += LicenseInfo();
        }
        else
        {
            strUsage += "\nUsage:\neccoind [options]                     Start Eccoind\n";

            strUsage += "\n" + HelpMessage();
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return false;
    }

    try
    {
        if (!fs::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n",
                gArgs.GetArg("-datadir", "").c_str());
            return false;
        }
        // Command-line RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
        {
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "ECC:"))
            {
                fCommandLine = true;
            }
        }
        if (fCommandLine)
        {
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        }
#ifndef WIN32
        fDaemon = gArgs.GetBoolArg("-daemon", false);
        if (fDaemon)
        {
            fprintf(stdout, "Eccoind server starting\n");

            // Daemonize
            pid_t pid = fork();
            if (pid < 0)
            {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
                return false;
            }
            if (pid > 0) // Parent process, pid is child process id
            {
                return true;
            }
            // Child process falls through to rest of initialization

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        gArgs.SoftSetBoolArg("-server", true);
        // Set this early so that parameter interactions go to console
        InitLogging();
        InitParameterInteraction();
        fRet = AppInit2(threadGroup);
    }
    catch (const std::exception &e)
    {
        PrintExceptionContinue(&e, "AppInit()");
    }
    catch (...)
    {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet)
    {
        Interrupt(threadGroup);
    }
    else
    {
        WaitForShutdown(&threadGroup);
    }
    Shutdown(threadGroup);

    return fRet;
}

int main(int argc, char *argv[])
{
    SetupEnvironment();

    return (AppInit(argc, argv) ? 0 : 1);
}
