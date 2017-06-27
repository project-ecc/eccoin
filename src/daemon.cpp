#include "rpc/bitcoinrpc.h"
#include "compat.h"
#include "fs.h"
#include "init.h"
#include "noui.h"
#include "util/util.h"
#include "util/utilstrencodings.h"
#include <boost/thread.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <stdio.h>

boost::thread_group ecc_threads;
bool AppInit(int argc, char* argv[]);

//
// Start
//
int main(int argc, char* argv[])
{
    SetupEnvironment();

    // Connect bitcoind signal handlers
    noui_connect();

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
}


bool AppInit(int argc, char* argv[])
{
    bool fRet = false;

    //
    // Parameters
    //
    // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
    ParseParameters(argc, argv);

    // Process help and version before taking care about datadir
    if (IsArgSet("-?") || IsArgSet("-h") ||  IsArgSet("-help") || IsArgSet("-version"))
    {
        std::string strUsage = strprintf(_("%s Daemon"), _("E-Currency Coin")) + " " + _("version") + " " + FormatFullVersion() + "\n";

        if (IsArgSet("-version"))
        {
            strUsage += FormatParagraph(LicenseInfo());
        }
        else
        {
            strUsage += "\n" + _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + strprintf(_("Start %s Daemon"), _("E-Currency Coin")) + "\n";

            strUsage += "\n" + HelpMessage();
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }
    bool fCommandLine = false;

    try
    {
        if (!fs::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", GetArg("-datadir", "").c_str());
            return false;
        }
        try
        {
            ReadConfigFile();
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }

        // Command-line RPC
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "ECCoin:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        }


        // Set this early so that parameter interactions go to console
        InitLogging();
        if(!InitParameterInteraction())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }

        if (!AppInitBasicSetup())
        {
            // InitError will have been called with detailed error, which ends up on console
            exit(EXIT_FAILURE);
        }

        fRet = AppInit2();
	if (fRet && fDaemon)
            return 0;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet)
    {
            Shutdown();
    }
    return fRet;
}

