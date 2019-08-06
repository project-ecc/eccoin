// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "args.h"
#include "util/util.h"

#include "networks/netman.h"
#include "random.h"
#include "serialize.h"
#include "util/utilstrencodings.h"
#include "util/utiltime.h"

#include <stdarg.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#else

#ifdef _MSC_VER
#pragma warning(disable : 4786)
#pragma warning(disable : 4804)
#pragma warning(disable : 4805)
#pragma warning(disable : 4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <shlobj.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
#include <malloc.h>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/program_options/detail/config_file.hpp>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

CArgsManager gArgs;

/** Interpret string as boolean, for argument parsing */
bool InterpretBool(const std::string &strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

/** Turn -noX into -X=0 */
void InterpretNegativeSetting(std::string &strKey, std::string &strValue)
{
    if (strKey.length() > 3 && strKey[0] == '-' && strKey[1] == 'n' && strKey[2] == 'o')
    {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void CArgsManager::ParseParameters(int argc, const char *const argv[])
{
    LOCK(cs_args);
    mapArgs.clear();
    mapMultiArgs.clear();

    for (int i = 1; i < argc; i++)
    {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos)
        {
            strValue = str.substr(is_index + 1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);
        InterpretNegativeSetting(str, strValue);

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);
    }
}

std::vector<std::string> CArgsManager::GetArgs(const std::string &strArg)
{
    LOCK(cs_args);
    if (IsArgSet(strArg))
        return mapMultiArgs.at(strArg);
    return {};
}

std::map<std::string, std::string> CArgsManager::GetMapArgs()
{
    LOCK(cs_args);
    return mapArgs;
}

bool CArgsManager::IsArgSet(const std::string &strArg)
{
    LOCK(cs_args);
    return mapArgs.count(strArg);
}

std::string CArgsManager::GetArg(const std::string &strArg, const std::string &strDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t CArgsManager::GetArg(const std::string &strArg, int64_t nDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool CArgsManager::GetBoolArg(const std::string &strArg, bool fDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return InterpretBool(mapArgs[strArg]);
    return fDefault;
}

bool CArgsManager::SoftSetArg(const std::string &strArg, const std::string &strValue)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return false;
    ForceSetArg(strArg, strValue);
    return true;
}

bool CArgsManager::SoftSetBoolArg(const std::string &strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

void CArgsManager::ForceSetArg(const std::string &strArg, const std::string &strValue)
{
    LOCK(cs_args);
    mapArgs[strArg] = strValue;
    mapMultiArgs[strArg].clear();
    mapMultiArgs[strArg].push_back(strValue);
}

extern fs::path pathCached;
extern fs::path pathCachedNetSpecific;
extern CCriticalSection csPathCached;

fs::path CArgsManager::GetConfigFile()
{
    fs::path pathConfigFile(GetArg("-conf", CONF_FILENAME));
    if (!pathConfigFile.is_complete())
        pathConfigFile = GetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

void CArgsManager::ReadConfigFile()
{
init:
    fs::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good())
    {
        fs::path ConfPath = GetDataDir(false) / "eccoin.conf";
        FILE *ConfFile = fopen(ConfPath.string().c_str(), "w");
        fprintf(ConfFile, "rpcuser=yourusername\n");
        fprintf(ConfFile, "rpcpassword=yourpassword\n");
        fprintf(ConfFile, "rpcport=19119\n");
        fprintf(ConfFile, "rpcconnect=127.0.0.1\n");
        fprintf(ConfFile, "rpcallowip=127.0.0.1\n");
        fclose(ConfFile);
        goto init;
    }

    std::set<std::string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override eccoin.conf
        std::string strKey = std::string("-") + it->string_key;
        std::string strValue = it->value[0];
        InterpretNegativeSetting(strKey, strValue);
        if (mapArgs.count(strKey) == 0)
            mapArgs[strKey] = strValue;
        mapMultiArgs[strKey].push_back(strValue);
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}
