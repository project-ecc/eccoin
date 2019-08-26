// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * thread wrappers
 */
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#include "compat.h"
#include "fs.h"
#include "tinyformat.h"
#include "util/logger.h"
#include "util/utiltime.h"

#include <atomic>
#include <exception>
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/signals2/signal.hpp>
#include <boost/thread/exceptions.hpp>

#define UNIQUE2(pfx, LINE) pfx##LINE
#define UNIQUE1(pfx, LINE) UNIQUE2(pfx, LINE)
/// UNIQUIFY is a macro that appends the current file's line number to the passed prefix, creating a symbol
// that is unique in this file.
#define UNIQUIFY(pfx) UNIQUE1(pfx, __LINE__)

#ifdef DEBUG_ASSERTION
/// If DEBUG_ASSERTION is enabled this asserts when the predicate is false.
//  If DEBUG_ASSERTION is disabled and the predicate is false, it executes the execInRelease statements.
//  Typically, the programmer will error out -- return false, raise an exception, etc in the execInRelease code.
//  DO NOT USE break or continue inside the DbgAssert!
#define DbgAssert(pred, execInRelease) assert(pred)
#else
#define DbgStringify(x) #x
#define DbgStringifyIntLiteral(x) DbgStringify(x)
#define DbgAssert(pred, execInRelease)                                                                        \
    do                                                                                                        \
    {                                                                                                         \
        if (!(pred))                                                                                          \
        {                                                                                                     \
            g_logger->LogPrintStr(std::string(                                                                \
                __FILE__ "(" DbgStringifyIntLiteral(__LINE__) "): Debug Assertion failed: \"" #pred "\"\n")); \
            execInRelease;                                                                                    \
        }                                                                                                     \
    } while (0)
#endif

extern bool fDaemon;
extern bool fServer;
extern std::string strMiscWarning;

extern const char *const CONF_FILENAME;
extern const char *const PID_FILENAME;


void SetupEnvironment();
bool SetupNetworking();

void ParseParameters(int argc, const char *const argv[]);
void FileCommit(FILE *fileout);
bool TruncateFile(FILE *file, unsigned int length);
int RaiseFileDescriptorLimit(int nMinFD);
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length);
bool RenameOver(fs::path src, fs::path dest);
bool TryCreateDirectory(const fs::path &p);
fs::path GetDefaultDataDir();
const fs::path &GetDataDir(bool fNetSpecific = true);
void ClearDatadirCache();
#ifndef WIN32
fs::path GetPidFile();
void CreatePidFile(const fs::path &path, pid_t pid);
#endif
#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif
fs::path GetTempPath();
void runCommand(const std::string &strCommand);

inline bool IsSwitchChar(char c)
{
#ifdef WIN32
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}


/**
 * Format a string to be used as group of options in help messages
 *
 * @param message Group name (e.g. "RPC server options:")
 * @return the formatted string
 */
std::string HelpMessageGroup(const std::string &message);

/**
 * Format a string to be used as option description in help messages
 *
 * @param option Option message (e.g. "-rpcuser=<user>")
 * @param message Option description (e.g. "Username for JSON-RPC connections")
 * @return the formatted string
 */
std::string HelpMessageOpt(const std::string &option, const std::string &message);

/**
 * Return the number of physical cores available on the current system.
 * @note This does not count virtual cores, such as those provided by HyperThreading
 * when boost is newer than 1.56.
 */
int GetNumCores();

void SetThreadPriority(int nPriority);
void RenameThread(const char *name);

inline int64_t roundint64(double d) { return (int64_t)(d > 0 ? d + 0.5 : d - 0.5); }
bool WildcardMatch(const char *psz, const char *mask);
bool WildcardMatch(const std::string &str, const std::string &mask);

inline uint32_t ByteReverse(uint32_t value)
{
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return (value << 16) | (value >> 16);
}

long hex2long(const char *hexString);

//! Substitute for C++14 std::make_unique.
template <typename T, typename... Args>
std::unique_ptr<T> MakeUnique(Args &&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}


#endif // BITCOIN_UTIL_H
