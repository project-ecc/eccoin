// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2018-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_LOGGER_H
#define ECCOIN_LOGGER_H

#include "tinyformat.h"

#include <list>
#include <mutex>
#include <mutex>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;
extern volatile bool fReopenDebugLog;

class CLogger
{
private:
    FILE *fileout;
    mutable std::mutex mutexDebugLog;
    std::list<std::string> vMsgsBeforeOpenLog;

public:
    bool fLogTimestamps;
    bool fLogTimeMicros;
    bool fLogIPs;

    bool fDebug;
    bool fPrintToConsole;
    bool fPrintToDebugLog;

private:
    // Disallow copies
    CLogger(const CLogger &);
    CLogger &operator=(const CLogger &);

    std::string LogTimestampStr(const std::string &str, bool *fStartedNewLine);

    int FileWriteStr(const std::string &str, FILE *fp);

public:
    CLogger()
    {
        fileout = nullptr;
        vMsgsBeforeOpenLog.clear();

        fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
        fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
        fLogIPs = DEFAULT_LOGIPS;
        fDebug = false;
        fPrintToConsole = false;
        fPrintToDebugLog = true;
    }
    void OpenDebugLog();

    /** Return true if log accepts specified category */
    bool LogAcceptCategory(const char *category);

    /** Send a string to the log output */
    int LogPrintStr(const std::string &str);

    void ShrinkDebugFile();
};
extern std::unique_ptr<CLogger> g_logger;


#define LogPrintf(...) LogPrint(NULL, __VA_ARGS__)

/**
 * Zero-arg versions of logging and error, these are not covered by
 * TINYFORMAT_FOREACH_ARGNUM
 */
static inline int LogPrint(const char *category, const char *format)
{
    if (!g_logger->LogAcceptCategory(category))
        return 0;
    return g_logger->LogPrintStr(format);
}
static inline bool error(const char *format)
{
    g_logger->LogPrintStr(std::string("ERROR: ") + format + "\n");
    return false;
}

void PrintException(const std::exception *pex, const char *pszThread);
void PrintExceptionContinue(const std::exception *pex, const char *pszThread);


/**
 * When we switch to C++11, this can be switched to variadic templates instead
 * of this macro-based construction (see tinyformat.h).
 */
#define MAKE_ERROR_AND_LOG_FUNC(n)                                                              \
    /**   Print to debug.log if -debug=category switch is given OR category is NULL. */         \
    template <TINYFORMAT_ARGTYPES(n)>                                                           \
    static inline int LogPrint(const char *category, const char *format, TINYFORMAT_VARARGS(n)) \
    {                                                                                           \
        if (!g_logger->LogAcceptCategory(category))                                             \
            return 0;                                                                           \
        return g_logger->LogPrintStr(tfm::format(format, TINYFORMAT_PASSARGS(n)));              \
    }                                                                                           \
    /**   Log error and return false */                                                         \
    template <TINYFORMAT_ARGTYPES(n)>                                                           \
    static inline bool error(const char *format, TINYFORMAT_VARARGS(n))                         \
    {                                                                                           \
        g_logger->LogPrintStr("ERROR: " + tfm::format(format, TINYFORMAT_PASSARGS(n)) + "\n");  \
        return false;                                                                           \
    }

TINYFORMAT_FOREACH_ARGNUM(MAKE_ERROR_AND_LOG_FUNC)


#endif
