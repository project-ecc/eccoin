// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Copyright (c) 2018-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "args.h"
#include "logger.h"
#include "fs.h"
#include "serialize.h"
#include "util.h"
#include "utiltime.h"
#include <set>

#include <boost/thread/tss.hpp>

std::unique_ptr<CLogger> g_logger;
volatile bool fReopenDebugLog = false;

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
std::string CLogger::LogTimestampStr(const std::string &str, bool *fStartedNewLine)
{
    std::string strStamped;

    if (!fLogTimestamps)
        return str;

    if (*fStartedNewLine)
    {
        int64_t nTimeMicros = GetLogTimeMicros();
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros / 1000000);
        if (fLogTimeMicros)
            strStamped += strprintf(".%06d", nTimeMicros % 1000000);
        strStamped += ' ' + str;
    }
    else
        strStamped = str;

    if (!str.empty() && str[str.size() - 1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

int CLogger::FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

void CLogger::OpenDebugLog()
{
    fs::path pathDebug = GetDataDir() / "debug.log";

    std::lock_guard<std::mutex> scoped_lock(mutexDebugLog);
    assert(fileout == nullptr);
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout)
        setbuf(fileout, nullptr); // unbuffered

    // dump buffered messages from before we opened the log
    while (!vMsgsBeforeOpenLog.empty())
    {
        FileWriteStr(vMsgsBeforeOpenLog.front(), fileout);
        vMsgsBeforeOpenLog.pop_front();
    }
}

bool CLogger::LogAcceptCategory(const char *category)
{
    if (category != nullptr)
    {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<std::set<std::string> > ptrCategory;
        if (ptrCategory.get() == NULL)
        {
            const std::vector<std::string> &categories = gArgs.GetArgs("-debug");
            ptrCategory.reset(new std::set<std::string>(categories.begin(), categories.end()));
            // thread_specific_ptr automatically deletes the set when the thread ends.
        }
        const std::set<std::string> &setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(std::string("")) == 0 && setCategories.count(std::string("1")) == 0 &&
            setCategories.count(std::string(category)) == 0)
            return false;
    }
    return true;
}

int CLogger::LogPrintStr(const std::string &str)
{
    std::lock_guard<std::mutex> scoped_lock(mutexDebugLog);
    int ret = 0; // Returns total number of characters written
    static bool fStartedNewLine = true;

    std::string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        // buffer if we haven't opened the log yet
        if (fileout == nullptr)
        {
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog.push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog)
            {
                fReopenDebugLog = false;
                fs::path pathDebug = GetDataDir() / "debug.log";
                if (freopen(pathDebug.string().c_str(), "a", fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

void CLogger::ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    fs::path pathLog = GetDataDir() / "debug.log";
    FILE *file = fopen(pathLog.string().c_str(), "r");
    if (file && fs::file_size(pathLog) > 20000)
    {
        // Restart the file with some of the end
        std::vector<char> vch(200000, 0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(begin_ptr(vch), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file)
        {
            fwrite(begin_ptr(vch), 1, nBytes, file);
            fclose(file);
        }
    }
    else if (file != nullptr)
        fclose(file);
}

static std::string FormatException(const std::exception *pex, const char *pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char *pszModule = "eccoin";
#endif
    if (pex)
        return strprintf("EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(),
            pszModule, pszThread);
    else
        return strprintf("UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintException(const std::exception *pex, const char *pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    throw;
}


void PrintExceptionContinue(const std::exception *pex, const char *pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
}
