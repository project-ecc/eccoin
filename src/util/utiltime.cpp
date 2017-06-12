
#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "utiltime.h"
#include "util.h"
#include "ui_interface.h"


#include <atomic>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread.hpp>
#include <boost/foreach.hpp>

std::string strMiscWarning;


static std::atomic<int64_t> nMockTime(0); //!< For unit testing

CMedianFilter<int64_t> vTimeOffsets(200,0);

static int64_t nTimeOffset = 0;

int64_t GetTimeOffset()
{
    return nTimeOffset;
}

int64_t GetAdjustedTime()
{
    return GetTime() + GetTimeOffset();
}

int64_t GetTime()
{
    int64_t mocktime = nMockTime.load(std::memory_order_relaxed);
    if (mocktime) return mocktime;

    time_t now = time(NULL);
    assert(now > 0);
    return now;
}

void SetMockTime(int64_t nMockTimeIn)
{
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

int64_t GetMockTime()
{
    return nMockTime.load(std::memory_order_relaxed);
}

int64_t GetTimeMillis()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
    assert(now > 0);
    return now;
}

int64_t GetTimeMicros()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_microseconds();
    assert(now > 0);
    return now;
}

int64_t GetSystemTimeInSeconds()
{
    return GetTimeMicros()/1000000;
}

void MilliSleep(int64_t n)
{

/**
 * Boost's sleep_for was uninterruptible when backed by nanosleep from 1.50
 * until fixed in 1.52. Use the deprecated sleep method for the broken case.
 * See: https://svn.boost.org/trac/boost/ticket/7238
 */
#if BOOST_VERSION >= 105000
    boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
#else
    boost::this_thread::sleep(boost::posix_time::milliseconds(n));
#endif
}

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime)
{
    static std::locale classic(std::locale::classic());
    // std::locale takes ownership of the pointer
    std::locale loc(classic, new boost::posix_time::time_facet(pszFormat));
    std::stringstream ss;
    ss.imbue(loc);
    ss << boost::posix_time::from_time_t(nTime);
    return ss.str();
}

inline int64_t abs64(int64_t n)
{
    return (n >= 0 ? n : -n);
}

void AddTimeData(const CNetAddr& ip, int64_t nTime)
{
    int64_t nOffsetSample = nTime - GetTime();

    // Ignore duplicates
    static std::set<CNetAddr> setKnown;
    if (!setKnown.insert(ip).second)
        return;

    // Add data
    vTimeOffsets.input(nOffsetSample);
    LogPrintf("Added time data, samples %d, offset %+d (%+d minutes)\n", vTimeOffsets.size(), nOffsetSample, nOffsetSample/60);
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1)
    {
        int64_t nMedian = vTimeOffsets.median();
        std::vector<int64_t> vSorted = vTimeOffsets.sorted();
        // Only let other nodes change our time by so much
        if (abs64(nMedian) < 70 * 60)
        {
            nTimeOffset = nMedian;
        }
        else
        {
            nTimeOffset = 0;

            static bool fDone;
            if (!fDone)
            {
                // If nobody has a time different than ours but within 5 minutes of ours, give a warning
                bool fMatch = false;
                BOOST_FOREACH(int64_t nOffset, vSorted)
                    if (nOffset != 0 && abs64(nOffset) < 5 * 60)
                        fMatch = true;

                if (!fMatch)
                {
                    fDone = true;
                    std::string strMessage = _("Warning: Please check that your computer's date and time are correct! If your clock is wrong ECCoin will not work properly.");
                    strMiscWarning = strMessage;
                    LogPrintf("*** %s\n", strMessage.c_str());
                    uiInterface.ThreadSafeMessageBox(strMessage+" ", std::string("ECCoin"), CClientUIInterface::BTN_OK | CClientUIInterface::ICON_WARNING);
                }
            }
        }
        if (fDebug) {
            BOOST_FOREACH(int64_t n, vSorted)
                LogPrintf("%+d  ", n);
            LogPrintf("|  ");
        }
        LogPrintf("nTimeOffset = %+d  (%+d minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}

