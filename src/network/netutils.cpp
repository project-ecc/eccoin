#include "netutils.h"
#include "strlcpy.h"
#include "util/utilstrencodings.h"
#include <boost/algorithm/string.hpp>

bool fNameLookup = false;

enum Network ParseNetwork(std::string net)
{
    boost::algorithm::to_lower(net);
    if (net == "ipv4") return NET_IPV4;
    if (net == "ipv6") return NET_IPV6;
    if (net == "tor")  return NET_TOR;
    if (net == "i2p")  return NET_I2P;
    return NET_UNROUTABLE;
}

void SplitHostPort(std::string in, int &portOut, std::string &hostOut) {
    size_t colon = in.find_last_of(':');
    // if a : is found, and it either follows a [...], or no other : is in the string, treat it as port separator
    bool fHaveColon = colon != in.npos;
    bool fBracketed = fHaveColon && (in[0]=='[' && in[colon-1]==']'); // if there is a colon, and in[0]=='[', colon is not 0, so in[colon-1] is safe
    bool fMultiColon = fHaveColon && (in.find_last_of(':',colon-1) != in.npos);
    if (fHaveColon && (colon==0 || fBracketed || !fMultiColon)) {
        char *endp = NULL;
        int n = strtol(in.c_str() + colon + 1, &endp, 10);
        if (endp && *endp == 0 && n >= 0) {
            in = in.substr(0, colon);
            if (n > 0 && n < 0x10000)
                portOut = n;
        }
    }
    if (in.size()>0 && in[0] == '[' && in[in.size()-1] == ']')
        hostOut = in.substr(1, in.size()-2);
    else
        hostOut = in;
}
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions)
{
    if (pszName[0] == 0)
        return false;
    int port = portDefault;
    std::string hostname = "";
    SplitHostPort(std::string(pszName), port, hostname);

    std::vector<CNetAddr> vIP;
    bool fRet = LookupIntern(hostname.c_str(), vIP, nMaxSolutions, fAllowLookup);
    if (!fRet)
        return false;
    vAddr.resize(vIP.size());
    for (unsigned int i = 0; i < vIP.size(); i++)
        vAddr[i] = CService(vIP[i], port);
    return true;
}

bool Lookup(const char *pszName, CService& addr, int portDefault, bool fAllowLookup)
{
    std::vector<CService> vService;
    bool fRet = Lookup(pszName, vService, portDefault, fAllowLookup, 1);
    if (!fRet)
        return false;
    addr = vService[0];
    return true;
}

bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    if (pszName[0] == 0)
        return false;
    char psz[256];
    char *pszHost = psz;
    strlcpy(psz, pszName, sizeof(psz));
    if (psz[0] == '[' && psz[strlen(psz)-1] == ']')
    {
        pszHost = psz+1;
        psz[strlen(psz)-1] = 0;
    }

    return LookupIntern(pszHost, vIP, nMaxSolutions, fAllowLookup);
}

bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup)
{
    std::vector<CNetAddr> vIP;
    LookupHost(pszName, vIP, 1, fAllowLookup);
    if(vIP.empty())
        return false;
    addr = vIP.front();
    return true;
}

bool LookupHostNumeric(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions)
{
    return LookupHost(pszName, vIP, nMaxSolutions, false);
}

bool LookupNumeric(const char *pszName, CService& addr, int portDefault)
{
    return Lookup(pszName, addr, portDefault, false);
}

CService LookupNumeric(const char *pszName, int portDefault)
{
    CService addr;
    // "1.2:345" will fail to resolve the ip, but will still set the port.
    // If the ip fails to resolve, re-init the result.
    if(!Lookup(pszName, addr, portDefault, false))
        addr = CService();
    return addr;
}


bool LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    vIP.clear();

    {
        CNetAddr addr;
        if (addr.SetSpecial(std::string(pszName))) {
            vIP.push_back(addr);
            return true;
        }
    }

    struct addrinfo aiHint;
    memset(&aiHint, 0, sizeof(struct addrinfo));

    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
#ifdef WIN32
#  ifdef USE_IPV6
    aiHint.ai_family = AF_UNSPEC;
#  else
    aiHint.ai_family = AF_INET;
#  endif
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
#  ifdef USE_IPV6
    aiHint.ai_family = AF_UNSPEC;
#  else
    aiHint.ai_family = AF_INET;
#  endif
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif
    struct addrinfo *aiRes = NULL;
    int nErr = getaddrinfo(pszName, NULL, &aiHint, &aiRes);
    if (nErr)
        return false;

    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != NULL && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            vIP.push_back(CNetAddr(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr));
        }

#ifdef USE_IPV6
        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            vIP.push_back(CNetAddr(((struct sockaddr_in6*)(aiTrav->ai_addr))->sin6_addr));
        }
#endif

        aiTrav = aiTrav->ai_next;
    }

    freeaddrinfo(aiRes);

    return (vIP.size() > 0);
}

bool LookupSubNet(const char* pszName, CSubNet& ret)
{
    std::string strSubnet(pszName);
    size_t slash = strSubnet.find_last_of('/');
    std::vector<CNetAddr> vIP;

    std::string strAddress = strSubnet.substr(0, slash);
    if (LookupHost(strAddress.c_str(), vIP, 1, false))
    {
        CNetAddr network = vIP[0];
        if (slash != strSubnet.npos)
        {
            std::string strNetmask = strSubnet.substr(slash + 1);
            int32_t n;
            // IPv4 addresses start at offset 12, and first 12 bytes must match, so just offset n
            if (ParseInt32(strNetmask, &n)) { // If valid number, assume /24 syntax
                ret = CSubNet(network, n);
                return ret.IsValid();
            }
            else // If not a valid number, try full netmask syntax
            {
                // Never allow lookup for netmask
                if (LookupHost(strNetmask.c_str(), vIP, 1, false)) {
                    ret = CSubNet(network, vIP[0]);
                    return ret.IsValid();
                }
            }
        }
        else
        {
            ret = CSubNet(network);
            return ret.IsValid();
        }
    }
    return false;
}

