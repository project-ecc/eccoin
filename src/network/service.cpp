#include "service.h"
#include "netutils.h"
#include "util/util.h"


void CService::Init()
{
    port = 0;
}

CService::CService()
{
    Init();
}

CService::CService(const CNetAddr& cip, unsigned short portIn) : CNetAddr(cip), port(portIn)
{
}

CService::CService(const struct in_addr& ipv4Addr, unsigned short portIn) : CNetAddr(ipv4Addr), port(portIn)
{
}

#ifdef USE_IPV6
CService::CService(const struct in6_addr& ipv6Addr, unsigned short portIn) : CNetAddr(ipv6Addr), port(portIn)
{
}
#endif

CService::CService(const struct sockaddr_in& addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

#ifdef USE_IPV6
CService::CService(const struct sockaddr_in6 &addr) : CNetAddr(addr.sin6_addr), port(ntohs(addr.sin6_port))
{
   assert(addr.sin6_family == AF_INET6);
}
#endif

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family) {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in*)paddr);
        return true;
#ifdef USE_IPV6
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6*)paddr);
        return true;
#endif
    default:
        return false;
    }
}

CService::CService(const char *pszIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(pszIpPort, ip, 0, fAllowLookup))
        *this = ip;
}

CService::CService(const char *pszIpPort, int portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(pszIpPort, ip, portDefault, fAllowLookup))
        *this = ip;
}

CService::CService(const std::string &strIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(strIpPort.c_str(), ip, 0, fAllowLookup))
        *this = ip;
}

CService::CService(const std::string &strIpPort, int portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(strIpPort.c_str(), ip, portDefault, fAllowLookup))
        *this = ip;
}

unsigned short CService::GetPort() const
{
    return port;
}

bool operator==(const CService& a, const CService& b)
{
    return (CNetAddr)a == (CNetAddr)b && a.port == b.port;
}

bool operator!=(const CService& a, const CService& b)
{
    return (CNetAddr)a != (CNetAddr)b || a.port != b.port;
}

bool operator<(const CService& a, const CService& b)
{
    return (CNetAddr)a < (CNetAddr)b || ((CNetAddr)a == (CNetAddr)b && a.port < b.port);
}

bool CService::GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const
{
    if (IsIPv4()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in*)paddr;
        memset(paddrin, 0, *addrlen);
        if (!GetInAddr(&paddrin->sin_addr))
            return false;
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
#ifdef USE_IPV6
    if (IsIPv6()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6*)paddr;
        memset(paddrin6, 0, *addrlen);
        if (!GetIn6Addr(&paddrin6->sin6_addr))
            return false;
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
#endif
    return false;
}

std::vector<unsigned char> CService::GetKey() const
{
     std::vector<unsigned char> vKey;
     vKey.resize(18);
     memcpy(&vKey[0], ip, 16);
     vKey[16] = port / 0x100;
     vKey[17] = port & 0x0FF;
     return vKey;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor() || IsI2P()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const
{
    return ToStringIPPort();
}

void CService::print() const
{
    LogPrintf("CService(%s)\n", ToString().c_str());
}

void CService::Set_Port(unsigned short portIn)
{
    port = portIn;
}
