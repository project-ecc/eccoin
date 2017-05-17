#include "proxyutils.h"

bool SetProxy(enum Network net, CService addrProxy, int nSocksVersion) {
    assert(net >= 0 && net < NET_MAX);
    if (nSocksVersion != 0 && nSocksVersion != 4 && nSocksVersion != 5)
        return false;
    if (nSocksVersion != 0 && !addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    proxyInfo[net] = std::make_pair(addrProxy, nSocksVersion);
    return true;
}

bool GetProxy(enum Network net, proxyType &proxyInfoOut) {
    assert(net >= 0 && net < NET_MAX);
    LOCK(cs_proxyInfos);
    if (!proxyInfo[net].second)
        return false;
    proxyInfoOut = proxyInfo[net];
    return true;
}

bool SetNameProxy(CService addrProxy, int nSocksVersion) {
    if (nSocksVersion != 0 && nSocksVersion != 5)
        return false;
    if (nSocksVersion != 0 && !addrProxy.IsValid())
        return false;
    LOCK(cs_proxyInfos);
    nameproxyInfo = std::make_pair(addrProxy, nSocksVersion);
    return true;
}

bool GetNameProxy(proxyType &nameproxyInfoOut)
{
    LOCK(cs_proxyInfos);
    if (!nameproxyInfo.second)
        return false;
    nameproxyInfoOut = nameproxyInfo;
    return true;
}

bool HaveNameProxy() {
    LOCK(cs_proxyInfos);
    return nameproxyInfo.second != 0;
}

bool IsProxy(const CNetAddr &addr) {
    LOCK(cs_proxyInfos);
    for (int i = 0; i < NET_MAX; i++) {
        if (proxyInfo[i].second && (addr == (CNetAddr)proxyInfo[i].first))
            return true;
    }
    return false;
}
