#ifndef PROXYUTILS_H
#define PROXYUTILS_H

#include "service.h"
#include "sync.h"

typedef std::pair<CService, int> proxyType;

// Settings
static proxyType proxyInfo[NET_MAX];
static proxyType nameproxyInfo;
static CCriticalSection cs_proxyInfos;


bool SetProxy(enum Network net, CService addrProxy, int nSocksVersion = 5);
bool GetProxy(enum Network net, proxyType &proxyInfoOut);
bool IsProxy(const CNetAddr &addr);
bool SetNameProxy(CService addrProxy, int nSocksVersion = 5);
bool GetNameProxy(proxyType &nameproxyInfoOut);
bool HaveNameProxy();

#endif // PROXYUTILS_H
