#ifndef SOCKETUTILS_H
#define SOCKETUTILS_H

#include "service.h"
#include "compat.h"

bool Socks4(const CService &addrDest, SOCKET& hSocket);
bool Socks5(std::string strDest, int port, SOCKET& hSocket);
bool ConnectSocketDirectly(const CService &addrConnect, SOCKET& hSocketRet, int nTimeout);
bool ConnectSocket(const CService &addr, SOCKET& hSocketRet, int nTimeout = 5000);
bool ConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault = 0, int nTimeout = 5000);

#endif // SOCKETUTILS_H
