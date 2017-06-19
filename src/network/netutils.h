#ifndef NETUTILS_H
#define NETUTILS_H

#include "service.h"
#include "subnet.h"

extern bool fNameLookup;

enum Network ParseNetwork(std::string net);

void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
bool Lookup(const char *pszName, CService& addr, int portDefault = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup);
bool LookupHostNumeric(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0);
bool LookupNumeric(const char *pszName, CService& addr, int portDefault = 0);
CService LookupNumeric(const char *pszName, int portDefault = 0);
bool LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup);
bool LookupSubNet(const char *pszName, CSubNet& subnet);

#endif // NETUTILS_H
