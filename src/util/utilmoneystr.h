#ifndef UTILMONEYSTR_H
#define UTILMONEYSTR_H

#include <stdint.h>
#include <string>

std::string FormatMoney(int64_t n, bool fPlus=false);
bool ParseMoney(const std::string& str, int64_t& nRet);
bool ParseMoney(const char* pszIn, int64_t& nRet);


#endif // UTILMONEYSTR_H
