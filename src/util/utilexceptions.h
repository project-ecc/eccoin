#ifndef UTILEXCEPTIONS_H
#define UTILEXCEPTIONS_H

#include <exception>

void PrintException(const std::exception *pex, const char* pszThread);
void PrintExceptionContinue(const std::exception *pex, const char* pszThread);

#endif // UTILEXCEPTIONS_H
