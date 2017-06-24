#ifndef UTILEXCEPTIONS_H
#define UTILEXCEPTIONS_H

#include <exception>

void PrintException(std::exception* pex, const char* pszThread);
void PrintExceptionContinue(std::exception* pex, const char* pszThread);

#endif // UTILEXCEPTIONS_H
