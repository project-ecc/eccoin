#ifndef CREQUESTTRACKER_H
#define CREQUESTTRACKER_H

#include "serialize.h"

class CRequestTracker
{
public:
    void (*fn)(void*, CDataStream&);
    void* param1;

    explicit CRequestTracker(void (*fnIn)(void*, CDataStream&)=NULL, void* param1In = NULL)
    {
        fn = fnIn;
        param1 = param1In;
    }
    bool IsNull();
};

#endif // CREQUESTTRACKER_H
