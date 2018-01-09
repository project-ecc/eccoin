#ifndef SIGNALS_H
#define SIGNALS_H

#include "net.h"

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);


#endif // SIGNALS_H
