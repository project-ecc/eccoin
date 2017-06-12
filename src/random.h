#ifndef RANDOM_H
#define RANDOM_H

#include "uint256.h"

#include <stdint.h>

/* Seed OpenSSL PRNG with additional entropy data */
void RandAddSeed();

/**
 * Functions to gather random data via the OpenSSL PRNG
 */
void GetRandBytes(unsigned char* buf, int num);
uint64_t GetRand(uint64_t nMax);
int GetRandInt(int nMax);
uint256 GetRandHash();
void RandAddSeedPerfmon();

static const ssize_t NUM_OS_RANDOM_BYTES = 32;


#endif // RANDOM_H
