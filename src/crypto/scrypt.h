#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdint.h>
#include <stdlib.h>

#include "net.h"
#include "primitives/block.h"

void *scrypt_buffer_alloc();
void scrypt_buffer_free(void *scratchpad);
uint256 scrypt_salted_multiround_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen, const unsigned int nRounds);
uint256 scrypt_salted_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen);
uint256 scrypt_hash(const void* input, size_t inputlen);
uint256 scrypt_blockhash(const void* input);
unsigned int scanhash_scrypt(CBlockHeader *pdata, void *scratchbuf, uint32_t max_nonce, uint32_t &hash_count, void *result, CBlockHeader *res_header);
void scrypt_hash_mine(const void* input, size_t inputlen, uint32_t *res, void *scratchpad);



#endif // SCRYPT_H
