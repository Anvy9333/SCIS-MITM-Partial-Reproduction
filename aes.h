/* aes.h - AES-128 primitives for SCIS MITM reproduction */
#ifndef AES_H
#define AES_H

#include <stdint.h>

typedef uint8_t aes_block_t[16];

void aes128_encrypt(const uint8_t key[16], const uint8_t pt[16], uint8_t ct[16]);
void aes_mmo(const uint8_t msg[16], const uint8_t cv[16], uint8_t out[16]);

#endif