#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

// aes_key_t is a structure that contains the key and iv
typedef struct aes_key *aes_key_t;

#define MAX_ENC_LENGTH(len) (len + (AES_BLOCK_SIZE - len % AES_BLOCK_SIZE))

aes_key_t aes_key_init(char *passwd);

ssize_t aes256_encrypt(aes_key_t key_st, void *input, int in_length, void *output);

ssize_t aes256_decrypt(aes_key_t key_st, void *input, int in_length, void *output);

#endif