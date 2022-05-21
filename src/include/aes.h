#ifndef AES_H
#define AES_H

#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32

#define MAX_ENC_LENGTH(len) (len + (AES_BLOCK_SIZE - len % AES_BLOCK_SIZE))

ssize_t aes256_encrypt(void *input, int length, void *output, unsigned char *key, unsigned char *iv);

ssize_t aes256_decrypt(void *input, int length, void *output, unsigned char *key, unsigned char *iv);

#endif