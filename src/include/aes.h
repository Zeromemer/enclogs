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

int aes256_encrypt(unsigned char *input, int length, unsigned char *output, unsigned char *key, unsigned char *iv);

int aes256_decrypt(unsigned char *input, int length, unsigned char *output, unsigned char *key, unsigned char *iv);

#endif