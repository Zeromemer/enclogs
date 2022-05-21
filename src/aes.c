#include "include/aes.h"

// Sourced from https://github.com/DaniloVlad/OpenSSL-AES

ssize_t aes256_encrypt(void *input, int in_length, void *output, unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX *ctx;
	int result_len;
	int len = MAX_ENC_LENGTH(in_length);

	//set up encryption context
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	//encrypt all the bytes up to but not including the last block
	if(!EVP_EncryptUpdate(ctx, output, &len, input, in_length)) {
		EVP_CIPHER_CTX_free(ctx);
		printf("EVP Error: couldn't update encryption with plain text!\n");
		return -1;
	}
	//update length with the amount of bytes written
	result_len = len;
	//EncryptFinal will cipher the last block + Padding
	if(!EVP_EncryptFinal_ex(ctx, output + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		printf("EVP Error: couldn't finalize encryption!\n");
		return -1;
	}
	//add padding to length
	result_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return result_len;
}

ssize_t aes256_decrypt(void *input, int in_length, void *output, unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX *ctx;
	int result_len;
	int len = 0;
	//initialize return message and cipher context
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	//same as above
	if(!EVP_DecryptUpdate(ctx, output, &len, input, in_length)) {
		EVP_CIPHER_CTX_free(ctx);
		printf("EVP Error: couldn't update decrypt with text!\n");
		return -1;
	}  
	result_len = len;
	if(!EVP_DecryptFinal_ex(ctx, output + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		printf("EVP Error: couldn't finalize decryption!\n");
		return -1;
	}
	//auto handle padding
	result_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return result_len;
}