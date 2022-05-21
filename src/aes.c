#include "include/aes.h"

// "inspired" by https://github.com/DaniloVlad/OpenSSL-AES

int aes256_encrypt(unsigned char *input, int length, unsigned char *output, unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX *ctx;
	int result_len;
	int len = length + (AES_BLOCK_SIZE - length % AES_BLOCK_SIZE);

	//set up encryption context
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	//encrypt all the bytes up to but not including the last block
	if(!EVP_EncryptUpdate(ctx, output, &len, input, length)) {
		EVP_CIPHER_CTX_cleanup(ctx);
		printf("EVP Error: couldn't update encryption with plain text!\n");
		return 1;
	}
	//update length with the amount of bytes written
	result_len = len;
	//EncryptFinal will cipher the last block + Padding
	if(!EVP_EncryptFinal_ex(ctx, len + output, &len)) {
		EVP_CIPHER_CTX_cleanup(ctx);
		printf("EVP Error: couldn't finalize encryption!\n");
		return 1;
	}
	//add padding to length
	result_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return result_len;
}

int aes256_decrypt(unsigned char *input, int length, unsigned char *output, unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX *ctx;
	int result_len;
	int len = 0;
	//initialize return message and cipher context
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	//same as above
	if(!EVP_DecryptUpdate(ctx, output, &len, input, length)) {
		EVP_CIPHER_CTX_cleanup(ctx);
		printf("EVP Error: couldn't update decrypt with text!\n");
		return 1;
	}  
	result_len = len;
	if(!EVP_DecryptFinal_ex(ctx, len + output, &len)) {
		EVP_CIPHER_CTX_cleanup(ctx);
		printf("EVP Error: couldn't finalize decryption!\n");
		return 1;
	}
	//auto handle padding
	result_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return result_len;
}