#include "include/aes.h"
#include "include/xmalloc.h"

struct aes_key {
	unsigned char key[AES_BLOCK_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
};

aes_key_t aes_key_init(char *passwd) {
	aes_key_t key = xmalloc(sizeof(struct aes_key));
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, passwd, strlen(passwd));
	SHA256_Final(hash, &sha256);
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, hash, SHA256_DIGEST_LENGTH, 1, key->key, key->iv);
	return key;
}

void aes_key_free(aes_key_t key) {
	xfree(key);
}

// aes256_encrypt/decrypt have been sourced from https://github.com/DaniloVlad/OpenSSL-AES

ssize_t aes256_encrypt(aes_key_t key_st, void *input, int in_length, void *output) {
	EVP_CIPHER_CTX *ctx;
	int result_len;
	int len = MAX_ENC_LENGTH(in_length);

	//set up encryption context
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key_st->key, key_st->iv);
	//encrypt all the bytes up to but not including the last block
	if(!EVP_EncryptUpdate(ctx, output, &len, input, in_length)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//update length with the amount of bytes written
	result_len = len;
	//EncryptFinal will cipher the last block + Padding
	if(!EVP_EncryptFinal_ex(ctx, output + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//add padding to length
	result_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return result_len;
}

ssize_t aes256_decrypt(aes_key_t key_st, void *input, int in_length, void *output) {
	EVP_CIPHER_CTX *ctx;
	int result_len;
	int len = 0;
	//initialize return message and cipher context
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key_st->key, key_st->iv);
	//same as above
	if(!EVP_DecryptUpdate(ctx, output, &len, input, in_length)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}  
	result_len = len;
	if(!EVP_DecryptFinal_ex(ctx, output + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	//auto handle padding
	result_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return result_len;
}