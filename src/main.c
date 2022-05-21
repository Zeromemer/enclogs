#include <stdio.h>
#include <openssl/sha.h>
#include "include/aes.h"

void hex_print(unsigned char *in, size_t len) {
	for(int i = 0; i < len; i++) {
		if(i % 4 == 0)
			printf("\n");
		printf("%02X ", *(in + i));
	}
	printf("\n\n");
}

int main() {
	const char *passwd = "password";

	// take password's SHA256 hash
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, passwd, strlen(passwd));
	SHA256_Final(hash, &sha256);

	// use hash to generate key and iv
	unsigned char key[AES_BLOCK_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, hash, SHA256_DIGEST_LENGTH, 1, key, iv);

	// use aes256_encrypt2 to encrypt a message inputed by user
	unsigned char input[1024];
	int input_length;
	printf("Enter message to encrypt: ");
	scanf("%s", input);
	printf("your message is: \"%s\"\n", input);
	input_length = strlen((char *)input);
	unsigned char ciphertext[MAX_ENC_LENGTH(input_length)];
	int ciphertext_length = aes256_encrypt(input, input_length, ciphertext, key, iv);
	printf("ciphertext is: ");
	hex_print(ciphertext, ciphertext_length);

	// use aes256_decrypt2 to decrypt the message
	unsigned char decrypted[ciphertext_length + 1];
	int decrypted_length = aes256_decrypt(ciphertext, ciphertext_length, decrypted, key, iv);
	decrypted[decrypted_length] = '\0';
	printf("decrypted message is: \"%s\"\n", decrypted);
	
	return 0;
}