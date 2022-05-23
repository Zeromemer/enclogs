#include <stdio.h>
#include <openssl/sha.h>
#include "include/aes.h"
#include "include/input.h"

void hex_print(unsigned char *in, size_t len) {
	for(int i = 0; i < len; i++) {
		if(i % 4 == 0)
			printf("\n");
		printf("%02X ", *(in + i));
	}
	printf("\n\n");
}

int main() {
	char *passwd = rl_getps("Enter password: ");

	aes_key_t *key_st = aes_key_init(passwd);

	// use aes256_encrypt to encrypt a message inputed by user
	char *input = rl_gets("Enter message: ");
	int input_length = strlen(input);
	printf("your message is: \"%s\"\n", input);
	unsigned char ciphertext[MAX_ENC_LENGTH(input_length)];
	int ciphertext_length = aes256_encrypt(key_st, input, input_length, ciphertext);
	if (ciphertext_length == -1) return 1;
	printf("ciphertext is: ");
	hex_print(ciphertext, ciphertext_length);

	// use aes256_decrypt to decrypt the message
	char decrypted[ciphertext_length + 1];
	int decrypted_length = aes256_decrypt(key_st, ciphertext, ciphertext_length, decrypted);
	if (decrypted_length == -1) return 1;
	decrypted[decrypted_length] = '\0';
	printf("decrypted message is: \"%s\"\n", decrypted);
	
	free(key_st);
	return 0;
}