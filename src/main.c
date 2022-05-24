#include <stdio.h>
#include "include/aes.h"
#include "include/input.h"
#include "include/log.h"

void hex_print(unsigned char *in, size_t len) {
	for(int i = 0; i < len; i++) {
		if(i % 4 == 0)
			printf("\n");
		printf("%02X ", *(in + i));
	}
	printf("\n\n");
}

int main() {
	char *input;

	input = rl_getps("Enter password: ");
	aes_key_t key_st = aes_key_init(input);

	input = rl_gets("Enter message: ");
	printf("your message is: \"%s\"\n", input);

	// create a log from the input, and serialize it
	log_t *log = log_init(input);
	char *serialized_log;
	size_t serialized_log_size;
	serialize_log(log, &serialized_log, &serialized_log_size);

	// encrypt the serialized log
	unsigned char encrypted_log[MAX_ENC_LENGTH(serialized_log_size)];
	ssize_t encrypted_log_length = aes256_encrypt(key_st, serialized_log, serialized_log_size, encrypted_log);
	printf("encrypted log: ");
	hex_print(encrypted_log, encrypted_log_length);

	// decrypt the encrypted log
	unsigned char decrypted_log[encrypted_log_length];
	ssize_t decrypted_log_length = aes256_decrypt(key_st, encrypted_log, encrypted_log_length, decrypted_log);
	printf("decrypted log: ");
	hex_print(decrypted_log, decrypted_log_length);

	// deserialize the decrypted log
	log_t *deserialized_log;
	deserialize_log(decrypted_log, decrypted_log_length, &deserialized_log);
	printf("deserialized log's message: \"%s\"\n", deserialized_log->message);
}