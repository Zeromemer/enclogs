#include <stdio.h>
#include "include/aes.h"
#include "include/input.h"
#include "include/log.h"
#include "include/xmalloc.h"

void hex_print(void *in, size_t len) {
	unsigned char *data = in;
	for (size_t i = 0; i < len; i++) {
		if (i % 16 == 0) {
			printf("\n");
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
}

int main() {
	char *input;

	input = rl_getps("Enter password: ");
	aes_key_t key_st = aes_key_init(input);

	input = rl_gets("Enter message: ");
	printf("your message is: \"%s\"\n", input);

	// create a log from the input
	log_t *log = log_init(input);

	// print the log
	printf("log: message_len: %zu, message: \"%s\", time: %ld.%ld\n", log->message_len, log->message, log->time.tv_sec, log->time.tv_nsec);

	// serialize the log
	char *serialized_log;
	size_t serialized_log_len;
	serialize_log(log, &serialized_log, &serialized_log_len);

	// encrypt the serialized log
	char encrypted_log[MAX_ENC_LENGTH(serialized_log_len)];
	ssize_t encrypted_log_len = aes256_encrypt(key_st, serialized_log, serialized_log_len, encrypted_log);
	if (encrypted_log_len < 0) {
		printf("Error encrypting log\n");
		return 1;
	}

	// print the encrypted log
	printf("encrypted log:");
	hex_print(encrypted_log, encrypted_log_len);

	// decrypt the encrypted log
	char decrypted_log[encrypted_log_len];
	ssize_t decrypted_log_len = aes256_decrypt(key_st, encrypted_log, encrypted_log_len, decrypted_log);
	if (decrypted_log_len < 0) {
		printf("Error decrypting log\n");
		return 1;
	}

	// print the decrypted log
	printf("decrypted log:");
	hex_print(decrypted_log, decrypted_log_len);

	// deserialize the decrypted log
	log_t *deserialized_log;
	deserialize_log(decrypted_log, &deserialized_log);

	// print the deserialized log
	printf("deserialized log: \"%s\"\n", deserialized_log->message);

	// free all the memory (uneccessary, but will be useful when this becomes an actual CLI)
	log_free(log);
	aes_key_free(key_st);
	free(serialized_log);
	log_free(deserialized_log);
}