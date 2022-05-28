#include <stdio.h>
#include <openssl/err.h>
#include "include/aes.h"
#include "include/input.h"
#include "include/log.h"
#include "include/xmalloc.h"

#define ENCLOGS_PATH "./logs.bin"

unsigned char sign[] = { 0xf3, 0x3f, 0x65, 0x6e, 0x63, 0x6c, 0x6f, 0x67, 0x73, 0x0d, 0x0a, 0x00 };
#define SIGN_LENGTH sizeof(sign)


/* TODO: make the logs infinitly expandable by not saving them in memory!
   indexing them will stay the same, probably
 */


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

int timespec2str(char *buf, uint len, struct timespec *ts) {
	int ret;
	struct tm t;

	tzset();
	if (localtime_r(&(ts->tv_sec), &t) == NULL)
		return 1;

	ret = strftime(buf, len, "%F %T", &t);
	if (ret == 0)
		return 2;
	len -= ret - 1;

	ret = snprintf(&buf[strlen(buf)], len, ".%09ld", ts->tv_nsec);
	if (ret >= len)
		return 3;

	return 0;
}


int main() {
	char *input;
	char time_buf[sizeof("1970-01-01 00:00:00.000000000")];
	aes_key_t key_st;

	// create an empty enclogs file if it doesn't exist
	int enclogs_file_exists = access(ENCLOGS_PATH, F_OK) == 0;
	
	if (enclogs_file_exists) {
		input = rl_getps("Enter password: ");
		key_st = aes_key_init(input);
		xfree(input);
	} else {
		input = rl_getps("Enter password: ");
		char *confirm = rl_getps("Confirm password: ");
		if (strcmp(input, confirm) != 0) {
			fprintf(stderr, "Error: passwords don't match\n");
			return 1;
		}
		key_st = aes_key_init(input);
		xfree(input);
		xfree(confirm);
	}

	if (!enclogs_file_exists) {
		FILE *f = fopen(ENCLOGS_PATH, "w+");
		// write the sign
		fwrite(sign, SIGN_LENGTH, sizeof(unsigned char), f);
		// write the length (0)
		size_t size = 0;
		fwrite(&size, sizeof(size), 1, f);

		fclose(f);
	}

	FILE *f = fopen(ENCLOGS_PATH, "r+");
	unsigned char sign_buff[SIGN_LENGTH];
	size_t bytes_read = fread(sign_buff, 1, SIGN_LENGTH, f);
	if (bytes_read != SIGN_LENGTH) {
		fprintf(stderr, "Error: file is too short for an enclogs file (%zu)", bytes_read);
		return 1;
	}
	if (memcmp(sign, sign_buff, SIGN_LENGTH) != 0) {
		fprintf(stderr, "Error: file is not an enclogs file (invalid signature)");
		return 1;
	}

	size_t logs_amount;
	fread(&logs_amount, sizeof(logs_amount), 1, f);
	printf("logs_amount = %zu\n", logs_amount);

	log_t **logs = xcalloc(logs_amount + 1, sizeof(log_t *));


	for (int i = 0; i < logs_amount; i++) {
		// read encrypted log's length
		ssize_t enclog_len;
		fread(&enclog_len, sizeof(enclog_len), 1, f);

		// read the encrypted log
		unsigned char *enclog = xcalloc(enclog_len, 1);
		if (fread(enclog, enclog_len, 1, f) != 1) {
			fprintf(stderr, "Error: Invalid log\n");
			return 1;
		}

		// decrypt the log
		unsigned char *log_bin = xcalloc(enclog_len, 1);
		ssize_t log_bin_len = aes256_decrypt(key_st, enclog, enclog_len, log_bin);
		if (log_bin_len == -1) {
			ERR_print_errors_fp(stderr);
			return 1;
		}

		// deserialize the log
		log_t *log;
		deserialize_log(log_bin, &log);

		// put in logs
		logs[i] = log;
	}

	// CLI loop
	for (;;) {
		input = rl_gets("[enclogs]$ ");
		if (strcmp("exit", input) == 0) {
			printf("Exiting...\n");
			break;
		} else if (strcmp("list", input) == 0) {
			for (int i = 0; i < logs_amount; i++) {
				timespec2str(time_buf, sizeof(time_buf), &logs[i]->time);
				printf("[%s]: %s\n", time_buf, logs[i]->content);
			}
		} else if (strcmp("add", input) == 0) {
			input = rl_gets("Enter message: ");
			log_t *log = log_init(input);
			logs_amount++;

			// make space and add log to logs
			logs = xreallocarray(logs, logs_amount, sizeof(log_t *));
			logs[logs_amount - 1] = log;


			// save log file (will be optimized)
			fseek(f, 0, SEEK_SET);
			// write the sign
			fwrite(sign, SIGN_LENGTH, sizeof(unsigned char), f);
			// write the length
			fwrite(&logs_amount, sizeof(logs_amount), 1, f);

			for (int i = 0; i < logs_amount; i++) {
				// serialize log
				char *binlog;
				size_t binlog_len;
				serialize_log(logs[i], &binlog, &binlog_len);

				// encrypt log
				unsigned char *enclog = xcalloc(MAX_ENC_LENGTH(binlog_len), 1);
				ssize_t enclog_len = aes256_encrypt(key_st, binlog, binlog_len, enclog);

				// write log and length to logs file
				fwrite(&enclog_len, sizeof(enclog_len), 1, f);
				fwrite(enclog, 1, enclog_len, f);
			}
		} else {
			printf("Unknown command \"%s\".\n", input);
		}
	}
}