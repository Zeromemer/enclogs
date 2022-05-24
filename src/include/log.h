#ifndef LOG_H
#define LOG_H

#include <sys/time.h>
#include <unistd.h>

typedef struct log {
    size_t message_len;
    char *message;
    struct timespec time;
} log_t;

log_t *log_init(char *message);
void log_free(log_t *log);

void serialize_log(log_t *src, char **dest, size_t *dest_len);
void deserialize_log(void *src, log_t **dest);

#endif // LOG_H