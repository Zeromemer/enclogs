#ifndef LOG_H
#define LOG_H

#include <sys/time.h>
#include <unistd.h>

typedef struct log {
    struct timespec time;
    char *message;
} log_t;

log_t *log_init(char *message);
void log_free(log_t *log);

void serialize_log(log_t *src, char **dest, size_t *size);
void deserialize_log(void *src, size_t size, log_t **dest);

#endif // LOG_H