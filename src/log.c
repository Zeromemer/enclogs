#include "include/log.h"
#include "include/xmalloc.h"
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

log_t *log_init(char *message) {
    log_t *log = xmalloc(sizeof(log_t));
    log->message = strdup(message);
    clock_gettime(CLOCK_REALTIME, &log->time);
    return log;
}
void log_free(log_t *log) {
    xfree(log->message);
    xfree(log);
}

void serialize_log(log_t *src, char **dest, size_t *size) {
    size_t message_size = strlen(src->message);
    *size = sizeof(struct timespec) + message_size;
    *dest = xmalloc(*size);
    memcpy(*dest, &(src->time), sizeof(struct timespec));
    memcpy(*dest + sizeof(struct timespec), src->message, message_size);
}

void deserialize_log(void *src, size_t size, log_t **dest) {
    size_t message_size = size - sizeof(struct timespec);
    *dest = xmalloc(sizeof(log_t));
    memcpy(&((*dest)->time), src, sizeof(struct timespec));
    (*dest)->message = xmalloc(message_size) + 1;
    memcpy((*dest)->message, src + sizeof(struct timespec), message_size);
    (*dest)->message[message_size] = '\0';
}