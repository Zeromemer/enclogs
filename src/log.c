#include "include/log.h"
#include "include/xmalloc.h"
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

log_t *log_init(char *message) {
    log_t *log = xmalloc(sizeof(log_t));
    log->message_len = strlen(message);
    log->message = xmalloc(log->message_len + 1);
    memcpy(log->message, message, log->message_len);
    log->message[log->message_len] = '\0';
    clock_gettime(CLOCK_REALTIME, &log->time);
    return log;
}
void log_free(log_t *log) {
    xfree(log->message);
    xfree(log);
}

void serialize_log(log_t *src, char **dest, size_t *dest_len) {
    // dest should look like this:
    // [message_len][message][timespec]
    // message_len is a size_t
    // message is an array of chars (excluding the null terminator)
    // timespec is a struct timespec
    size_t message_len = strlen(src->message);
    size_t timespec_len = sizeof(src->time);
    size_t total_len = sizeof(message_len) + message_len + timespec_len;
    *dest = xmalloc(total_len);
    memcpy(*dest, &message_len, sizeof(size_t));
    memcpy(*dest + sizeof(size_t), src->message, message_len);
    memcpy(*dest + sizeof(size_t) + message_len, &src->time, timespec_len);
    *dest_len = total_len;
}

void deserialize_log(void *src, log_t **dest) {
    // the dest should look like a log_t
    size_t message_len = *(size_t *)src;
    char *message = xmalloc(message_len + 1);
    memcpy(message, src + sizeof(size_t), message_len);
    message[message_len] = '\0';
    struct timespec time;
    memcpy(&time, src + sizeof(size_t) + message_len, sizeof(struct timespec));
    *dest = xmalloc(sizeof(log_t));
    (*dest)->message_len = message_len;
    (*dest)->message = message;
    (*dest)->time = time;
}