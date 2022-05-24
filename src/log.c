#include "include/log.h"
#include "include/xmalloc.h"
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

log_t *log_init(char *message) {
    log_t *log = xmalloc(sizeof(log_t));
    log->content_len = strlen(message);
    log->content = xmalloc(log->content_len + 1);
    memcpy(log->content, message, log->content_len);
    log->content[log->content_len] = '\0';
    clock_gettime(CLOCK_REALTIME, &log->time);
    return log;
}
void log_free(log_t *log) {
    xfree(log->content);
    xfree(log);
}

void serialize_log(log_t *src, char **dest, size_t *dest_len) {
    // dest should look like this:
    // [message_len][message][timespec]
    // message_len is a size_t
    // message is an array of chars (excluding the null terminator)
    // timespec is a struct timespec
    size_t content_len = strlen(src->content);
    size_t timespec_len = sizeof(src->time);
    size_t total_len = sizeof(content_len) + content_len + timespec_len;
    *dest = xmalloc(total_len);
    memcpy(*dest, &content_len, sizeof(size_t));
    memcpy(*dest + sizeof(size_t), src->content, content_len);
    memcpy(*dest + sizeof(size_t) + content_len, &src->time, timespec_len);
    *dest_len = total_len;
}

void deserialize_log(void *src, log_t **dest) {
    // the dest should look like a log_t
    size_t content_len = *(size_t *)src;
    char *content = xmalloc(content_len + 1);
    memcpy(content, src + sizeof(size_t), content_len);
    content[content_len] = '\0';
    struct timespec time;
    memcpy(&time, src + sizeof(size_t) + content_len, sizeof(struct timespec));
    *dest = xmalloc(sizeof(log_t));
    (*dest)->content_len = content_len;
    (*dest)->content = content;
    (*dest)->time = time;
}