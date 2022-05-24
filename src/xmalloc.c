#include "include/xmalloc.h"
#include <stdio.h>

// #define ENCLOGS_XMALLOC_DEBUG

void *xmalloc_internal(size_t size, const char *file, int line) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "xmalloc: Out of memory at %s:%d\n", file, line);
        exit(1);
    }
    #ifdef ENCLOGS_XMALLOC_DEBUG
    printf("%s:%d: xmalloc(%zu) = %p\n", file, line, size, ptr);
    #endif
    return ptr;
}

void *xcalloc_internal(size_t nmemb, size_t size, const char *file, int line) {
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL) {
        fprintf(stderr, "xmalloc: Out of memory at %s:%d\n", file, line);
        exit(1);
    }
    #ifdef ENCLOGS_XMALLOC_DEBUG
    printf("%s:%d: xcalloc(%zu, %zu) = %p\n", file, line, nmemb, size, ptr);
    #endif
    return ptr;
}

void *xrealloc_internal(void *ptr, size_t size, const char *file, int line) {
    void *new_ptr = realloc(ptr, size);
    if (new_ptr == NULL && size != 0) {
        fprintf(stderr, "xmalloc: Out of memory at %s:%d\n", file, line);
        exit(1);
    }
    #ifdef ENCLOGS_XMALLOC_DEBUG
    printf("%s:%d: xrealloc(%p, %zu) = %p\n", file, line, ptr, size, new_ptr);
    #endif
    return new_ptr;
}

void *xreallocarray_internal(void *ptr, size_t nmemb, size_t size, const char *file, int line) {
    void *new_ptr = reallocarray(ptr, nmemb, size);
    if (new_ptr == NULL && nmemb != 0 && size != 0) {
        fprintf(stderr, "xmalloc: Out of memory at %s:%d\n", file, line);
        exit(1);
    }
    #ifdef ENCLOGS_XMALLOC_DEBUG
    printf("%s:%d: xreallocarray(%p, %zu, %zu) = %p\n", file, line, ptr, nmemb, size, new_ptr);
    #endif
    return new_ptr;
}

void xfree_internal(void *ptr, const char *file, int line) {
    #ifdef ENCLOGS_XMALLOC_DEBUG
    printf("%s:%d: xfree(%p)\n", file, line, ptr);
    #endif
    free(ptr);
}