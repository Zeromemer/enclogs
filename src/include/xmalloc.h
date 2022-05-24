#ifndef ENCLOGS_XMALLOC_H
#define ENCLOGS_XMALLOC_H

#include <stdlib.h>

void *xmalloc_internal(size_t size, const char *file, int line);
void *xcalloc_internal(size_t nmemb, size_t size, const char *file, int line);
void *xrealloc_internal(void *ptr, size_t size, const char *file, int line);
void *xreallocarray_internal(void *ptr, size_t nmemb, size_t size, const char *file, int line);
void xfree_internal(void *ptr, const char *file, int line);

#define xmalloc(size) xmalloc_internal(size, __FILE__, __LINE__)
#define xcalloc(nmemb, size) xcalloc_internal(nmemb, size, __FILE__, __LINE__)
#define xrealloc(ptr, size) xrealloc_internal(ptr, size, __FILE__, __LINE__)
#define xreallocarray(ptr, nmemb, size) xreallocarray_internal(ptr, nmemb, size, __FILE__, __LINE__)
#define xfree(ptr) xfree_internal(ptr, __FILE__, __LINE__)

#endif // ENCLOGS_XMALLOC_H