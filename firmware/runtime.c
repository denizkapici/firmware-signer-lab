#include <stddef.h>

/* The firmware links with -nostdlib, but GCC may still emit calls to
 * memset and memcpy (zero-initialised arrays, struct assignment). */
void *memset(void *destination, int value, size_t count);
void *memcpy(void *destination, const void *source, size_t count);

void *memcpy(void *destination, const void *source, size_t count)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    while (count != 0u) {
        *out++ = *in++;
        --count;
    }
    return destination;
}

void *memset(void *destination, int value, size_t count)
{
    unsigned char *bytes = destination;
    while (count != 0u) {
        *bytes++ = (unsigned char)value;
        --count;
    }
    return destination;
}
