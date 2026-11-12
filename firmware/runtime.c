#include <stddef.h>

void *memset(void *destination, int value, size_t count)
{
    unsigned char *bytes = destination;
    while (count != 0u) {
        *bytes++ = (unsigned char)value;
        --count;
    }
    return destination;
}
