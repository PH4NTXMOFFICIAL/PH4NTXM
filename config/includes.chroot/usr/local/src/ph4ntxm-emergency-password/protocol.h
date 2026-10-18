/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#ifndef PH4_EMERGENCY_PROTOCOL_H
#define PH4_EMERGENCY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PH4_MAX_TOKEN 511
#define PH4_NONMATCH 1
#define PH4_DISABLED 2
#define PH4_MATCH 3
#define PH4_ERROR 4

static inline int ph4_token_valid(const unsigned char *s, size_t n)
{
    size_t i = 0, count = 0;
    if (n == 0 || n > PH4_MAX_TOKEN)
        return 0;
    while (i < n) {
        uint32_t cp;
        size_t k;
        unsigned char c = s[i++];
        if (c < 0x80) {
            cp = c;
            k = 0;
        } else if (c >= 0xc2 && c <= 0xdf) {
            cp = c & 0x1f;
            k = 1;
        } else if (c >= 0xe0 && c <= 0xef) {
            cp = c & 0x0f;
            k = 2;
        } else if (c >= 0xf0 && c <= 0xf4) {
            cp = c & 0x07;
            k = 3;
        } else {
            return 0;
        }
        if (n - i < k)
            return 0;
        for (size_t j = 0; j < k; j++) {
            unsigned char next = s[i++];
            if ((next & 0xc0) != 0x80)
                return 0;
            cp = (cp << 6) | (next & 0x3f);
        }
        if ((k == 1 && cp < 0x80) || (k == 2 && cp < 0x800) ||
            (k == 3 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff) || cp < 32 || cp == 127)
            return 0;
        count++;
        if (count > 256)
            return 0;
    }
    return count >= 6;
}

#endif
