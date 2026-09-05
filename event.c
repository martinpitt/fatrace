/**
 * fatrace - Trace system wide file access events.
 *
 * (C) 2026 Martin Pitt <martin@piware.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <string.h>

#include <sys/fanotify.h>

#include "event.h"

/**
 * mask2str:
 *
 * Convert a fanotify_event_metadata mask into a human readable string.
 *
 * Returns: decoded mask; only valid until the next call, do not free.
 */
const char*
mask2str (uint64_t mask)
{
    static char buffer[10];
    int offset = 0;

    if (mask & FAN_ACCESS)
        buffer[offset++] = 'R';
    if (mask & FAN_CLOSE_WRITE || mask & FAN_CLOSE_NOWRITE)
        buffer[offset++] = 'C';
    if (mask & FAN_MODIFY || mask & FAN_CLOSE_WRITE)
        buffer[offset++] = 'W';
    if (mask & FAN_OPEN)
        buffer[offset++] = 'O';
#ifdef FAN_REPORT_FID
    if (mask & FAN_CREATE)
        buffer[offset++] = '+';
    if (mask & FAN_DELETE)
        buffer[offset++] = 'D';
    if (mask & FAN_MOVED_FROM)
        buffer[offset++] = '<';
    if (mask & FAN_MOVED_TO)
        buffer[offset++] = '>';
#endif
    buffer[offset] = '\0';

    return buffer;
}

/* if str is a valid UTF-8 string without need of any JSON escaping, return the
   byte length, otherwise -1. */
static inline int
nonfunny_utf8_len (const char* str) {
    const unsigned char* s = (unsigned char*)str;
    int i = 0;
    while (str[i] != 0) {
        unsigned char c = s[i];
        // Unescaped ASCII
        if (0x20 <= c && c != '"' && c != '\\' && c <= 0x7e) {
            i++; continue;
        }
        // it's ok to read s[i+1] since we know s[i] != 0
        uint32_t mbc = c<<8 | s[i+1];
        if (// 2-char: 110xxxxx 10xxxxxx
            (mbc & 0xe0c0) == 0xc080 &&
            // but not 1100000x 10xxxxxx (overlong)
            (mbc & 0xfec0) != 0xc080) {
            i+=2; continue;
        }
        if (s[i+1] == 0)
            return -1;
        // it's ok to read s[i+2] since we know s[i+1] != 0
        mbc = mbc<<8 | s[i+2];
        if (// 3-char: 1110xxxx 10xxxxxx 10xxxxxx
            (mbc & 0xf0c0c0) == 0xe08080 &&
            // but not 11100000 100xxxxx 10xxxxxx (overlong)
            (mbc & 0xffe0c0) != 0xe08080 &&
            // neither 11101101 101xxxxx 10xxxxxx (reserved for surrogates)
            (mbc & 0xffe0c0) != 0xeda080) {
            i+=3; continue;
        }
        if (s[i+2] == 0)
            return -1;
        // it's ok to read s[i+3] since we know s[i+2] != 0
        mbc = mbc<<8 | s[i+3];
        if (// 4-char: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            (mbc & 0xf8c0c0c0) == 0xf0808080 &&
            // but not 11110000 1000xxxx 10xxxxxx 10xxxxxx (overlong)
            (mbc & 0xfff0c0c0) != 0xf0808080 &&
            // neither 11110PPP 10PPxxxx 10xxxxxx 10xxxxxx, PPPPP>0x10 (too big)
            (mbc & 0x07300000) <= 0x04000000) {
            i+=4; continue;
        }
        return -1;
    }
    return i;
}

/* print "key":"value" if value is clean UTF-8, otherwise "key_raw":[bytes...] */
void
print_json_str (FILE *out, const char* key, const char* value) {
    int value_len = nonfunny_utf8_len (value);
    int key_len = strlen(key);
    if (value_len >= 0) {
        putc('"', out);
        fwrite (key, 1, key_len, out);
        putc('"', out);
        putc(':', out);
        putc('"', out);
        fwrite (value, 1, value_len, out);
        putc ('"', out);
    } else {
        putc('"', out);
        fwrite (key, 1, key_len, out);
        fwrite ("_raw\":[", 1, 7, out);
        for (int i = 0; value[i] != 0; i++)
            fprintf (out, i ? ",%d" : "%d", (unsigned int)(unsigned char)(value[i]));
        putc (']', out);
    }
}
