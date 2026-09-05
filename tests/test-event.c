/* Unit tests for event.c */

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/fanotify.h>

#include "../event.h"

static unsigned checks;
static unsigned failures;

#define ASSERT_STREQ(actual, expected) do { \
    const char *actual_ = (actual); \
    const char *expected_ = (expected); \
    checks++; \
    if (strcmp (actual_, expected_) != 0) { \
        failures++; \
        fprintf (stderr, "%s:%d: FAIL\n  expected: %s\n  actual:   %s\n", \
                 __FILE__, __LINE__, expected_, actual_); \
    } \
} while (0)

/* capture formatter output: write to `mem` between mem_start() and mem_end(); the result is
 * valid until the next mem_start() */
static FILE *mem;
static char *mem_buf;
static size_t mem_len;

static void
mem_start (void)
{
    free (mem_buf);
    mem_buf = NULL;
    mem = open_memstream (&mem_buf, &mem_len);
    if (!mem) {
        perror ("open_memstream");
        exit (1);
    }
}

static const char *
mem_end (void)
{
    fclose (mem);
    mem = NULL;
    return mem_buf;
}

static void
test_mask2str (void)
{
    ASSERT_STREQ (mask2str (0), "");
    ASSERT_STREQ (mask2str (FAN_ACCESS), "R");
    ASSERT_STREQ (mask2str (FAN_MODIFY), "W");
    ASSERT_STREQ (mask2str (FAN_OPEN), "O");
    ASSERT_STREQ (mask2str (FAN_CLOSE_NOWRITE), "C");
    /* closing a written file implies a write */
    ASSERT_STREQ (mask2str (FAN_CLOSE_WRITE), "CW");
    ASSERT_STREQ (mask2str (FAN_MODIFY | FAN_CLOSE_WRITE), "CW");
    /* fixed output order regardless of bit order */
    ASSERT_STREQ (mask2str (FAN_OPEN | FAN_CLOSE_NOWRITE | FAN_ACCESS), "RCO");
    ASSERT_STREQ (mask2str (FAN_OPEN | FAN_CLOSE_WRITE), "CWO");
#ifdef FAN_REPORT_FID
    ASSERT_STREQ (mask2str (FAN_CREATE), "+");
    ASSERT_STREQ (mask2str (FAN_DELETE), "D");
    ASSERT_STREQ (mask2str (FAN_MOVED_FROM), "<");
    ASSERT_STREQ (mask2str (FAN_MOVED_TO), ">");
    ASSERT_STREQ (mask2str (FAN_MOVE), "<>");
    ASSERT_STREQ (mask2str (FAN_ACCESS | FAN_CLOSE | FAN_MODIFY | FAN_OPEN |
                            FAN_CREATE | FAN_DELETE | FAN_MOVE), "RCWO+D<>");
#endif
    /* unrelated bits are ignored */
    ASSERT_STREQ (mask2str (FAN_ONDIR | FAN_EVENT_ON_CHILD), "");
}

static const char *
json_str (const char *key, const char *value)
{
    mem_start ();
    print_json_str (mem, key, value);
    return mem_end ();
}

/* check that value gets printed verbatim (good) or as a "_raw" byte array (bad) */
static void
check_json_str_utf8 (const char *value, bool good)
{
    char expected[256];
    size_t len = 0;

    if (good) {
        snprintf (expected, sizeof expected, "\"k\":\"%s\"", value);
    } else {
        len = snprintf (expected, sizeof expected, "\"k_raw\":[");
        for (const unsigned char *c = (const unsigned char *) value; *c; ++c)
            len += snprintf (expected + len, sizeof expected - len, "%s%u",
                             c == (const unsigned char *) value ? "" : ",", *c);
        snprintf (expected + len, sizeof expected - len, "]");
    }
    ASSERT_STREQ (json_str ("k", value), expected);
}

static void
test_print_json_str (void)
{
    ASSERT_STREQ (json_str ("path", "/tmp/hello.txt"), "\"path\":\"/tmp/hello.txt\"");
    ASSERT_STREQ (json_str ("comm", ""), "\"comm\":\"\"");
    /* JSON metacharacters are not escaped but trigger the raw representation */
    ASSERT_STREQ (json_str ("path", "a\"b"), "\"path_raw\":[97,34,98]");
    ASSERT_STREQ (json_str ("path", "a\\b"), "\"path_raw\":[97,92,98]");
    ASSERT_STREQ (json_str ("path", "\n"), "\"path_raw\":[10]");

    /* ASCII boundaries */
    check_json_str_utf8 ("\x05-tmp", false);
    check_json_str_utf8 ("\x1f-tmp", false);
    check_json_str_utf8 ("\x20-tmp", true);
    check_json_str_utf8 ("\x21-tmp", true);
    check_json_str_utf8 ("\x22-tmp", false); /* " */
    check_json_str_utf8 ("\x23-tmp", true);
    check_json_str_utf8 ("\x5b-tmp", true);
    check_json_str_utf8 ("\x5c-tmp", false); /* \ */
    check_json_str_utf8 ("\x5d-tmp", true);
    check_json_str_utf8 ("\x7e-tmp", true);
    check_json_str_utf8 ("\x7f-tmp", false);

    /* 2-byte UTF-8 */
    check_json_str_utf8 ("\xc2\x80-tmp", true);     /* U+0080 */
    check_json_str_utf8 ("\xc3\x85-tmp", true);     /* U+00C5 Å */
    check_json_str_utf8 ("\xc3-tmp", false);        /* incomplete */
    check_json_str_utf8 ("\xc3", false);            /* incomplete at end of string */
    check_json_str_utf8 ("\xc0\x80-tmp", false);    /* overlong */
    check_json_str_utf8 ("\xdf\xbf-tmp", true);     /* U+07FF */

    /* 3-byte UTF-8 */
    check_json_str_utf8 ("\xe0\xa0\x80-tmp", true); /* U+0800 */
    check_json_str_utf8 ("\xe0\xaf\xb5-tmp", true); /* U+0BF5 ௵ */
    check_json_str_utf8 ("\xe0\xaf-tmp", false);    /* incomplete */
    check_json_str_utf8 ("\xe0\xaf", false);        /* incomplete at end of string */
    check_json_str_utf8 ("\xe0\x80\x80-tmp", false); /* overlong */
    check_json_str_utf8 ("\xed\x9f\xbf-tmp", true); /* U+D7FF */
    check_json_str_utf8 ("\xed\xa0\x80-tmp", false); /* surrogate U+D800 */
    check_json_str_utf8 ("\xee\x80\x80-tmp", true); /* U+E000 */
    check_json_str_utf8 ("\xef\xbf\xbf-tmp", true); /* U+FFFF */

    /* 4-byte UTF-8 */
    check_json_str_utf8 ("\xf0\x90\x80\x80-tmp", true);  /* U+10000 */
    check_json_str_utf8 ("\xf0\x9f\x80\x85-tmp", true);  /* U+1F005 🀅 */
    check_json_str_utf8 ("\xf0\x9f\x80-tmp", false);     /* incomplete */
    check_json_str_utf8 ("\xf0\x9f\x80", false);         /* incomplete at end of string */
    check_json_str_utf8 ("\xf0\x80\x80\x80-tmp", false); /* overlong */
    check_json_str_utf8 ("\xf4\x8f\xbf\xbf-tmp", true);  /* U+10FFFF */
    check_json_str_utf8 ("\xf4\x90\x80\x80-tmp", false); /* > U+10FFFF */

    /* stray continuation bytes */
    check_json_str_utf8 ("\x80-tmp", false);
    check_json_str_utf8 ("\xbf-tmp", false);
}

int
main (void)
{
    test_mask2str ();
    test_print_json_str ();

    if (failures) {
        fprintf (stderr, "%u of %u checks FAILED\n", failures, checks);
        return 1;
    }
    printf ("%u checks passed\n", checks);
    return 0;
}
