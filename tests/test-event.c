/* Unit tests for event.c */

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/fanotify.h>
#include <sys/sysmacros.h>

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

#define ASSERT_JSON(key, value, expected) \
    ASSERT_STREQ (json_str (key, value), expected)

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

static void
test_print_json_str (void)
{
    ASSERT_JSON ("path", "/tmp/hello.txt", "\"path\":\"/tmp/hello.txt\"");
    ASSERT_JSON ("comm", "",               "\"comm\":\"\"");

    /* JSON metacharacters are not escaped but trigger the raw representation */
    ASSERT_JSON ("path", "a\"b", "\"path_raw\":[97,34,98]");
    ASSERT_JSON ("path", "a\\b", "\"path_raw\":[97,92,98]");
    ASSERT_JSON ("path", "\n",   "\"path_raw\":[10]");

    /* ASCII boundaries */
    ASSERT_JSON ("k", "\x05-", "\"k_raw\":[5,45]");
    ASSERT_JSON ("k", "\x1f-", "\"k_raw\":[31,45]");
    ASSERT_JSON ("k", "\x20-", "\"k\":\" -\"");
    ASSERT_JSON ("k", "\x21-", "\"k\":\"!-\"");
    ASSERT_JSON ("k", "\x22-", "\"k_raw\":[34,45]"); /* " */
    ASSERT_JSON ("k", "\x23-", "\"k\":\"#-\"");
    ASSERT_JSON ("k", "\x5b-", "\"k\":\"[-\"");
    ASSERT_JSON ("k", "\x5c-", "\"k_raw\":[92,45]"); /* \ */
    ASSERT_JSON ("k", "\x5d-", "\"k\":\"]-\"");
    ASSERT_JSON ("k", "\x7e-", "\"k\":\"~-\"");
    ASSERT_JSON ("k", "\x7f-", "\"k_raw\":[127,45]");

    /* 2-byte UTF-8 */
    ASSERT_JSON ("k", "\xc2\x80-", "\"k\":\"-\"");           /* U+0080 */
    ASSERT_JSON ("k", "\xc3\x85-", "\"k\":\"Å-\"");           /* U+00C5 */
    ASSERT_JSON ("k", "\xc3-",     "\"k_raw\":[195,45]");     /* incomplete */
    ASSERT_JSON ("k", "\xc3",      "\"k_raw\":[195]");        /* incomplete at end of string */
    ASSERT_JSON ("k", "\xc0\x80-", "\"k_raw\":[192,128,45]"); /* overlong */
    ASSERT_JSON ("k", "\xdf\xbf-", "\"k\":\"߿-\"");          /* U+07FF */

    /* 3-byte UTF-8 */
    ASSERT_JSON ("k", "\xe0\xa0\x80-", "\"k\":\"ࠀ-\"");               /* U+0800 */
    ASSERT_JSON ("k", "\xe0\xaf\xb5-", "\"k\":\"௵-\"");               /* U+0BF5 */
    ASSERT_JSON ("k", "\xe0\xaf-",     "\"k_raw\":[224,175,45]");     /* incomplete */
    ASSERT_JSON ("k", "\xe0\xaf",      "\"k_raw\":[224,175]");        /* incomplete at end of string */
    ASSERT_JSON ("k", "\xe0\x80\x80-", "\"k_raw\":[224,128,128,45]"); /* overlong */
    ASSERT_JSON ("k", "\xed\x9f\xbf-", "\"k\":\"퟿-\"");               /* U+D7FF */
    ASSERT_JSON ("k", "\xed\xa0\x80-", "\"k_raw\":[237,160,128,45]"); /* surrogate U+D800 */
    ASSERT_JSON ("k", "\xee\x80\x80-", "\"k\":\"-\"");               /* U+E000 */
    ASSERT_JSON ("k", "\xef\xbf\xbf-", "\"k\":\"￿-\"");               /* U+FFFF */

    /* 4-byte UTF-8 */
    ASSERT_JSON ("k", "\xf0\x90\x80\x80-", "\"k\":\"𐀀-\"");                   /* U+10000 */
    ASSERT_JSON ("k", "\xf0\x9f\x80\x85-", "\"k\":\"🀅-\"");                   /* U+1F005 */
    ASSERT_JSON ("k", "\xf0\x9f\x80-",     "\"k_raw\":[240,159,128,45]");     /* incomplete */
    ASSERT_JSON ("k", "\xf0\x9f\x80",      "\"k_raw\":[240,159,128]");        /* incomplete at end of string */
    ASSERT_JSON ("k", "\xf0\x80\x80\x80-", "\"k_raw\":[240,128,128,128,45]"); /* overlong */
    ASSERT_JSON ("k", "\xf4\x8f\xbf\xbf-", "\"k\":\"􏿿-\"");                   /* U+10FFFF */
    ASSERT_JSON ("k", "\xf4\x90\x80\x80-", "\"k_raw\":[244,144,128,128,45]"); /* > U+10FFFF */

    /* stray continuation bytes */
    ASSERT_JSON ("k", "\x80-", "\"k_raw\":[128,45]");
    ASSERT_JSON ("k", "\xbf-", "\"k_raw\":[191,45]");
}

/* the struct is large, so use a single static one and reset it for each test */
static struct fatrace_event ev;

static void
event_init (pid_t pid, const char *comm, uint64_t mask, const char *path)
{
    memset (&ev, 0, sizeof ev);
    ev.proc.pid = pid;
    strcpy (ev.proc.comm, comm);
    ev.mask = mask;
    if (path) {
        ev.fd_valid = true;
        strcpy (ev.path, path);
    }
}

static void
event_add_parent (pid_t pid, const char *comm, const char *exe)
{
    struct fatrace_event_proc *p = &ev.parents[ev.parents_len++];
    p->pid = pid;
    strcpy (p->comm, comm);
    strcpy (p->exe, exe);
}

static const char *
text (enum fatrace_timestamp timestamp_mode)
{
    mem_start ();
    format_fatrace_event_text (mem, &ev, timestamp_mode);
    return mem_end ();
}

static const char *
json (enum fatrace_timestamp timestamp_mode)
{
    mem_start ();
    format_fatrace_event_json (mem, &ev, timestamp_mode);
    return mem_end ();
}

static void
test_format_event (void)
{
    /* minimal */
    event_init (1234, "touch", FAN_OPEN | FAN_CLOSE_WRITE, "/tmp/x");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "touch(1234): CWO /tmp/x\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE), "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"CWO\",\"path\":\"/tmp/x\"}\n");

    /* types column is padded in text mode */
    event_init (5, "head", FAN_ACCESS, "/etc/passwd");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "head(5): R   /etc/passwd\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE), "{\"comm\":\"head\",\"pid\":5,\"types\":\"R\",\"path\":\"/etc/passwd\"}\n");

    /* unknown process name */
    event_init (1234, "", FAN_OPEN, "/tmp/x");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "unknown(1234): O   /tmp/x\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE), "{\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");

    /* file vanished before it could be looked at */
    event_init (1234, "rm", FAN_CLOSE_NOWRITE, NULL);
    ASSERT_STREQ (text (TIMESTAMP_NONE), "rm(1234): C   (deleted)\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE), "{\"comm\":\"rm\",\"pid\":1234,\"types\":\"C\"}\n");

    /* path unknown, but device/inode known */
    event_init (1234, "cat", FAN_ACCESS, "");
    ev.have_stat = true;
    ev.dev = makedev (8, 1);
    ev.ino = 42;
    ASSERT_STREQ (text (TIMESTAMP_NONE), "cat(1234): R   device 8:1 inode 42\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm\":\"cat\",\"pid\":1234,\"types\":\"R\",\"device\":{\"major\":8,\"minor\":1},\"inode\":42}\n");

    /* path and device/inode known: text mode only shows the path */
    strcpy (ev.path, "/tmp/x");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "cat(1234): R   /tmp/x\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm\":\"cat\",\"pid\":1234,\"types\":\"R\",\"device\":{\"major\":8,\"minor\":1},\"inode\":42,\"path\":\"/tmp/x\"}\n");

    /* neither path nor device/inode known */
    event_init (1234, "cat", FAN_ACCESS, "");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "cat(1234): R   \n");
    ASSERT_STREQ (json (TIMESTAMP_NONE), "{\"comm\":\"cat\",\"pid\":1234,\"types\":\"R\"}\n");

    /* no known event type */
    event_init (1234, "touch", 0, "/tmp/x");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "touch(1234):     /tmp/x\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE), "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"\",\"path\":\"/tmp/x\"}\n");

    /* --user */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    ev.have_ids = true;
    ev.uid = 1000;
    ev.gid = 100;
    ASSERT_STREQ (text (TIMESTAMP_NONE), "touch(1234) [1000:100]: O   /tmp/x\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm\":\"touch\",\"pid\":1234,\"uid\":1000,\"gid\":100,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");

    /* --exe */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    strcpy (ev.proc.exe, "/usr/bin/touch");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "touch(1234): O   /tmp/x exe=/usr/bin/touch\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\",\"exe\":\"/usr/bin/touch\"}\n");

    /* --parents; the middle one could not be read */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    event_add_parent (100, "bash", "/usr/bin/bash");
    event_add_parent (50, "", "");
    event_add_parent (1, "systemd", "/usr/lib/systemd/systemd");
    ASSERT_STREQ (text (TIMESTAMP_NONE),
                  "touch(1234): O   /tmp/x, parents=(pid=100 comm=bash exe=/usr/bin/bash),(pid=50),"
                  "(pid=1 comm=systemd exe=/usr/lib/systemd/systemd)\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\","
                  "\"parents\":[{\"pid\":100,\"comm\":\"bash\",\"exe\":\"/usr/bin/bash\"},{\"pid\":50},"
                  "{\"pid\":1,\"comm\":\"systemd\",\"exe\":\"/usr/lib/systemd/systemd\"}]}\n");

    /* --parents without --exe, and a parent with exe but without comm */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    event_add_parent (100, "bash", "");
    event_add_parent (50, "", "/usr/bin/foo");
    ASSERT_STREQ (text (TIMESTAMP_NONE),
                  "touch(1234): O   /tmp/x, parents=(pid=100 comm=bash),(pid=50 exe=/usr/bin/foo)\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\","
                  "\"parents\":[{\"pid\":100,\"comm\":\"bash\"},{\"pid\":50,\"exe\":\"/usr/bin/foo\"}]}\n");

    /* --timestamp; main() sets TZ=UTC */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    ev.time.tv_sec = 1728047655;
    ev.time.tv_usec = 1234;
    ASSERT_STREQ (text (TIMESTAMP_LOCAL), "13:14:15.001234 touch(1234): O   /tmp/x\n");
    ASSERT_STREQ (text (TIMESTAMP_EPOCH), "1728047655.001234 touch(1234): O   /tmp/x\n");
    /* TIMESTAMP_LOCAL follows the time zone; POSIX TZ string, so that this does not need tzdata */
    setenv ("TZ", "IST-5:30", 1);
    tzset ();
    ASSERT_STREQ (text (TIMESTAMP_LOCAL), "18:44:15.001234 touch(1234): O   /tmp/x\n");
    setenv ("TZ", "UTC", 1);
    tzset ();
    /* wall clock time is a JSON string, epoch time a number */
    ASSERT_STREQ (json (TIMESTAMP_LOCAL),
                  "{\"timestamp\":\"13:14:15.001234\",\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");
    ASSERT_STREQ (json (TIMESTAMP_EPOCH),
                  "{\"timestamp\":1728047655.001234,\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");

    /* strings which are not clean UTF-8: text mode prints them verbatim */
    event_init (1234, "t\xffuch", FAN_OPEN, "/tmp/a\"b");
    ASSERT_STREQ (text (TIMESTAMP_NONE), "t\xffuch(1234): O   /tmp/a\"b\n");
    ASSERT_STREQ (json (TIMESTAMP_NONE),
                  "{\"comm_raw\":[116,255,117,99,104],\"pid\":1234,\"types\":\"O\",\"path_raw\":[47,116,109,112,47,97,34,98]}\n");

    /* everything at once */
    event_init (1234, "touch", FAN_OPEN | FAN_CLOSE_WRITE, "/tmp/x");
    ev.time.tv_sec = 1728047655;
    ev.time.tv_usec = 1234;
    ev.have_ids = true;
    ev.uid = 1000;
    ev.gid = 100;
    ev.have_stat = true;
    ev.dev = makedev (8, 1);
    ev.ino = 42;
    strcpy (ev.proc.exe, "/usr/bin/touch");
    event_add_parent (100, "bash", "/usr/bin/bash");
    event_add_parent (1, "systemd", "/usr/lib/systemd/systemd");
    ASSERT_STREQ (text (TIMESTAMP_LOCAL),
                  "13:14:15.001234 touch(1234) [1000:100]: CWO /tmp/x exe=/usr/bin/touch, "
                  "parents=(pid=100 comm=bash exe=/usr/bin/bash),(pid=1 comm=systemd exe=/usr/lib/systemd/systemd)\n");
    ASSERT_STREQ (json (TIMESTAMP_EPOCH),
                  "{\"timestamp\":1728047655.001234,\"comm\":\"touch\",\"pid\":1234,\"uid\":1000,\"gid\":100,\"types\":\"CWO\","
                  "\"device\":{\"major\":8,\"minor\":1},\"inode\":42,\"path\":\"/tmp/x\",\"exe\":\"/usr/bin/touch\","
                  "\"parents\":[{\"pid\":100,\"comm\":\"bash\",\"exe\":\"/usr/bin/bash\"},"
                  "{\"pid\":1,\"comm\":\"systemd\",\"exe\":\"/usr/lib/systemd/systemd\"}]}\n");
}

int
main (void)
{
    /* deterministic TIMESTAMP_LOCAL output */
    setenv ("TZ", "UTC", 1);
    tzset ();

    test_mask2str ();
    test_print_json_str ();
    test_format_event ();

    if (failures) {
        fprintf (stderr, "%u of %u checks FAILED\n", failures, checks);
        return 1;
    }
    printf ("%u checks passed\n", checks);
    return 0;
}
