/* Unit tests for functions in fatrace.c */

#define FATRACE_UNIT_TEST
#include "../fatrace.c"
#undef FATRACE_UNIT_TEST

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/fanotify.h>
#include <sys/prctl.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

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
    ASSERT_JSON ("k", "\xc2\x80-", "\"k_raw\":[194,128,45]"); /* U+0080 */
    ASSERT_JSON ("k", "\xc2\x9f-", "\"k_raw\":[194,159,45]"); /* U+009f */
    ASSERT_JSON ("k", "\xc2\xa0-", "\"k\":\" -\"");           /* U+00a0 */
    ASSERT_JSON ("k", "\xc2\xa1-", "\"k\":\"¡-\"");           /* U+00A1 */
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
    /* Sometimes write garbage to the whole structure before resetting */
    static int alternate_garbage = 0;
    if (alternate_garbage++ & 1)
        memset (&ev, 0xa5, sizeof ev);
    /* Reset the same way as in ../fatrace.c */
    event_reset (&ev);
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
text_with_timestamp_mode (enum fatrace_timestamp timestamp_mode)
{
    mem_start ();
    format_fatrace_event_text (mem, &ev, timestamp_mode);
    return mem_end ();
}
static const char *
text (void)
{
    return text_with_timestamp_mode (TIMESTAMP_NONE);
}

static const char *
json_with_timestamp_mode (enum fatrace_timestamp timestamp_mode)
{
    mem_start ();
    format_fatrace_event_json (mem, &ev, timestamp_mode);
    return mem_end ();
}
static const char *
json (void)
{
    return json_with_timestamp_mode (TIMESTAMP_NONE);
}

static void
test_format_event (void)
{
    /* minimal */
    event_init (1234, "touch", FAN_OPEN | FAN_CLOSE_WRITE, "/tmp/x");
    ASSERT_STREQ (text (), "touch(1234): CWO /tmp/x\n");
    ASSERT_STREQ (json (), "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"CWO\",\"path\":\"/tmp/x\"}\n");

    /* types column is padded in text mode */
    event_init (5, "head", FAN_ACCESS, "/etc/passwd");
    ASSERT_STREQ (text (), "head(5): R   /etc/passwd\n");
    ASSERT_STREQ (json (), "{\"comm\":\"head\",\"pid\":5,\"types\":\"R\",\"path\":\"/etc/passwd\"}\n");

    /* unknown process name */
    event_init (1234, "", FAN_OPEN, "/tmp/x");
    ASSERT_STREQ (text (), "unknown(1234): O   /tmp/x\n");
    ASSERT_STREQ (json (), "{\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");

    /* file vanished before it could be looked at */
    event_init (1234, "rm", FAN_CLOSE_NOWRITE, NULL);
    ASSERT_STREQ (text (), "rm(1234): C   (deleted)\n");
    ASSERT_STREQ (json (), "{\"comm\":\"rm\",\"pid\":1234,\"types\":\"C\"}\n");

    /* path unknown, but device/inode known */
    event_init (1234, "cat", FAN_ACCESS, "");
    ev.have_stat = true;
    ev.dev = makedev (8, 1);
    ev.ino = 42;
    ASSERT_STREQ (text (), "cat(1234): R   device 8:1 inode 42\n");
    ASSERT_STREQ (json (),
                  "{\"comm\":\"cat\",\"pid\":1234,\"types\":\"R\",\"device\":{\"major\":8,\"minor\":1},\"inode\":42}\n");

    /* path and device/inode known: text mode only shows the path */
    strcpy (ev.path, "/tmp/x");
    ASSERT_STREQ (text (), "cat(1234): R   /tmp/x\n");
    ASSERT_STREQ (json (),
                  "{\"comm\":\"cat\",\"pid\":1234,\"types\":\"R\",\"device\":{\"major\":8,\"minor\":1},\"inode\":42,\"path\":\"/tmp/x\"}\n");

    /* neither path nor device/inode known */
    event_init (1234, "cat", FAN_ACCESS, "");
    ASSERT_STREQ (text (), "cat(1234): R   \n");
    ASSERT_STREQ (json (), "{\"comm\":\"cat\",\"pid\":1234,\"types\":\"R\"}\n");

    /* no known event type */
    event_init (1234, "touch", 0, "/tmp/x");
    ASSERT_STREQ (text (), "touch(1234):     /tmp/x\n");
    ASSERT_STREQ (json (), "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"\",\"path\":\"/tmp/x\"}\n");

    /* --user */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    ev.have_ids = true;
    ev.uid = 1000;
    ev.gid = 100;
    ASSERT_STREQ (text (), "touch(1234) [1000:100]: O   /tmp/x\n");
    ASSERT_STREQ (json (),
                  "{\"comm\":\"touch\",\"pid\":1234,\"uid\":1000,\"gid\":100,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");

    /* --exe */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    strcpy (ev.proc.exe, "/usr/bin/touch");
    ASSERT_STREQ (text (), "touch(1234): O   /tmp/x exe=/usr/bin/touch\n");
    ASSERT_STREQ (json (),
                  "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\",\"exe\":\"/usr/bin/touch\"}\n");

    /* --parents; the middle one could not be read */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    event_add_parent (100, "bash", "/usr/bin/bash");
    event_add_parent (50, "", "");
    event_add_parent (1, "systemd", "/usr/lib/systemd/systemd");
    ASSERT_STREQ (text (),
                  "touch(1234): O   /tmp/x, parents=(pid=100 comm=bash exe=/usr/bin/bash),(pid=50),"
                  "(pid=1 comm=systemd exe=/usr/lib/systemd/systemd)\n");
    ASSERT_STREQ (json (),
                  "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\","
                  "\"parents\":[{\"pid\":100,\"comm\":\"bash\",\"exe\":\"/usr/bin/bash\"},{\"pid\":50},"
                  "{\"pid\":1,\"comm\":\"systemd\",\"exe\":\"/usr/lib/systemd/systemd\"}]}\n");

    /* --parents without --exe, and a parent with exe but without comm */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    event_add_parent (100, "bash", "");
    event_add_parent (50, "", "/usr/bin/foo");
    ASSERT_STREQ (text (),
                  "touch(1234): O   /tmp/x, parents=(pid=100 comm=bash),(pid=50 exe=/usr/bin/foo)\n");
    ASSERT_STREQ (json (),
                  "{\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\","
                  "\"parents\":[{\"pid\":100,\"comm\":\"bash\"},{\"pid\":50,\"exe\":\"/usr/bin/foo\"}]}\n");

    /* --timestamp; main() sets TZ=UTC */
    event_init (1234, "touch", FAN_OPEN, "/tmp/x");
    ev.time.tv_sec = 1728047655;
    ev.time.tv_usec = 1234;
    ASSERT_STREQ (text_with_timestamp_mode (TIMESTAMP_LOCAL), "13:14:15.001234 touch(1234): O   /tmp/x\n");
    ASSERT_STREQ (text_with_timestamp_mode (TIMESTAMP_EPOCH), "1728047655.001234 touch(1234): O   /tmp/x\n");
    /* TIMESTAMP_LOCAL follows the time zone; POSIX TZ string, so that this does not need tzdata */
    setenv ("TZ", "IST-5:30", 1);
    tzset ();
    ASSERT_STREQ (text_with_timestamp_mode (TIMESTAMP_LOCAL), "18:44:15.001234 touch(1234): O   /tmp/x\n");
    setenv ("TZ", "UTC", 1);
    tzset ();
    /* wall clock time is a JSON string, epoch time a number */
    ASSERT_STREQ (json_with_timestamp_mode (TIMESTAMP_LOCAL),
                  "{\"timestamp\":\"13:14:15.001234\",\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");
    ASSERT_STREQ (json_with_timestamp_mode (TIMESTAMP_EPOCH),
                  "{\"timestamp\":1728047655.001234,\"comm\":\"touch\",\"pid\":1234,\"types\":\"O\",\"path\":\"/tmp/x\"}\n");

    /* strings which are not clean UTF-8: text mode prints them verbatim */
    event_init (1234, "t\xffuch", FAN_OPEN, "/tmp/a\"b");
    ASSERT_STREQ (text (), "t\xffuch(1234): O   /tmp/a\"b\n");
    ASSERT_STREQ (json (),
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
    ASSERT_STREQ (text_with_timestamp_mode (TIMESTAMP_LOCAL),
                  "13:14:15.001234 touch(1234) [1000:100]: CWO /tmp/x exe=/usr/bin/touch, "
                  "parents=(pid=100 comm=bash exe=/usr/bin/bash),(pid=1 comm=systemd exe=/usr/lib/systemd/systemd)\n");
    ASSERT_STREQ (json_with_timestamp_mode (TIMESTAMP_EPOCH),
                  "{\"timestamp\":1728047655.001234,\"comm\":\"touch\",\"pid\":1234,\"uid\":1000,\"gid\":100,\"types\":\"CWO\","
                  "\"device\":{\"major\":8,\"minor\":1},\"inode\":42,\"path\":\"/tmp/x\",\"exe\":\"/usr/bin/touch\","
                  "\"parents\":[{\"pid\":100,\"comm\":\"bash\",\"exe\":\"/usr/bin/bash\"},"
                  "{\"pid\":1,\"comm\":\"systemd\",\"exe\":\"/usr/lib/systemd/systemd\"}]}\n");
}

/* ---- /proc reader test helpers ------------------------------------------ */

/* The readers below warn on stderr for the failure cases; mute it around the
 * call so that only real assertion failures show up in the test output. */
static int
mute_stderr (void)
{
    fflush (stderr);
    int saved = dup (STDERR_FILENO);
    int null_fd = open ("/dev/null", O_WRONLY);
    if (saved < 0 || null_fd < 0) {
        perror ("mute_stderr");
        exit (1);
    }
    dup2 (null_fd, STDERR_FILENO);
    close (null_fd);
    return saved;
}

static void
unmute_stderr (int saved)
{
    fflush (stderr);
    dup2 (saved, STDERR_FILENO);
    close (saved);
}

/* a real child process that renamed itself, so that the tests read the format
 * the running kernel actually produces */
static pid_t child_pid;
static int child_proc_fd = -1;
static int child_hold = -1;

static void
child_start (const char *comm)
{
    int ready[2], hold[2];
    if (pipe (ready) < 0 || pipe (hold) < 0) {
        perror ("pipe");
        exit (1);
    }

    child_pid = fork ();
    if (child_pid < 0) {
        perror ("fork");
        exit (1);
    }
    if (child_pid == 0) {
        close (ready[0]);
        close (hold[1]);
        char c = 'x';
        prctl (PR_SET_NAME, comm, 0, 0, 0);
        if (write (ready[1], &c, 1) != 1)
            _exit (1);
        /* stay alive, and keep this name, until the parent is done looking */
        while (read (hold[0], &c, 1) < 0 && errno == EINTR)
            ;
        _exit (0);
    }

    close (ready[1]);
    close (hold[0]);
    child_hold = hold[1];

    char c;
    if (read (ready[0], &c, 1) != 1) {
        fprintf (stderr, "child failed to rename itself\n");
        exit (1);
    }
    close (ready[0]);

    char path[64];
    snprintf (path, sizeof path, "/proc/%i", child_pid);
    child_proc_fd = open (path, O_RDONLY | O_DIRECTORY);
    if (child_proc_fd < 0) {
        perror (path);
        exit (1);
    }
}

static void
child_end (void)
{
    close (child_proc_fd);
    child_proc_fd = -1;
    close (child_hold);
    child_hold = -1;
    waitpid (child_pid, NULL, 0);
}

/* a directory standing in for /proc/PID, for contents the kernel will not
 * produce on demand; only valid until the next fake_proc_start() */
static char fake_proc_path[256];
static int fake_proc_fd = -1;

static void
fake_proc_end (void)
{
    if (fake_proc_fd < 0)
        return;
    static const char *const names[] = { "comm", "stat", "exe" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i)
        unlinkat (fake_proc_fd, names[i], 0);
    close (fake_proc_fd);
    fake_proc_fd = -1;
    rmdir (fake_proc_path);
}

static void
fake_proc_start (void)
{
    const char *tmp = getenv ("TMPDIR");
    fake_proc_end ();
    snprintf (fake_proc_path, sizeof fake_proc_path, "%s/fatrace-test.XXXXXX",
              tmp && tmp[0] ? tmp : "/tmp");
    if (mkdtemp (fake_proc_path) == NULL) {
        perror ("mkdtemp");
        exit (1);
    }
    fake_proc_fd = open (fake_proc_path, O_RDONLY | O_DIRECTORY);
    if (fake_proc_fd < 0) {
        perror (fake_proc_path);
        exit (1);
    }
}

static void
fake_proc_file (const char *name, const char *content)
{
    size_t len = strlen (content);
    int fd = openat (fake_proc_fd, name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || (size_t) write (fd, content, len) != len) {
        perror (name);
        exit (1);
    }
    close (fd);
}

#define ASSERT_INT_EQ(actual, expected) do { \
    long actual_ = (long) (actual); \
    long expected_ = (long) (expected); \
    checks++; \
    if (actual_ != expected_) { \
        failures++; \
        fprintf (stderr, "%s:%d: FAIL\n  expected: %ld\n  actual:   %ld\n", \
                 __FILE__, __LINE__, expected_, actual_); \
    } \
} while (0)

/* the parent PID get_proc_stat() reads, 0 if it could not read one */
static pid_t
stat_ppid (int proc_fd, pid_t pid)
{
    pid_t ppid = 0;
    get_proc_stat (proc_fd, pid, NULL, 0, &ppid, NULL);
    return ppid;
}

/* get_proc_stat()'s parent PID for a /proc/PID/stat with the given contents */
#define ASSERT_PPID(stat, expected) do { \
    fake_proc_start (); \
    fake_proc_file ("stat", (stat)); \
    int saved_ = mute_stderr (); \
    pid_t ppid_ = stat_ppid (fake_proc_fd, 1234); \
    unmute_stderr (saved_); \
    checks++; \
    if (ppid_ != (expected)) { \
        failures++; \
        fprintf (stderr, "%s:%d: FAIL\n  stat:     %s\n  expected: %i\n  actual:   %i\n", \
                 __FILE__, __LINE__, (stat), (int) (expected), (int) ppid_); \
    } \
} while (0)

/* get_proc_stat()'s process name for a /proc/PID/stat with the given contents */
#define ASSERT_STAT_COMM(stat, expected_ok, expected) do { \
    char buf_[FATRACE_COMM_MAX] = "unset"; \
    fake_proc_start (); \
    fake_proc_file ("stat", (stat)); \
    int saved_ = mute_stderr (); \
    bool ok_ = get_proc_stat (fake_proc_fd, 1234, buf_, sizeof buf_, NULL, NULL); \
    unmute_stderr (saved_); \
    ASSERT_INT_EQ (ok_, (expected_ok)); \
    ASSERT_STREQ (buf_, (expected)); \
} while (0)

/* get_proc_stat()'s kernel-thread flag for a /proc/PID/stat with the given contents */
#define ASSERT_KTHREAD(stat, expected) do { \
    bool kthread_ = true; \
    fake_proc_start (); \
    fake_proc_file ("stat", (stat)); \
    int saved_ = mute_stderr (); \
    get_proc_stat (fake_proc_fd, 1234, NULL, 0, NULL, &kthread_); \
    unmute_stderr (saved_); \
    ASSERT_INT_EQ (kthread_, (expected)); \
} while (0)

/* get_procname() on a /proc/PID/comm with the given contents */
#define ASSERT_PROCNAME(comm, expected_ok, expected) do { \
    char buf_[FATRACE_COMM_MAX] = "unset"; \
    fake_proc_start (); \
    if (comm) \
        fake_proc_file ("comm", (comm)); \
    int saved_ = mute_stderr (); \
    bool ok_ = get_procname (fake_proc_fd, 1234, buf_, sizeof buf_); \
    unmute_stderr (saved_); \
    ASSERT_INT_EQ (ok_, (expected_ok)); \
    if (ok_) \
        ASSERT_STREQ (buf_, (expected)); \
} while (0)

/* get_exe() on a /proc/PID/exe symlink to the given target */
#define ASSERT_EXE(target, bufsize, expected) do { \
    char buf_[bufsize]; \
    fake_proc_start (); \
    if (target && symlinkat ((target), fake_proc_fd, "exe") < 0) { \
        perror ("symlinkat"); \
        exit (1); \
    } \
    int saved_ = mute_stderr (); \
    get_exe (fake_proc_fd, 1234, buf_, sizeof buf_); \
    unmute_stderr (saved_); \
    ASSERT_STREQ (buf_, (expected)); \
} while (0)

/* ---- /proc reader tests ------------------------------------------------- */

/* Read a real process, so that these assertions are about the format the
 * running kernel produces rather than about our idea of it. */
static void
test_proc_real_process (void)
{
    char comm[FATRACE_COMM_MAX];
    char exe[PATH_MAX];
    char self[PATH_MAX];

    ssize_t len = readlink ("/proc/self/exe", self, sizeof self - 1);
    if (len < 0) {
        perror ("readlink /proc/self/exe");
        exit (1);
    }
    self[len] = '\0';

    /* an ordinary process name */
    child_start ("fatrace-child");
    ASSERT_INT_EQ (stat_ppid (child_proc_fd, child_pid), getpid ());
    ASSERT_INT_EQ (get_procname (child_proc_fd, child_pid, comm, sizeof comm), true);
    ASSERT_STREQ (comm, "fatrace-child");
    get_exe (child_proc_fd, child_pid, exe, sizeof exe);
    ASSERT_STREQ (exe, self);
    child_end ();

    /* PR_SET_NAME is unprivileged and the kernel does not escape comm in
     * /proc/PID/stat, so a process must not be able to pick the ppid we
     * report for it */
    child_start ("x) R 1");
    ASSERT_INT_EQ (stat_ppid (child_proc_fd, child_pid), getpid ());
    ASSERT_INT_EQ (get_procname (child_proc_fd, child_pid, comm, sizeof comm), true);
    ASSERT_STREQ (comm, "x) R 1");
    child_end ();

    /* ... nor an arbitrary one */
    child_start ("x) R 99999");
    ASSERT_INT_EQ (stat_ppid (child_proc_fd, child_pid), getpid ());
    child_end ();

    /* ... nor break the parse and lose its ancestry altogether */
    child_start ("a)b");
    ASSERT_INT_EQ (stat_ppid (child_proc_fd, child_pid), getpid ());
    child_end ();

    /* PR_SET_NAME does not reject a newline either, and /proc/PID/comm appends
     * one of its own, which must not be mistaken for part of the name */
    child_start ("ev\n");
    ASSERT_INT_EQ (stat_ppid (child_proc_fd, child_pid), getpid ());
    ASSERT_INT_EQ (get_procname (child_proc_fd, child_pid, comm, sizeof comm), true);
    ASSERT_STREQ (comm, "ev\n");
    child_end ();

    /* a name that fills comm exactly */
    child_start ("123456789012345");
    ASSERT_INT_EQ (get_procname (child_proc_fd, child_pid, comm, sizeof comm), true);
    ASSERT_STREQ (comm, "123456789012345");
    ASSERT_INT_EQ (stat_ppid (child_proc_fd, child_pid), getpid ());
    child_end ();
}

/* Which file we read the name from depends on unrelated options, so the two
 * readers have to agree on it for every name a process can have. */
static void
test_proc_readers_agree (void)
{
    static const char *const names[] = {
        "fatrace-child", "x) R 1", "a)b", "()", ") (", "ev\n", "a b\tc", "", "123456789012345",
    };

    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i) {
        char from_comm[FATRACE_COMM_MAX], from_stat[FATRACE_COMM_MAX];
        pid_t ppid = 0;
        bool is_kthread = true;

        child_start (names[i]);
        ASSERT_INT_EQ (get_procname (child_proc_fd, child_pid, from_comm, sizeof from_comm), true);
        ASSERT_INT_EQ (get_proc_stat (child_proc_fd, child_pid, from_stat, sizeof from_stat,
                                      &ppid, &is_kthread), true);
        ASSERT_STREQ (from_stat, names[i]);
        ASSERT_STREQ (from_stat, from_comm);
        ASSERT_INT_EQ (ppid, getpid ());
        /* a forked test process is not a kernel thread */
        ASSERT_INT_EQ (is_kthread, false);
        child_end ();
    }
}

static void
test_get_proc_stat_ppid (void)
{
    ASSERT_PPID ("1234 (bash) S 42 1234 1234 0 -1 4194304 1 2 3", 42);
    /* pid 1 has no parent */
    ASSERT_PPID ("1 (systemd) S 0 1 1 0 -1 4194560 100", 0);
    /* a process may have an empty name */
    ASSERT_PPID ("1234 () S 42 1234", 42);

    /* comm is not escaped and may contain ')' and spaces */
    ASSERT_PPID ("1234 (x) R 1) S 42 1234", 42);
    ASSERT_PPID ("1234 (x) R 99999) S 42 1234", 42);
    ASSERT_PPID ("1234 (a)b) S 42 1234", 42);
    ASSERT_PPID ("1234 ()))) S 42 1234", 42);
    ASSERT_PPID ("1234 (()) S 42 1234", 42);
    /* PR_SET_NAME does not reject newlines either */
    ASSERT_PPID ("1234 (ev\n) R 1) S 42 1234", 42);

    /* the longest comm the kernel can print is 63 bytes, for workqueue
     * workers whose names wq_worker_comm() expands ... */
    ASSERT_PPID ("1234 (012345678901234567890123456789012345678901234567890123456789abc) S 42 1234", 42);
    /* ... including when it ends with the character we search for */
    ASSERT_PPID ("1234 (012345678901234567890123456789012345678901234567890123456789ab)) S 42 1234", 42);

    /* a comm of 64 bytes cannot occur, and falls outside the window
     * get_proc_stat() searches: report unknown rather than risk a value that
     * comm picked */
    ASSERT_PPID ("1234 (012345678901234567890123456789012345678901234567890123456789abcd) S 42 1234", 0);

    /* malformed input is reported as unknown rather than guessed */
    ASSERT_PPID ("", 0);
    ASSERT_PPID ("1234 bash S 42 1234", 0);
    ASSERT_PPID ("1234 (bash", 0);
    ASSERT_PPID ("1234 (bash) S", 0);
    ASSERT_PPID ("1234 (bash) S x", 0);

    /* no stat file at all */
    fake_proc_start ();
    int saved = mute_stderr ();
    pid_t ppid = stat_ppid (fake_proc_fd, 1234);
    unmute_stderr (saved);
    ASSERT_INT_EQ (ppid, 0);
}

/* the longest name the kernel can print, 63 bytes */
#define COMM_63 "012345678901234567890123456789012345678901234567890123456789abc"

/* the name between the parentheses of stat has to come out the same as the one
 * get_procname() reads from comm; test_proc_readers_agree() covers the names
 * the running kernel can be made to produce, these the ones it cannot */
static void
test_get_proc_stat_comm (void)
{
    ASSERT_STAT_COMM ("1234 (bash) S 42 1234 1234 0 -1 4194304 1 2 3", true, "bash");
    ASSERT_STAT_COMM ("1234 () S 42 1234", true, "");
    /* comm is not escaped and may contain ')', spaces and newlines */
    ASSERT_STAT_COMM ("1234 (x) R 1) S 42 1234", true, "x) R 1");
    ASSERT_STAT_COMM ("1234 (a)b) S 42 1234", true, "a)b");
    ASSERT_STAT_COMM ("1234 ()))) S 42 1234", true, ")))");
    ASSERT_STAT_COMM ("1234 (()) S 42 1234", true, "()");
    ASSERT_STAT_COMM ("1234 (ev\n) R 1) S 42 1234", true, "ev\n) R 1");
    /* a kernel thread's name, in full */
    ASSERT_STAT_COMM ("1234 (kworker/u16:2-events_unbound) S 2 0 0 0 -1 2129984", true,
                      "kworker/u16:2-events_unbound");
    ASSERT_STAT_COMM ("1234 (" COMM_63 ") S 42 1234", true, COMM_63);
    /* 64 bytes cannot occur, and is reported as unknown rather than guessed */
    ASSERT_STAT_COMM ("1234 (" COMM_63 "d) S 42 1234", false, "");

    /* malformed input is reported as unknown rather than guessed */
    ASSERT_STAT_COMM ("", false, "");
    ASSERT_STAT_COMM ("1234 bash S 42 1234", false, "");
    ASSERT_STAT_COMM ("1234 (bash", false, "");
    ASSERT_STAT_COMM ("1234 (bash) S x", false, "");
}

static void
test_get_proc_stat_kthread (void)
{
    /* field 9 is task->flags, emitted unmasked; PF_KTHREAD is 0x00200000 */
    ASSERT_KTHREAD ("2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0", true);
    ASSERT_KTHREAD ("1234 (bash) S 42 1234 1234 0 -1 4194304 1 2 3", false);
    /* a process may not name itself into the flags field */
    ASSERT_KTHREAD ("1234 (x) R 1 1 1 1 1 2129984) S 42 1234 1234 0 -1 4194304 1", false);
    /* without a flags field we cannot tell, and say so on stderr */
    ASSERT_KTHREAD ("1234 (bash) S 42 1234", false);
}

static void
test_get_procname (void)
{
    ASSERT_PROCNAME ("bash\n", true, "bash");
    /* the trailing newline is optional */
    ASSERT_PROCNAME ("bash", true, "bash");
    /* an empty name is not an error */
    ASSERT_PROCNAME ("\n", true, "");
    ASSERT_PROCNAME ("", true, "");
    /* the kernel appends exactly one newline, so a name ending in one keeps it */
    ASSERT_PROCNAME ("ev\n\n", true, "ev\n");
    ASSERT_PROCNAME ("\n\n", true, "\n");
    ASSERT_PROCNAME ("1234567890123\n\n", true, "1234567890123\n");
    /* 15 bytes is as long as a userspace process gets: writing comm, like
     * PR_SET_NAME, truncates there */
    ASSERT_PROCNAME ("123456789012345\n", true, "123456789012345");
    /* ... and those 15 bytes may themselves end in a newline */
    ASSERT_PROCNAME ("12345678901234\n\n", true, "12345678901234\n");
    /* a kernel thread is not named that way and is not bounded by that:
     * get_kthread_comm() prints a kthread's full name and wq_worker_comm()
     * appends the work item a worker is running, both through the 64 byte
     * buffer proc_task_name() (fs/proc/array.c) formats comm in */
    ASSERT_PROCNAME ("kworker/u16:2-events_unbound\n", true, "kworker/u16:2-events_unbound");
    /* 63 bytes is all that buffer can hold ... */
    ASSERT_PROCNAME (COMM_63 "\n", true, COMM_63);
    /* ... so anything longer cannot occur, and is truncated to what fits */
    ASSERT_PROCNAME (COMM_63 "d\n", true, COMM_63);
    /* names are free-form: no quoting or escaping is applied */
    ASSERT_PROCNAME ("x) R 1\n", true, "x) R 1");
    ASSERT_PROCNAME ("a b\tc\n", true, "a b\tc");
    /* no comm file */
    ASSERT_PROCNAME (NULL, false, "");
}

/* A name is copied into the event verbatim, so it has to survive the trip
 * from /proc all the way into the output too. */
static void
test_format_event_kthread_comm (void)
{
    event_init (1234, "", FAN_OPEN, "/tmp/x");
    fake_proc_start ();
    fake_proc_file ("comm", "kworker/u16:2-events_unbound\n");
    ASSERT_INT_EQ (get_procname (fake_proc_fd, 1234, ev.proc.comm, sizeof ev.proc.comm), true);
    ASSERT_STREQ (text (), "kworker/u16:2-events_unbound(1234): O   /tmp/x\n");
    ASSERT_STREQ (json (), "{\"comm\":\"kworker/u16:2-events_unbound\",\"pid\":1234,"
                           "\"types\":\"O\",\"path\":\"/tmp/x\"}\n");
}

static void
test_comm_matches (void)
{
    ASSERT_INT_EQ (comm_matches ("bash", "bash", false), true);
    ASSERT_INT_EQ (comm_matches ("bash", "dash", false), false);
    ASSERT_INT_EQ (comm_matches ("bash", "", false), false);
    ASSERT_INT_EQ (comm_matches ("", "", false), true);
    /* a name the kernel did not cut has to match in full, not as a prefix */
    ASSERT_INT_EQ (comm_matches ("bash", "ba", false), false);
    ASSERT_INT_EQ (comm_matches ("bash", "bashful", false), false);

    /* the kernel reports a userspace name cut to 15 bytes, so the whole name
     * the user typed still selects the program they meant */
    ASSERT_INT_EQ (comm_matches ("VeryLongTouchCommand", "VeryLongTouchCo", false), true);
    ASSERT_INT_EQ (comm_matches ("VeryLongTouchCommand", "VeryLongTouchCx", false), false);
    /* only a name of exactly that length can have been cut */
    ASSERT_INT_EQ (comm_matches ("VeryLongTouchCommand", "VeryLongTouchC", false), false);
    ASSERT_INT_EQ (comm_matches ("VeryLongTouchCommand", "VeryLongTouchCom", false), false);

    /* a kernel thread's name is reported in full, and matches as it stands */
    ASSERT_INT_EQ (comm_matches ("kworker/u16:2-events_unbound", "kworker/u16:2-events_unbound", true), true);
    ASSERT_INT_EQ (comm_matches ("kworker/u16:2-events_unbound", "kworker/u16:2-events_unbounx", true), false);
    /* ... and nothing was cut off it, so it does not prefix-match either,
     * even where a userspace name of the same length would */
    ASSERT_INT_EQ (comm_matches ("kworker/u16:2-events_unbound", "kworker/u16:2-e", true), false);
    ASSERT_INT_EQ (comm_matches ("kworker/u16:2-events_unbound", "kworker/u16:2-e", false), true);

    /* @want may be longer than any name /proc can report -- fatrace warns
     * about that but does not cut it -- and then only the kernel's cut of a
     * userspace name is left to match against */
    ASSERT_INT_EQ (comm_matches (COMM_63 "d", "012345678901234", false), true);
    ASSERT_INT_EQ (comm_matches (COMM_63 COMM_63, "012345678901234", false), true);
    ASSERT_INT_EQ (comm_matches (COMM_63 "d", "01234567890123x", false), false);
    ASSERT_INT_EQ (comm_matches (COMM_63 "d", "012345678901234", true), false);
    /* a name /proc did report in full still has to be equal to it, whether it
     * is the longest one possible ... */
    ASSERT_INT_EQ (comm_matches (COMM_63, COMM_63, true), true);
    ASSERT_INT_EQ (comm_matches (COMM_63 "d", COMM_63, true), false);
    /* ... or the shortest one no userspace process can have */
    ASSERT_INT_EQ (comm_matches (COMM_63 "d", "0123456789012345", false), false);

    /* the cut form is a name of exactly 15 bytes, not a prefix of one: a
     * shorter @want does not match it either */
    ASSERT_INT_EQ (comm_matches ("bash", "bash-completion", false), false);
    ASSERT_INT_EQ (comm_matches ("", "012345678901234", false), false);
    ASSERT_INT_EQ (comm_matches ("012345678901234", "012345678901234", false), true);
}

static void
test_get_exe (void)
{
    ASSERT_EXE ("/usr/bin/touch", PATH_MAX, "/usr/bin/touch");
    /* the target need not be absolute, and is not resolved */
    ASSERT_EXE ("relative/path", PATH_MAX, "relative/path");
    /* a target longer than the buffer is silently truncated */
    ASSERT_EXE ("/usr/bin/touch", 8, "/usr/bi");
    /* no exe symlink, e.g. for a kernel thread or an exited process */
    ASSERT_EXE (NULL, PATH_MAX, "");
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
    test_proc_real_process ();
    test_proc_readers_agree ();
    test_get_proc_stat_ppid ();
    test_get_proc_stat_comm ();
    test_get_proc_stat_kthread ();
    test_get_procname ();
    test_format_event_kthread_comm ();
    test_comm_matches ();
    test_get_exe ();
    fake_proc_end ();

    if (failures) {
        fprintf (stderr, "%u of %u checks FAILED\n", failures, checks);
        return 1;
    }
    printf ("%u checks passed\n", checks);
    return 0;
}
