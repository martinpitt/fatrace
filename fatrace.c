/**
 * fatrace - Trace system wide file access events.
 *
 * (C) 2012 Canonical Ltd.
 * (C) 2026 Martin Pitt
 * Author: Martin Pitt <martin@piware.de>
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

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <mntent.h>
#include <signal.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/fanotify.h>
/* for MIN() */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>

#define BUFSIZE 256*1024

/* Likely to be less than /proc/sys/fs/fanotify/max_user_marks */
#define MAX_DIRS 4096

/* https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html ; not defined in any include file */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* deeper process trees get truncated with a warning */
#define MAX_PARENTS 64

#define DEBUG 0
#if DEBUG
#define debug(fmt, ...) fprintf (stderr, "DEBUG: " fmt "\n", ##__VA_ARGS__)
#else
#define debug(...) {}
#endif

/* data structures */

enum fatrace_timestamp {
    TIMESTAMP_NONE,
    TIMESTAMP_LOCAL,    /* HH:MM:SS.uuuuuu wall clock time */
    TIMESTAMP_EPOCH,    /* seconds.uuuuuu since the epoch */
};

struct fatrace_event_proc {
    /* Make fatrace_event_proc share alignment with fatrace_event. This is
       assumed by the assertions in event_reset(). */
    alignas (uint64_t) pid_t pid;
    char comm[TASK_COMM_LEN];   /* "" if unknown */
    char exe[PATH_MAX];         /* "" if unknown or not requested */
};

struct fatrace_event {
    struct timeval time;
    uint64_t mask;
    struct fatrace_event_proc proc;
    bool have_ids;
    uid_t uid;
    gid_t gid;
    bool fd_valid;              /* false if the file vanished before it could be looked at;
                                   then path is "" and have_stat is false */
    char path[PATH_MAX];        /* "" if unknown */
    bool have_stat;
    dev_t dev;
    ino_t ino;
    unsigned parents_len;
    struct fatrace_event_proc parents[MAX_PARENTS];
};

/* command line options */
static char* option_output = NULL;
static long option_filter_mask = 0xffffffff;
static long option_timeout = -1;
static bool option_current_mount = false;
static enum fatrace_timestamp option_timestamp = TIMESTAMP_NONE;
static bool option_user = false;
static pid_t ignored_pids[1024];
static unsigned int ignored_pids_len = 0;
static char* option_comm = NULL;
static bool option_json = false;
static bool option_parents = false;
static bool option_exe = false;
static const char *option_dirs[MAX_DIRS];
static unsigned int option_dirs_len = 0;

/* --time alarm sets this to 0 */
static volatile int running = 1;
static volatile int signaled = 0;

/* FAN_MARK_FILESYSTEM got introduced in Linux 4.20; do_mark falls back to _MOUNT */
#ifdef FAN_MARK_FILESYSTEM
static int mark_mode = FAN_MARK_ADD | FAN_MARK_FILESYSTEM;
#else
static int mark_mode = FAN_MARK_ADD | FAN_MARK_MOUNT;
#endif

/* FAN_REPORT_FID mode got introduced in Linux 5.1 */
#ifdef FAN_REPORT_FID
static int fid_mode;

/* fsid → mount fd map */

#define MAX_MOUNTS 100
static struct {
    fsid_t fsid;
    int mount_fd;
} fsids[MAX_MOUNTS];
static size_t fsids_len;

/**
 * add_fsid:
 *
 * Add fsid → mount fd map entry for a particular mount point
 */
static void
add_fsid (const char* mount_point)
{
    struct statfs s;
    int fd;

    if (fsids_len == MAX_MOUNTS) {
        warnx ("Too many mounts, not resolving fd paths for %s", mount_point);
        return;
    }

    fd = open (mount_point, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        warn ("Failed to open mount point %s", mount_point);
        return;
    }

    if (fstatfs (fd, &s) < 0) {
        warn ("Failed to stat mount point %s", mount_point);
        close (fd);
        return;
    }

    memcpy (&fsids[fsids_len].fsid, &s.f_fsid, sizeof (s.f_fsid));
    fsids[fsids_len++].mount_fd = fd;
    debug ("mount %s fd %i", mount_point, fd);
}

static int
get_mount_id (const fsid_t *fsid)
{
    for (size_t i = 0; i < fsids_len; ++i) {
        if (memcmp (fsid, &fsids[i].fsid, sizeof (fsids[i].fsid)) == 0) {
            debug ("mapped fsid to fd %i", fsids[i].mount_fd);
            return fsids[i].mount_fd;
        }
    }

    debug ("fsid not found, default to AT_FDCWD\n");
    return AT_FDCWD;
}

/**
 * get_fid_event_fd:
 *
 * In FAN_REPORT_FID mode, return an fd for the event's target.
 */
static int
get_fid_event_fd (const struct fanotify_event_metadata *data)
{
    const struct fanotify_event_info_fid *fid = (const struct fanotify_event_info_fid *) (data + 1);
    int fd;

    if (fid->hdr.info_type != FAN_EVENT_INFO_TYPE_FID) {
        warnx ("Received unexpected event info type %i, cannot get affected file", fid->hdr.info_type);
        return -1;
    }

    /* get affected file fd from fanotify_event_info_fid */
    fd = open_by_handle_at (get_mount_id ((const fsid_t *) &fid->fsid),
                            (struct file_handle *) fid->handle, O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_PATH);
    /* ignore ESTALE for deleted fds between the notification and handling it */
    if (fd < 0 && errno != ESTALE)
        warn ("open_by_handle_at");

    return fd;
}

#else /* defined(FAN_REPORT_FID) */

#define add_fsid(...)

#endif /* defined(FAN_REPORT_FID) */

/**
 * mask2str:
 *
 * Convert a fanotify_event_metadata mask into a human readable string.
 *
 * Returns: decoded mask; only valid until the next call, do not free.
 */
static const char*
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

/**
 * show_pid:
 *
 * Check if events for given PID should be logged.
 *
 * Returns: true if PID is to be logged, false if not.
 */
static bool
show_pid (pid_t pid)
{
    unsigned int i;
    for (i = 0; i < ignored_pids_len; ++i)
        if (pid == ignored_pids[i])
            return false;

    return true;
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
        if (// Not C0 control character
            // https://en.wikipedia.org/wiki/C0_and_C1_control_codes
            0x20 <= c &&
            // Not double quote or backslash, which require JSON escaping
            c != '"' && c != '\\' &&
            // Not unprintable DEL (0x7f) or non-ASCII
            c <= 0x7e) {
            i++; continue;
        }
        // it's ok to read s[i+1] since we know s[i] != 0
        uint32_t mbc = c<<8 | s[i+1];
        if (// 2-char: 110xxxxx 10xxxxxx
            (mbc & 0xe0c0) == 0xc080 &&
            // but not 1100000x 10xxxxxx (overlong)
            (mbc & 0xfec0) != 0xc080 &&
            // neither 11000010 100xxxxx (C1 control characters)
            // https://en.wikipedia.org/wiki/C0_and_C1_control_codes
            (mbc & 0xffe0) != 0xc280) {
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

/* print time value in the given mode */
static void
format_time (FILE *out, const struct timeval *tv, enum fatrace_timestamp mode)
{
    assert (mode != TIMESTAMP_NONE);
    if (mode == TIMESTAMP_LOCAL) {
        char hms[9];
        strftime (hms, sizeof hms, "%H:%M:%S", localtime (&tv->tv_sec));
        fputs (hms, out);
    } else if (mode == TIMESTAMP_EPOCH) {
        /* time_t may be wider than long on 32 bit with _TIME_BITS=64 */
        fprintf (out, "%lli", (long long) tv->tv_sec);
    }
    fprintf (out, ".%06li", (long) tv->tv_usec);
}

void
format_fatrace_event_text (FILE *out, const struct fatrace_event *ev, enum fatrace_timestamp timestamp_mode)
{
    if (timestamp_mode != TIMESTAMP_NONE) {
        format_time (out, &ev->time, timestamp_mode);
        putc (' ', out);
    }

    fprintf (out, "%s(%i)", ev->proc.comm[0] ? ev->proc.comm : "unknown", ev->proc.pid);
    if (ev->have_ids)
        fprintf (out, " [%u:%u]", ev->uid, ev->gid);
    fprintf (out, ": %-3s ", mask2str (ev->mask));

    if (!ev->fd_valid)
        fputs ("(deleted)", out);
    else if (ev->path[0])
        fputs (ev->path, out);
    else if (ev->have_stat)
        fprintf (out, "device %u:%u inode %llu", major (ev->dev), minor (ev->dev), (unsigned long long) ev->ino);

    if (ev->proc.exe[0])
        fprintf (out, " exe=%s", ev->proc.exe);

    for (unsigned i = 0; i < ev->parents_len; ++i) {
        const struct fatrace_event_proc *p = &ev->parents[i];
        fprintf (out, "%s(pid=%i", i == 0 ? ", parents=" : ",", p->pid);
        if (p->comm[0])
            fprintf (out, " comm=%s", p->comm);
        if (p->exe[0])
            fprintf (out, " exe=%s", p->exe);
        putc (')', out);
    }

    putc ('\n', out);
}

void
format_fatrace_event_json (FILE *out, const struct fatrace_event *ev, enum fatrace_timestamp timestamp_mode)
{
    putc ('{', out);
    if (timestamp_mode != TIMESTAMP_NONE) {
        /* wall clock time is a string, epoch time a number */
        const char *quote = timestamp_mode == TIMESTAMP_LOCAL ? "\"" : "";
        fprintf (out, "\"timestamp\":%s", quote);
        format_time (out, &ev->time, timestamp_mode);
        fprintf (out, "%s,", quote);
    }

    if (ev->proc.comm[0]) {
        print_json_str (out, "comm", ev->proc.comm);
        putc (',', out);
    }
    fprintf (out, "\"pid\":%i,", ev->proc.pid);
    if (ev->have_ids)
        fprintf (out, "\"uid\":%u,\"gid\":%u,", ev->uid, ev->gid);
    fprintf (out, "\"types\":\"%s\"", mask2str (ev->mask));

    if (ev->have_stat)
        fprintf (out, ",\"device\":{\"major\":%u,\"minor\":%u},\"inode\":%llu",
                 major (ev->dev), minor (ev->dev), (unsigned long long) ev->ino);
    if (ev->path[0]) {
        putc (',', out);
        print_json_str (out, "path", ev->path);
    }
    if (ev->proc.exe[0]) {
        putc (',', out);
        print_json_str (out, "exe", ev->proc.exe);
    }

    for (unsigned i = 0; i < ev->parents_len; ++i) {
        const struct fatrace_event_proc *p = &ev->parents[i];
        fprintf (out, "%s{\"pid\":%i", i == 0 ? ",\"parents\":[" : ",", p->pid);
        if (p->comm[0]) {
            putc (',', out);
            print_json_str (out, "comm", p->comm);
        }
        if (p->exe[0]) {
            putc (',', out);
            print_json_str (out, "exe", p->exe);
        }
        putc ('}', out);
    }
    if (ev->parents_len > 0)
        putc (']', out);

    fputs ("}\n", out);
}

/* given an fd to /proc/PID and a buffer of size TASK_COMM_LEN, try to read the
   process name. Return true on success. */
static bool
get_procname (int proc_fd, pid_t pid, char *procname, size_t procname_size) {
    int fd = openat (proc_fd, "comm", O_RDONLY);
    if (fd < 0) {
        warn ("failed to open /proc/%u/comm", pid);
        return false;
    }
    ssize_t len = read (fd, procname, procname_size - 1);
    close (fd);
    if (len < 0) {
        warn ("failed to read /proc/%u/comm", pid);
        return false;
    }
    /* the kernel appends exactly one newline; stripping every trailing one
       would eat a newline the name itself ends in */
    if (len > 0 && procname[len-1] == '\n')
        len--;
    procname[len] = '\0';
    return true;
}

/* proc_task_name() (fs/proc/array.c) renders comm through a 64 byte buffer, for
   both /proc/PID/comm and the comm field of /proc/PID/stat; TASK_COMM_LEN (16)
   bounds only what userspace can set. */
#define STAT_COMM_MAX 64

/* given an fd to /proc/PID, return the parent PID, or 0 if there is none or it
   could not be read -- the latter warns on stderr. A process has no parent PID
   when it is pid 1, when it is pid 2 (kthreadd, whose parent is the idle task),
   or when its parent lives in an ancestor PID namespace, as after
   "docker exec"; the chain does not always end at pid 1. */
static pid_t
get_ppid (int proc_fd, pid_t pid) {
    static char statbuf[4096];
    int stat_fd = openat (proc_fd, "stat", O_RDONLY);
    if (stat_fd < 0) {
        warn ("failed to open /proc/%u/stat", pid);
        return 0;
    }
    ssize_t len = read (stat_fd, statbuf, sizeof (statbuf));
    close (stat_fd);
    if (len < 0) {
        warn ("failed to read /proc/%u/stat", pid);
        return 0;
    }
    /* buffer is static, and read() does not nul terminate */
    statbuf[MIN(len, sizeof (statbuf) - 1)] = '\0';

    /* The format is "PID (COMM) STATE PPID ...". COMM is printed unescaped and
       may contain ')' and spaces, so skipping it with "%*[^)]" stops at the
       first ')' inside it and lets a process pick the PPID we report for it,
       e.g. by prctl(PR_SET_NAME, "x) R 1"). Every field after COMM is numeric,
       so COMM's closing ')' is the last ')' within STAT_COMM_MAX bytes of the
       only '('; searching just that window stays cheap as fields are appended. */
    const char *open_paren = strchr (statbuf, '(');
    if (open_paren != NULL) {
        /* one past the last byte that can hold COMM's closing ')', clamped to
           the end of the string so a short read cannot run off it */
        const char *end = open_paren + strnlen (open_paren, STAT_COMM_MAX + 1);

        for (const char *p = end - 1; p > open_paren; --p) {
            if (*p != ')')
                continue;
            pid_t ret;
            if (sscanf (p + 1, " %*c %d", &ret) == 1)
                return ret;
            /* an earlier ')' would only yield a PPID that COMM chose */
            break;
        }
    }

    /* this *really* should not happen, kernel API change  */
    warnx ("failed to parse /proc/%u/stat, please file a bug: %s", pid, statbuf);
    return 0;
}

/* read /proc/PID/exe; "" on failure */
static void
get_exe (int proc_fd, pid_t pid, char *exe, size_t exe_size) {
    ssize_t len = readlinkat (proc_fd, "exe", exe, exe_size - 1);
    if (len < 0) {
        warn ("failed to readlink /proc/%i/exe", pid);
        len = 0;
    }
    exe[len] = '\0';
}

/* Initialize or reinitialize a struct fatrace_event  */
static void
event_reset (struct fatrace_event* ev)
{
    /* parents[] is the bulk of the struct and only valid up to parents_len.
       Assert compile-time that parents[] is the last member, and reset by
       writing 0 to everything but parents[]. */
    static_assert (alignof (typeof (*ev)) == alignof (typeof (ev->parents[0])),
                   "fatrace_event and fatrace_event_proc need to share alignment.");
    static_assert (sizeof (*ev) == offsetof (typeof (*ev), parents) + sizeof (ev->parents),
                   "parents[] needs to be the last member of struct fatrace_event");
    memset (ev, 0, offsetof (typeof (*ev), parents));
}

/**
 * process_event:
 *
 * Apply the filter options to a fanotify event and collect all information into @ev
 *
 * Returns: true if the event passed the filters and @ev is valid, false if the
 * event is ignored.
 */
static bool
process_event (const struct fanotify_event_metadata *data,
               const struct timeval *event_time,
               struct fatrace_event *ev)
{
    int event_fd = data->fd;
    static char procpath[100];
    static char procname[TASK_COMM_LEN];
    static int procname_pid = -1;
    bool got_procname = false;
    pid_t ppid = 0;

    if ((data->mask & option_filter_mask) == 0 || !show_pid (data->pid)) {
        if (event_fd >= 0)
            close (event_fd);
        return false;
    }

    event_reset (ev);
    ev->time = *event_time;
    ev->mask = data->mask;
    ev->proc.pid = data->pid;

    snprintf (procpath, sizeof (procpath), "/proc/%i", data->pid);
    int proc_fd = open (procpath, O_RDONLY | O_DIRECTORY);
    if (proc_fd >= 0) {
        if (option_parents)
            ppid = get_ppid (proc_fd, data->pid);

        if (get_procname (proc_fd, data->pid, procname, sizeof (procname))) {
            procname_pid = data->pid;
            got_procname = true;
        }

        /* /proc/PID is owned by the process' user and group */
        if (option_user) {
            struct stat st;
            if (fstat (proc_fd, &st) < 0) {
                warn ("failed to stat /proc/%i", data->pid);
            } else {
                ev->have_ids = true;
                ev->uid = st.st_uid;
                ev->gid = st.st_gid;
            }
        }

        if (option_exe)
            get_exe (proc_fd, data->pid, ev->proc.exe, sizeof (ev->proc.exe));

        close (proc_fd);
    } else {
        warn ("failed to open /proc/%i", data->pid);
    }

    /* /proc/pid/comm often goes away before processing the event; reuse previously cached value if pid still matches */
    if (!got_procname) {
        if (data->pid == procname_pid) {
            debug ("re-using cached procname value %s for pid %i", procname, procname_pid);
        } else if (procname_pid >= 0) {
            debug ("invalidating previously cached procname %s for pid %i", procname, procname_pid);
            procname_pid = -1;
            procname[0] = '\0';
        }
    }

    if (option_comm && strcmp (option_comm, procname) != 0 &&
        procname[0] != '\0') {
        if (event_fd >= 0)
            close (event_fd);
        return false;
    }
    memcpy (ev->proc.comm, procname, sizeof (procname));

#ifdef FAN_REPORT_FID
    if (fid_mode)
        event_fd = get_fid_event_fd (data);
#endif

    if (event_fd >= 0) {
        struct stat st;

        ev->fd_valid = true;
        if (fstat (event_fd, &st) < 0) {
            warn ("stat");
        } else {
            ev->have_stat = true;
            ev->dev = st.st_dev;
            ev->ino = st.st_ino;
        }

        snprintf (procpath, sizeof (procpath), "/proc/self/fd/%i", event_fd);
        ssize_t len = readlink (procpath, ev->path, sizeof (ev->path) - 1);
        if (len >= 0)
            ev->path[len] = '\0';

        close (event_fd);
    }

    while (ppid > 0) {
        if (ev->parents_len == MAX_PARENTS) {
            warnx ("process %i has more than %i parents, truncating", data->pid, MAX_PARENTS);
            break;
        }
        struct fatrace_event_proc *parent = &ev->parents[ev->parents_len++];
        parent->pid = ppid;
        parent->comm[0] = '\0';
        parent->exe[0] = '\0';

        snprintf (procpath, sizeof (procpath), "/proc/%i", ppid);
        int ppid_dir_fd = open (procpath, O_RDONLY | O_DIRECTORY);
        if (ppid_dir_fd >= 0) {
            get_procname (ppid_dir_fd, ppid, parent->comm, sizeof (parent->comm));
            if (option_exe)
                get_exe (ppid_dir_fd, ppid, parent->exe, sizeof (parent->exe));
            /* get next parent */
            if (ppid == 1)
                ppid = 0;
            else
                ppid = get_ppid (ppid_dir_fd, ppid);
            close (ppid_dir_fd);
        } else {
            warn ("failed to open %s", procpath);
            ppid = 0;
        }
    }

    return true;
}

static void
do_mark (int fan_fd, const char *dir, bool fatal)
{
    int res;
    uint64_t mask = FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD;

#ifdef FAN_REPORT_FID
    if (fid_mode)
        mask |= FAN_CREATE | FAN_DELETE | FAN_MOVE;
#endif

    res = fanotify_mark (fan_fd, mark_mode, mask, AT_FDCWD, dir);

#ifdef FAN_MARK_FILESYSTEM
    /* fallback for Linux < 4.20 */
    if (res < 0 && errno == EINVAL && mark_mode & FAN_MARK_FILESYSTEM)
    {
        debug ("FAN_MARK_FILESYSTEM not supported; falling back to FAN_MARK_MOUNT");
        mark_mode = FAN_MARK_ADD | FAN_MARK_MOUNT;
        do_mark (fan_fd, dir, fatal);
        return;
    }
#endif

    if (res < 0)
    {
        if (fatal)
            err (EXIT_FAILURE, "Failed to add watch for %s", dir);
        else
            warn ("Failed to add watch for %s", dir);
    }
}

/**
 * setup_fanotify:
 *
 * @fan_fd: fanotify file descriptor as returned by fanotify_init().
 *
 * Set up fanotify watches on all mount points, or on the current directory
 * mount if --current-mount is given.
 */
static void
setup_fanotify (int fan_fd)
{
    if (option_dirs_len > 0) {
        mark_mode = FAN_MARK_ADD;
        char resolved[PATH_MAX];
        struct stat st;
        for (unsigned i = 0; i < option_dirs_len; i++) {
            if (realpath(option_dirs[i], resolved) &&
                stat(resolved, &st) == 0) {
                if (S_ISDIR(st.st_mode))
                    do_mark (fan_fd, resolved, false);
                else
                    errx(EXIT_FAILURE,
                         "Not a directory: %s", option_dirs[i]);
            }
            else
                err(EXIT_FAILURE,
                    "Cannot resolve directory: %s", option_dirs[i]);
        }
        return;
    }

    FILE* mounts;
    struct mntent* mount;

    if (option_current_mount) {
        do_mark (fan_fd, ".", true);
        return;
    }

    /* iterate over all mounts; explicitly start with the root dir, to get
     * the shortest possible paths on fsid resolution on e. g. OSTree */
    do_mark (fan_fd, "/", false);
    add_fsid ("/");

    mounts = setmntent ("/proc/self/mounts", "r");
    if (mounts == NULL)
        err (EXIT_FAILURE, "setmntent");

    while ((mount = getmntent (mounts)) != NULL) {
        /* Only consider mounts which have an actual device or bind mount
         * point. The others are stuff like proc, sysfs, binfmt_misc etc. which
         * are virtual and do not actually cause disk access. */
        if (mount->mnt_fsname == NULL || access (mount->mnt_fsname, F_OK) != 0 ||
            mount->mnt_fsname[0] != '/') {
            /* zfs mount point don't start with a "/" so allow them anyway */
            if (strcmp(mount->mnt_type, "zfs") != 0) {
                debug ("ignore: fsname: %s dir: %s type: %s", mount->mnt_fsname, mount->mnt_dir, mount->mnt_type);
                continue;
            }
        }

        /* root dir already added above */
        if (strcmp (mount->mnt_dir, "/") == 0)
            continue;

        debug ("add watch for %s mount %s", mount->mnt_type, mount->mnt_dir);
        do_mark (fan_fd, mount->mnt_dir, false);
        add_fsid (mount->mnt_dir);
    }

    endmntent (mounts);
}

/**
 * help:
 *
 * Show help.
 */
static void
help (void)
{
    puts ("Usage: fatrace [options...] [--] [DIR...]\n"
"\n"
"Options:\n"
"  -c, --current-mount           Only record events on partition/mount of\n"
"                                current directory.\n"
"  -o FILE, --output=FILE        Write events to a file instead of standard\n"
"                                output.\n"
"  -s SECONDS, --seconds=SECONDS Stop after the given number of seconds.\n"
"  -t, --timestamp               Add timestamp to events. Give twice for seconds\n"
"                                since the epoch.\n"
"  -u, --user                    Add user ID and group ID to events.\n"
"  -p PID, --ignore-pid=PID      Ignore events for this process ID. Can be\n"
"                                specified multiple times.\n"
"  -f TYPES, --filter=TYPES      Show only the given event types; choose from C,\n"
"                                R, O, W, +, D, < or >, e. g. --filter=OC.\n"
"  -C COMM, --command=COMM       Show only events for this command.\n"
"  -j, --json                    Write events in JSONL format.\n"
"  -P, --parents                 Include information about all parent processes.\n"
"  -e, --exe                     Add executable path to events.\n"
"  -d DIR, --dir=DIR             Show only events on files directly under this\n"
"                                directory. NOT recursive. Can be specified\n"
"                                multiple times. DIRs can also be specified at\n"
"                                the end of the command line.\n"
"  -h, --help                    Show help.");
}

/**
 * parse_args:
 *
 * Parse command line arguments and set the global option_* variables.
 */
static void
parse_args (int argc, char** argv)
{
    int c;
    int j;
    long pid;
    char *endptr;

    static struct option long_options[] = {
        {"current-mount", no_argument,       0, 'c'},
        {"output",        required_argument, 0, 'o'},
        {"seconds",       required_argument, 0, 's'},
        {"timestamp",     no_argument,       0, 't'},
        {"user",          no_argument,       0, 'u'},
        {"ignore-pid",    required_argument, 0, 'p'},
        {"filter",        required_argument, 0, 'f'},
        {"command",       required_argument, 0, 'C'},
        {"json",          no_argument,       0, 'j'},
        {"parents",       no_argument,       0, 'P'},
        {"exe",           no_argument,       0, 'e'},
        {"dir",           required_argument, 0, 'd'},
        {"help",          no_argument,       0, 'h'},
        {0,               0,                 0,  0 }
    };

    while (1) {
        c = getopt_long (argc, argv, "C:co:s:tup:f:jPed:h", long_options, NULL);

        if (c == -1)
            break;

        switch (c) {
            case 'C':
                option_comm = strdup (optarg);
                if (!option_comm)
                    err(EXIT_FAILURE, "memory allocation failed for --command");
                /* see https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html */
                if (strlen (option_comm) > TASK_COMM_LEN - 1) {
                    option_comm[TASK_COMM_LEN - 1] = '\0';
                    warnx ("--command truncated to %i characters: %s", TASK_COMM_LEN - 1, option_comm);
                }
                break;

            case 'c':
                option_current_mount = true;
                break;

            case 'o':
                option_output = strdup (optarg);
                if (!option_output)
                    err(EXIT_FAILURE, "memory allocation failed for --output");
                break;

            case 'u':
                option_user = true;
                break;

            case 'f':
                j = 0;
                option_filter_mask = 0;
                while (optarg[j] != '\0') {
                    switch (toupper (optarg[j])) {
                        case 'R':
                            option_filter_mask |= FAN_ACCESS;
                            break;
                        case 'C':
                            option_filter_mask |= FAN_CLOSE_WRITE;
                            option_filter_mask |= FAN_CLOSE_NOWRITE;
                            break;
                        case 'W':
                            option_filter_mask |= FAN_CLOSE_WRITE;
                            option_filter_mask |= FAN_MODIFY;
                            break;
                        case 'O':
                            option_filter_mask |= FAN_OPEN;
                            break;
#ifdef FAN_REPORT_FID
                        case '+':
                            option_filter_mask |= FAN_CREATE;
                            break;
                        case 'D':
                            option_filter_mask |= FAN_DELETE;
                            break;
                        case '<':
                            option_filter_mask |= FAN_MOVED_FROM;
                            break;
                        case '>':
                            option_filter_mask |= FAN_MOVED_TO;
                            break;
#endif
                        default:
                            errx (EXIT_FAILURE, "Error: Unknown --filter type '%c'", optarg[j]);
                    }
                    j++;
                }
                break;

            case 's':
                option_timeout = strtol (optarg, &endptr, 10);
                if (*endptr != '\0' || option_timeout <= 0)
                    errx (EXIT_FAILURE, "Error: Invalid number of seconds");
                break;

            case 'p':
                pid = strtol (optarg, &endptr, 10);
                if (*endptr != '\0' || pid <= 0)
                    errx (EXIT_FAILURE, "Error: Invalid PID");
                if (ignored_pids_len
                    < (sizeof (ignored_pids) / sizeof (ignored_pids[0])))
                    ignored_pids[ignored_pids_len++] = pid;
                else
                    errx (EXIT_FAILURE, "Error: Too many ignored PIDs");
                break;

            case 't':
                if (++option_timestamp > TIMESTAMP_EPOCH)
                    errx (EXIT_FAILURE, "Error: --timestamp option can be given at most two times");
                break;

            case 'j':
                option_json = true;
                break;

            case 'P':
                option_parents = true;
                break;

            case 'e':
                option_exe = true;
                break;

            case 'd':
                if (option_dirs_len >= MAX_DIRS)
                    errx (EXIT_FAILURE, "Error: Too many --dir arguments"
                          " (maximum is %d).", MAX_DIRS);
                option_dirs[option_dirs_len++] = optarg;
                break;

            case 'h':
                help ();
                exit (EXIT_SUCCESS);

            case '?':
                /* getopt_long() already prints error message */
                exit (EXIT_FAILURE);

            default:
                errx (EXIT_FAILURE, "Internal error: unexpected option '%c'", c);
        }
    }
    for (int i = optind; i < argc; i++) {
        if (option_dirs_len >= MAX_DIRS)
            errx (EXIT_FAILURE, "Error: Too many --dir and DIR arguments"
                  " (maximum is %d).", MAX_DIRS);
        option_dirs[option_dirs_len++] = argv[i];
    }
    if (option_current_mount && option_dirs_len > 0)
        errx (EXIT_FAILURE,
              "Error: -c,--current-mount and -d,--dir are mutually exclusive.");
}

static void
signal_handler (int signal)
{
    (void)signal;

    /* ask the main loop to stop */
    running = 0;
    signaled++;

    /* but if stuck in some others functions, just quit now */
    if (signaled > 1)
        _exit (EXIT_FAILURE);
}

#ifdef FATRACE_UNIT_TEST
/* A unit test has its own main function, so we must rename this one.
   We can't remove it though, as it would orphan some static functions above. */
#define FATRACE_MAIN fatrace_main
#else
#define FATRACE_MAIN main
#endif

int
FATRACE_MAIN (int argc, char** argv)
{
    int fan_fd = -1;
    int res;
    void *buffer;
    struct fanotify_event_metadata *data;
    struct sigaction sa;
    struct timeval event_time;
    static struct fatrace_event event;
    void (*format_event) (FILE *, const struct fatrace_event *, enum fatrace_timestamp);

    /* always ignore events from ourselves (writing log file) */
    ignored_pids[ignored_pids_len++] = getpid ();

    parse_args (argc, argv);
    format_event = option_json ? format_fatrace_event_json : format_fatrace_event_text;

#ifdef FAN_REPORT_FID
    fan_fd = fanotify_init (FAN_CLASS_NOTIF | FAN_REPORT_FID, O_LARGEFILE);
    if (fan_fd >= 0)
        fid_mode = 1;

    if (fan_fd < 0 && errno == EINVAL)
        debug ("FAN_REPORT_FID not available");
#endif
    if (fan_fd < 0)
        fan_fd = fanotify_init (0, O_LARGEFILE);

    if (fan_fd < 0) {
        int e = errno;
        perror ("Cannot initialize fanotify");
        if (e == EPERM)
            fputs ("You need to run this program as root.\n", stderr);
        exit (EXIT_FAILURE);
    }

    setup_fanotify (fan_fd);

    /* allocate memory for fanotify */
    buffer = NULL;
    res = posix_memalign (&buffer, 4096, BUFSIZE);
    if (res != 0 || buffer == NULL)
        err (EXIT_FAILURE, "Failed to allocate buffer");

    /* output file? */
    if (option_output) {
        int fd = open (option_output, O_CREAT|O_WRONLY|O_EXCL, 0666);
        if (fd < 0)
            err (EXIT_FAILURE, "Failed to open output file");
        fflush (stdout);
        dup2 (fd, STDOUT_FILENO);
        close (fd);
    }

    /* useful for live tailing and multiple writers */
    setlinebuf (stdout);

    /* setup signal handler to cleanly stop the program */
    sa.sa_handler = signal_handler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction (SIGINT, &sa, NULL) < 0)
        err (EXIT_FAILURE, "sigaction");

    /* set up --time alarm */
    if (option_timeout > 0) {
        sa.sa_handler = signal_handler;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction (SIGALRM, &sa, NULL) < 0)
            err (EXIT_FAILURE, "sigaction");
        alarm (option_timeout);
    }

    /* clear event time if timestamp is not required */
    if (!option_timestamp) {
        memset (&event_time, 0, sizeof (struct timeval));
    }

    /* read all events in a loop */
    while (running) {
        res = read (fan_fd, buffer, BUFSIZE);
        if (res == 0) {
            fprintf (stderr, "No more fanotify event (EOF)\n");
            break;
        }
        if (res < 0) {
            if (errno == EINTR)
                continue;
            err (EXIT_FAILURE, "read");
        }

        /* get event time, if requested */
        if (option_timestamp) {
            if (gettimeofday (&event_time, NULL) < 0)
                err (EXIT_FAILURE, "gettimeofday");
        }

        data = (struct fanotify_event_metadata *) buffer;
        while (FAN_EVENT_OK (data, res)) {
            if (data->vers != FANOTIFY_METADATA_VERSION)
                errx (EXIT_FAILURE, "Mismatch of fanotify metadata version");
            if (process_event (data, &event_time, &event))
                format_event (stdout, &event, option_timestamp);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
}
