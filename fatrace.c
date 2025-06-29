/**
 * fatrace - Trace system wide file access events.
 *
 * (C) 2012 Canonical Ltd.
 * Author: Martin Pitt <martin.pitt@ubuntu.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <mntent.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/fanotify.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <ctype.h>
#include <ftw.h>

#define BUFSIZE 256*1024

/* https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html ; not defined in any include file */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define DEBUG 0
#if DEBUG
#define debug(fmt, ...) fprintf (stderr, "DEBUG: " fmt "\n", ##__VA_ARGS__)
#else
#define debug(...) {}
#endif

/* command line options */
static char* option_output = NULL;
static long option_filter_mask = 0xffffffff;
static long option_timeout = -1;
static int option_current_mount = 0;
static int option_timestamp = 0;
static int option_user = 0;
static pid_t ignored_pids[1024];
static unsigned int ignored_pids_len = 0;
static char* option_comm = NULL;
static int option_json = 0;
static int option_inclusive = 0;
static int option_ancestors = 0;
static int option_exe = 0;
static const char *option_dirs[1024];
static int option_dir_lens[1024];
static int dir_watch_mode = 0;
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

/**
 * show_path:
 *
 * Check if events for given path should be logged.
 *
 * Returns: true if path is to be logged, false if not.
 */
static bool
show_path (const char* path)
{
    if (option_dirs_len == 0) return true;
    int plen = strlen(path);
    for (unsigned int i = 0; i < option_dirs_len; i++) {
        const char* compare_to_dir = option_dirs[i];
        int compare_to_dir_len = option_dir_lens[i];
        if (compare_to_dir_len <= plen &&
            (path[compare_to_dir_len] == '\0' ||
             path[compare_to_dir_len] == '/') &&
            memcmp(path, compare_to_dir, compare_to_dir_len) == 0)
            return true;
    }
    return false;
}

static bool
print_json_str (const char* key, const char* value) {
    const unsigned char* str = (unsigned char*)value;
    printf("\"%s\":\"", key);
    bool decode_problem = false;
    for (int i = 0; str[i] != 0; ) {
        char c = str[i];
        // 1-char: 0xxxxxxx
        switch(c) {
            case '"':    printf("\\\""); i++; continue;
            case '\\': printf("\\\\"); i++; continue;
            case '\b': printf("\\b"); i++; continue;
            case '\f': printf("\\f"); i++; continue;
            case '\n': printf("\\n"); i++; continue;
            case '\r': printf("\\r"); i++; continue;
            case '\t': printf("\\t"); i++; continue;
        }
        if (0x20 <= c && c <= 0x7e) {
            putchar(c); i++; continue;
        }
        if ((c & 0x80) == 0) {
            printf("\\u%04x", c); i++; continue;
        }
        // 2-char: 110xxxxx 10xxxxxx
        // but not 1100000x 10xxxxxx (overlong)
        if ((c                    & 0xe0) == 0xc0 &&
            (c                    & 0xfe) != 0xc0 &&
            (str[i+1] & 0xc0) == 0x80)
        {
            printf("\\u%04x", (c & 0x1f) << 6 | (str[i+1] & 0x3f));
            i+=2; continue;
        }
        // 3-char: 1110xxxx 10xxxxxx 10xxxxxx
        // but not 11100000 100xxxxx 10xxxxxx (overlong)
        // neither 11101101 101xxxxx 10xxxxxx (reserved for surrogate pairs)
        if ((c                    & 0xf0) == 0xe0 &&
            (str[i+1] & 0xc0) == 0x80 &&
            ((c & 0x0f) | (str[i+1] & 0x20)) != 0x00 &&
            ((c & 0x0f) | (str[i+1] & 0x20)) != 0x2d &&
            (str[i+2] & 0xc0) == 0x80)
        {
            printf("\\u%04x",
                   (c & 0x0f) << 12 |
                   (str[i+1] & 0x3f) << 6 |
                   (str[i+2] & 0x3f));
            i+=3; continue;
        }
        // 4-char: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
        // but not 11110000 1000xxxx 10xxxxxx 10xxxxxx (overlong)
        // neither 11110PPP 10PPxxxx 10xxxxxx 10xxxxxx, PPPPP>0x10 (too big)
        if ((c                    & 0xf8) == 0xf0 &&
            (str[i+1] & 0xc0) == 0x80 &&
            ((c & 0x07) | (str[i+1] & 0x30)) != 0 &&
            (((c & 0x07) << 2) | ((str[i+1] & 0x30) >> 4)) <= 0x10 &&
            (str[i+2] & 0xc0) == 0x80 &&
            (str[i+3] & 0xc0) == 0x80)
        {
            int cp = ((c & 0x07) << 18 |
                      (str[i+1] & 0x3f) << 12 |
                      (str[i+2] & 0x3f) << 6 |
                      (str[i+3] & 0x3f));
            int hsp = ((cp - 0x10000) >> 10)    | 0xd800;
            int lsp = ((cp - 0x10000) & 0x3f) | 0xdc00;
            printf("\\u%04x\\u%04x", hsp, lsp);
            i+=4; continue;
        }
        printf("\\ufffd");
        decode_problem = true;
        i++; continue;
    }
    putchar('"');
    if (decode_problem) {
        printf(",\"%s_raw\":[", key);
        for (int i = 0; str[i] != 0; i++)
          printf(i ? ",%d" : "%d", (unsigned int)(str[i]));
        putchar(']');
    }
    return decode_problem;
}

static int mark_cb(const char *fpath, const struct stat*, int typeflag,
                   struct FTW*);

/**
 * print_event:
 *
 * Print data from fanotify_event_metadata struct to stdout.
 */
static void
print_event (const struct fanotify_event_metadata *data,
             const struct timeval *event_time)
{
    const char* problems[18];
    int problem_idx = 0;
    int event_fd = data->fd;
    static char printbuf[100];
    static char procname[TASK_COMM_LEN];
    static int procname_pid = -1;
    static char procname2[TASK_COMM_LEN];
    static int procname2_pid = -1;
    static char pathname[PATH_MAX];
    bool got_procname = false;
    static char exepath[PATH_MAX];
    bool got_exepath = false;
    struct stat proc_fd_stat = { .st_uid = -1 };
    int ppid = 0;
    bool got_ppid = false;
    static char statbuf[4096];

    if ((data->mask & option_filter_mask) == 0 || !show_pid (data->pid)) {
        if (event_fd >= 0)
            close (event_fd);
        return;
    }

    snprintf (printbuf, sizeof (printbuf), "/proc/%i", data->pid);
    int proc_fd = open (printbuf, O_RDONLY | O_DIRECTORY);
    if (proc_fd >= 0) {
        /* get ppid */
        if (option_ancestors) {
            int ppid_fd = openat (proc_fd, "stat", O_RDONLY);
            ssize_t len = read (ppid_fd, statbuf, sizeof (statbuf));
            close (ppid_fd);
            if (len >= 0 && sscanf(statbuf, "%*d (%*[^)]) %*c %d", &ppid) == 1)
                got_ppid = true;
            else
                problems[problem_idx++] = "Could not read /proc/PID/stat, cannot determine any ancestors.";
        }

        /* read process name */
        int procname_fd = openat (proc_fd, "comm", O_RDONLY);
        ssize_t len = read (procname_fd, procname, sizeof (procname));
        if (len >= 0) {
            while (len > 0 && procname[len-1] == '\n')
                len--;
            procname[len] = '\0';
            procname_pid = data->pid;
            got_procname = true;
        } else {
            debug ("failed to read /proc/%i/comm", data->pid);
            problems[problem_idx++] = "Failed to read /proc/PID/comm, cannot determine comm.";
        }

        close (procname_fd);

        /* get user and group */
        if (option_user) {
            if (fstat (proc_fd, &proc_fd_stat) < 0) {
                debug ("failed to stat /proc/%i: %m", data->pid);
                problems[problem_idx++] = "Failed to stat /proc/PID, cannot determine uid or gid.";
            }
        }

        /* get exe */
        if (option_exe) {
            ssize_t len = readlinkat (proc_fd, "exe", exepath, sizeof (exepath));
            if (len >= 0) {
                exepath[len] = '\0';
                got_exepath = true;
            } else {
                debug ("failed to readlink /proc/%i/exe: %m", data->pid);
                problems[problem_idx++] = "Failed to readlink /proc/PID/exe, cannot determine executable path.";
            }
        }

        close (proc_fd);
    } else {
        debug ("failed to open /proc/%i: %m", data->pid);
        problems[problem_idx++] = "Failed to open /proc/PID, cannot read any process metadata.";
    }

    /* /proc/pid/comm often goes away before processing the event; reuse previously cached value if pid still matches */
    if (!got_procname) {
        if (data->pid == procname_pid) {
            debug ("re-using cached procname value %s for pid %i", procname, procname_pid);
            problems[problem_idx++] = "However, cached comm is usable.";
            got_procname = true;
        } else if (data->pid == procname2_pid) {
            debug ("re-using cached procname2 value %s for pid %i", procname2, procname2_pid);
            problems[problem_idx++] = "However, cached comm 2 is usable.";
            procname_pid = procname2_pid;
            memcpy (procname, procname2, sizeof (procname));
            got_procname = true;
        }
    }

    if (option_comm &&
        (got_procname
         ? strcmp (option_comm, procname) != 0
         : !option_inclusive)) {
        if (event_fd >= 0)
            close (event_fd);
        return;
    }

#ifdef FAN_REPORT_FID
    if (fid_mode)
        event_fd = get_fid_event_fd (data);
#endif

    bool got_path = false;
    struct stat st = { .st_uid = -1 };
    if (option_json && fstat (event_fd, &st) < 0)
        problems[problem_idx++] = "Failed to stat event, cannot determine device or inode.";
    if (event_fd >= 0) {
        /* try to figure out the path name */
        snprintf (printbuf, sizeof (printbuf), "/proc/self/fd/%i", event_fd);
        ssize_t len = readlink (printbuf, pathname, sizeof (pathname));
        if (len >= 0) {
            pathname[len] = '\0';
            got_path = true;
        } else if (option_json) {
          // no fallback, device/inode will always be printed
        } else {
            /* fall back to the device/inode */
            if (fstat (event_fd, &st) < 0) {
                pathname[0] = '\0';
                problems[problem_idx++] = "Failed to stat event, cannot determine device or inode.";
            } else {
                snprintf (pathname, sizeof (pathname), "device %i:%i inode %ld\n", major (st.st_dev), minor (st.st_dev), st.st_ino);
            }
        }

        close (event_fd);
    } else {
        snprintf (pathname, sizeof (pathname), "(deleted)");
        problems[problem_idx++] = "Event deleted, cannot determine path.";
    }

    if (dir_watch_mode &&
        (data->mask & FAN_ONDIR) != 0 &&
        (data->mask & (FAN_CREATE |
                       FAN_MOVED_TO |
                       FAN_MOVE_SELF)) != 0) {
        nftw(pathname, mark_cb, 32, FTW_PHYS);
    }

    if (option_dirs_len > 0 &&
        (got_path ? !show_path(pathname) : !option_inclusive)) {
        if (dir_watch_mode && (data->mask & FAN_ONDIR) != 0) {
            nftw(pathname, mark_cb, 32, FTW_PHYS);
        }
        return;
    }

    /* event matches filters, copy procname cache 1 to cache 2 */
    procname2_pid = procname_pid;
    memcpy (procname2, procname, sizeof (procname));

    /* print event */
    if (option_timestamp == 1) {
        strftime (printbuf, sizeof (printbuf), "%H:%M:%S", localtime (&event_time->tv_sec));
        printf (option_json ? "{\"timestamp\":\"%s.%06li\"" : "%s.%06li ", printbuf, event_time->tv_usec);
    } else if (option_timestamp == 2) {
        printf (option_json ? "{\"timestamp\":%li.%06li" : "%li.%06li ", event_time->tv_sec, event_time->tv_usec);
    }

    /* print user and group */
    if (option_user && proc_fd_stat.st_uid != (uid_t)-1)
        snprintf(printbuf, sizeof printbuf,
                 option_json ? ",\"uid\":%u,\"gid\":%u" : " [%u:%u]",
                 proc_fd_stat.st_uid, proc_fd_stat.st_gid);
    else
        printbuf[0] = '\0';

    if (option_json) {
        putchar(option_timestamp ? ',' : '{');
        if (got_procname) {
            if (print_json_str("comm", procname)) {
                problems[problem_idx++] = "comm contains invalid UTF-8, comm_raw contains the bytes.";
            }
            putchar(',');
        }
        printf ("\"pid\":%i%s,\"types\":\"%s\"",
                data->pid, printbuf, mask2str (data->mask));
        if (st.st_uid != (uid_t)-1)
            printf(",\"device\":[%i,%i],\"inode\":%ld"
                   , major (st.st_dev), minor (st.st_dev), st.st_ino);
        if (got_path) {
            putchar(',');
            if (print_json_str("path", pathname)) {
                problems[problem_idx++] = "path contains invalid UTF-8, path_raw contains the bytes.";
            }
        }
        if (option_exe == 1 && got_exepath) {
            putchar(',');
            if (print_json_str("exe", exepath))
                problems[problem_idx++] = "exe contains invalid UTF-8, exe_raw contains the bytes.";
        }
    } else {
        printf ("%s(%i)%s: %-3s %s", got_procname ? procname : "unknown", data->pid, printbuf, mask2str (data->mask), pathname);
        if (option_exe == 1 && got_exepath)
            printf (" exe=%s", exepath);
    }
    if (option_ancestors && got_ppid) {
        printf(option_json ? ",\"ancestors\":" : ", ancestors");
        char sep = option_json ? '[' : '=';
        bool problem_p_comm_not_found = false;
        bool problem_p_comm_raw = false;
        bool problem_exe_not_found = false;
        bool problem_exe_raw = false;
        while (ppid) {
            printf(option_json ? "%c{\"pid\":%i" : "%c(pid=%i", sep, ppid);
            sep = ',';
            snprintf (printbuf, sizeof (printbuf), "/proc/%i", ppid);
            int ppid_dir_fd = open (printbuf, O_RDONLY | O_DIRECTORY);
            if (ppid_dir_fd >= 0) {
                char p_procname[TASK_COMM_LEN];
                int p_procname_fd = openat (ppid_dir_fd, "comm", O_RDONLY);
                ssize_t len = read (p_procname_fd, p_procname, sizeof (p_procname));
                close (p_procname_fd);
                if (len >= 0) {
                    while (len > 0 && p_procname[len-1] == '\n')
                        len--;
                    p_procname[len] = '\0';
                    if (option_json) {
                        putchar(',');
                        if (print_json_str("comm", p_procname)) {
                            if (!problem_p_comm_raw)
                                problems[problem_idx++] = "In an ancestor, comm contains invalid UTF-8, comm_raw contains the bytes.";
                            problem_p_comm_raw = true;
                        }
                    } else
                      printf(" comm=%s", p_procname);
                } else {
                    if (!problem_p_comm_not_found)
                        problems[problem_idx++] = "In an ancestor, failed to read /proc/PPID/comm, cannot determine comm.";
                    problem_p_comm_not_found = true;
                }
                if (option_exe) {
                    ssize_t len = readlinkat (ppid_dir_fd, "exe", exepath, sizeof (exepath));
                    if (len >= 0) {
                        exepath[len] = '\0';
                        if (option_json) {
                            putchar(',');
                            if (print_json_str("exe", exepath)) {
                                if (!problem_exe_raw)
                                    problems[problem_idx++] = "In an ancestor, exe contains invalid UTF-8, exe_raw contains the bytes.";
                                problem_exe_raw = true;
                            }
                        } else
                          printf(" exe=%s", exepath);
                    } else {
                        if (!problem_exe_not_found)
                            problems[problem_idx++] = "In an ancestor, failed to readlink /proc/PPID/exe, cannot determine executable path.";
                        problem_exe_not_found = true;
                    }
                }
                /* get next parent */
                if (ppid == 1)
                    ppid = 0;
                else {
                    int p_stat_fd = openat (ppid_dir_fd, "stat", O_RDONLY);
                    len = read (p_stat_fd, statbuf, sizeof (statbuf));
                    close (p_stat_fd);
                    if (len >= 0) {
                        if (sscanf(statbuf, "%*d (%*[^)]) %*c %d", &ppid) != 1) {
                            problems[problem_idx++] = "In an ancestor, could not parse /proc/PPID/stat, ancestors list is incomplete.";
                            ppid = 0; // stop here
                        }
                    } else {
                        problems[problem_idx++] = "Could not read all /proc/PPID/stat, ancestors list is incomplete.";
                    }
                }
                close (ppid_dir_fd);
            }
            putchar(option_json ? '}' : ')');
        }
        if (option_json) putchar(']');
    }
    if (option_json && problem_idx) {
      for (int i = 0; i < problem_idx; i++) {
        printf("%s%s", i ? "\",\"" : ",\"problems\":[\"", problems[i]);
      }
      printf("\"]");
    }
    printf(option_json ? "}\n" : "\n");
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

    if (dir_watch_mode && !show_path(dir)) {
        res = fanotify_mark (fan_fd, FAN_MARK_REMOVE, 0, AT_FDCWD, dir);
        if (res < 0)
        {
            if (fatal)
                err (EXIT_FAILURE, "Failed to remove watch for %s", dir);
            else
                warn ("Failed to remove watch for %s", dir);
        }
        return;
    }

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

/* helpers for marking directories */
#define DIR_MARK_LIMIT 4096
static int count_cb_dir_count = 0; // global var used to pass an argument.
static int count_cb(const char *, const struct stat*, int typeflag, struct FTW*)
{
    if (typeflag == FTW_D) count_cb_dir_count++;
    if (count_cb_dir_count > DIR_MARK_LIMIT) return 1;
    return 0;
}
static int mark_cb_fanfd = 0; // global var used to pass an argument.
static int mark_cb(const char *fpath, const struct stat*, int typeflag,
                   struct FTW*)
{
  if (typeflag == FTW_D) {
      do_mark (mark_cb_fanfd, fpath, false);
  }
  return 0;
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
    count_cb_dir_count = 0;
    if (option_dirs_len > 0) {
        for (unsigned i = 0; i < option_dirs_len; i++) {
            nftw(option_dirs[i], count_cb, 32, FTW_PHYS);
            if (count_cb_dir_count > DIR_MARK_LIMIT) break;
        }
        if (count_cb_dir_count <= DIR_MARK_LIMIT) {
            dir_watch_mode = 1;
            mark_mode = FAN_MARK_ADD;
            mark_cb_fanfd = fan_fd;
            for (unsigned i = 0; i < option_dirs_len; i++) {
                nftw(option_dirs[i], mark_cb, 32, FTW_PHYS);
            }
            return;
        } else {
            warnx ("Directories are too many to watch separately. Watching all"
                   " files instead.");
        }
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
    puts ("Usage: fatrace [options...] \n"
"\n"
"Options:\n"
"  -c, --current-mount\t\tOnly record events on partition/mount of current directory.\n"
"  -o FILE, --output=FILE\tWrite events to a file instead of standard output.\n"
"  -s SECONDS, --seconds=SECONDS\tStop after the given number of seconds.\n"
"  -t, --timestamp\t\tAdd timestamp to events. Give twice for seconds since the epoch.\n"
"  -u, --user\t\t\tAdd user ID and group ID to events.\n"
"  -p PID, --ignore-pid PID\tIgnore events for this process ID. Can be specified multiple times.\n"
"  -f TYPES, --filter=TYPES\tShow only the given event types; choose from C, R, O, W, +, D, < or >, e. g. --filter=OC.\n"
"  -C COMM, --command=COMM\tShow only events for this command.\n"
"  -j, --json\t\t\tWrite events in JSONL format.\n"
"  -i, --inclusive\t\tInclude events where missing data makes filtering ambiguous.\n"
"  -a, --ancestors\t\tInclude information about parent processes.\n"
"  -e, --exe\t\t\tAdd executable path to events.\n"
"  -d, --dir\t\t\tShow only events on files under this directory. Can be specified multiple times.\n"
"  -h, --help\t\t\tShow help.");
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
        {"inclusive",     no_argument,       0, 'i'},
        {"ancestors",     no_argument,       0, 'a'},
        {"exe",           no_argument,       0, 'e'},
        {"dir",           no_argument,       0, 'd'},
        {"help",          no_argument,       0, 'h'},
        {0,               0,                 0,  0 }
    };

    while (1) {
        c = getopt_long (argc, argv, "C:co:s:tup:f:jiaed:h", long_options, NULL);

        if (c == -1)
            break;

        switch (c) {
            case 'C':
                option_comm = strdup (optarg);
                /* see https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html */
                if (strlen (option_comm) > TASK_COMM_LEN - 1) {
                    option_comm[TASK_COMM_LEN - 1] = '\0';
                    warnx ("--command truncated to %i characters: %s", TASK_COMM_LEN - 1, option_comm);
                }
                break;

            case 'c':
                option_current_mount = 1;
                break;

            case 'o':
                option_output = strdup (optarg);
                break;

            case 'u':
                option_user = 1;
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
                if (++option_timestamp > 2)
                    errx (EXIT_FAILURE, "Error: --timestamp option can be given at most two times");
                break;

            case 'j':
                option_json = 1;
                break;

            case 'i':
                option_inclusive = 1;
                break;

            case 'a':
                option_ancestors = 1;
                break;

            case 'e':
                option_exe = 1;
                break;

            case 'd':
                if (option_dirs_len
                    < (sizeof (option_dirs) / sizeof (option_dirs[0]))) {
                    const char* path = optarg;
                    int plen = strlen(path);
                    if (plen == 0)
                        errx (EXIT_FAILURE, "Error: Empty dir given");
                    if (plen >= PATH_MAX)
                        errx (EXIT_FAILURE, "Error: Dir too long: %s", path);
                    if (path[0] != '/')
                        errx (EXIT_FAILURE, "Error: Dir must be absolute: %s",
                              path);
                    if (plen == 1)
                        errx (EXIT_FAILURE,
                              "Error: Dir must not be filesystem root. To"
                              " include all dirs, instead remove all -d,--dir"
                              " options.");
                    if (path[plen - 1] == '/')
                        errx (EXIT_FAILURE,
                              "Error: Dir must not end with a slash: %s", path);
                    for (int i = 0; i < plen - 1; i++)
                        if (path[i] == '/' && path[i + 1] == '/')
                            errx (EXIT_FAILURE,
                                  "Error: Dir must not contain double slashes:"
                                  " %s", path);
                    // Check that dir exists
                    int path_fd = open (path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
                    if (path_fd < 0) {
                        err (EXIT_FAILURE, "Error: Cannot open dir %s", path);
                    }
                    close (path_fd);
                    option_dirs[option_dirs_len] = path;
                    option_dir_lens[option_dirs_len] = plen;
                    option_dirs_len++;
                }
                else
                    errx (EXIT_FAILURE, "Error: Too many dirs");
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

int
main (int argc, char** argv)
{
    int fan_fd = -1;
    int res;
    void *buffer;
    struct fanotify_event_metadata *data;
    struct sigaction sa;
    struct timeval event_time;

    /* always ignore events from ourselves (writing log file) */
    ignored_pids[ignored_pids_len++] = getpid ();

    parse_args (argc, argv);

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
            print_event (data, &event_time);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
}
