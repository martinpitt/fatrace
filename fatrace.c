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
static bool option_current_mount = false;
static int option_timestamp = 0;
static bool option_user = false;
static pid_t ignored_pids[1024];
static unsigned int ignored_pids_len = 0;
static char* option_comm = NULL;
static bool option_json = false;
static bool option_parents = false;
static bool option_exe = false;

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

static void
print_json_str (const char* key, const char* value) {
    int value_len = nonfunny_utf8_len (value);
    int key_len = strlen(key);
    if (value_len >= 0) {
        putchar('"');
        fwrite (key, 1, key_len, stdout);
        putchar('"');
        putchar(':');
        putchar('"');
        fwrite (value, 1, value_len, stdout);
        putchar ('"');
    } else {
        putchar('"');
        fwrite (key, 1, key_len, stdout);
        fwrite ("_raw\":[", 1, 7, stdout);
        for (int i = 0; value[i] != 0; i++)
            printf (i ? ",%d" : "%d", (unsigned int)(unsigned char)(value[i]));
        putchar (']');
    }
}

/* given an fd to /proc/PID and a buffer of size TASK_COMM_LEN, try to read the
   process name. Return true on success. */
static bool
get_procname (int proc_fd, char *procname, size_t procname_size) {
    int fd = openat (proc_fd, "comm", O_RDONLY);
    ssize_t len = read (fd, procname, procname_size - 1);
    close (fd);
    if (len >= 0) {
        while (len > 0 && procname[len-1] == '\n')
            len--;
        procname[len] = '\0';
        return true;
    }
    debug ("failed to read /proc/PID/comm");
    return false;
}

/* given an fd to /proc/PID, return the parent PID if it can be determined,
   otherwise 0. */
static pid_t
get_ppid (int proc_fd) {
    static char statbuf[4096];
    int stat_fd = openat (proc_fd, "stat", O_RDONLY);
    ssize_t len = read (stat_fd, statbuf, sizeof (statbuf));
    close (stat_fd);
    pid_t ret;
    if (len >= 0 && sscanf(statbuf, "%*d (%*[^)]) %*c %d", &ret) == 1)
        return ret;
    return 0;
}

/**
 * print_event:
 *
 * Print data from fanotify_event_metadata struct to stdout.
 */
static void
print_event (const struct fanotify_event_metadata *data,
             const struct timeval *event_time)
{
    int event_fd = data->fd;
    static char printbuf[100];
    static char procname[TASK_COMM_LEN];
    static int procname_pid = -1;
    static char pathname[PATH_MAX];
    bool got_procname = false;
    static char exepath[PATH_MAX];
    bool got_exepath = false;
    struct stat proc_fd_stat = { .st_uid = -1 };
    int ppid = 0;

    if ((data->mask & option_filter_mask) == 0 || !show_pid (data->pid)) {
        if (event_fd >= 0)
            close (event_fd);
        return;
    }

    snprintf (printbuf, sizeof (printbuf), "/proc/%i", data->pid);
    int proc_fd = open (printbuf, O_RDONLY | O_DIRECTORY);
    if (proc_fd >= 0) {
        /* get ppid */
        if (option_parents)
            ppid = get_ppid (proc_fd);

        /* read process name */
        if (get_procname (proc_fd, procname, sizeof (procname))) {
            procname_pid = data->pid;
            got_procname = true;
        }

        /* get user and group */
        if (option_user) {
            if (fstat (proc_fd, &proc_fd_stat) < 0)
                debug ("failed to stat /proc/%i: %m", data->pid);
        }

        /* get exe */
        if (option_exe) {
            ssize_t len = readlinkat (proc_fd, "exe", exepath, sizeof (exepath));
            if (len >= 0) {
                exepath[len] = '\0';
                got_exepath = true;
            } else {
                debug ("failed to readlink /proc/%i/exe: %m", data->pid);
            }
        }

        close (proc_fd);
    } else {
        debug ("failed to open /proc/%i: %m", data->pid);
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
        return;
    }

#ifdef FAN_REPORT_FID
    if (fid_mode)
        event_fd = get_fid_event_fd (data);
#endif

    bool got_path = false;
    struct stat st = { .st_uid = -1 };
    if (event_fd >= 0) {
        if (option_json && fstat (event_fd, &st) < 0)
            warn ("stat");
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
                warn ("stat");
                pathname[0] = '\0';
            } else {
                snprintf (pathname, sizeof (pathname), "device %i:%i inode %ld\n", major (st.st_dev), minor (st.st_dev), st.st_ino);
            }
        }

        close (event_fd);
    } else {
        snprintf (pathname, sizeof (pathname), "(deleted)");
    }

    if (option_json)
        putchar('{');

    /* print event */
    if (option_timestamp == 1) {
        strftime (printbuf, sizeof (printbuf), "%H:%M:%S", localtime (&event_time->tv_sec));
        printf (option_json ? "\"timestamp\":\"%s.%06li\"," : "%s.%06li ", printbuf, event_time->tv_usec);
    } else if (option_timestamp == 2) {
        printf (option_json ? "\"timestamp\":%li.%06li," : "%li.%06li ", event_time->tv_sec, event_time->tv_usec);
    }

    /* print user and group */
    if (option_user && proc_fd_stat.st_uid != (uid_t)-1)
        snprintf(printbuf, sizeof printbuf,
                 option_json ? "\"uid\":%u,\"gid\":%u," : " [%u:%u]",
                 proc_fd_stat.st_uid, proc_fd_stat.st_gid);
    else
        printbuf[0] = '\0';

    if (option_json) {
        if (procname_pid >= 0) {
            print_json_str("comm", procname);
            putchar(',');
        }
        printf ("\"pid\":%i,%s\"types\":\"%s\"",
                data->pid, printbuf, mask2str (data->mask));
        if (st.st_uid != (uid_t)-1)
            printf(",\"device\":{\"major\":%i,\"minor\":%i},\"inode\":%ld"
                   , major (st.st_dev), minor (st.st_dev), st.st_ino);
        if (got_path) {
            putchar(',');
            print_json_str("path", pathname);
        }
        if (option_exe && got_exepath) {
            putchar(',');
            print_json_str("exe", exepath);
        }
    } else {
        printf ("%s(%i)%s: %-3s %s", procname[0] == '\0' ? "unknown" : procname, data->pid, printbuf, mask2str (data->mask), pathname);
        if (option_exe && got_exepath)
            printf (" exe=%s", exepath);
    }
    if (option_parents && ppid) {
        printf(option_json ? ",\"parents\":" : ", parents");
        char sep = option_json ? '[' : '=';
        do {
            printf(option_json ? "%c{\"pid\":%i" : "%c(pid=%i", sep, ppid);
            sep = ',';
            snprintf (printbuf, sizeof (printbuf), "/proc/%i", ppid);
            int ppid_dir_fd = open (printbuf, O_RDONLY | O_DIRECTORY);
            if (ppid_dir_fd >= 0) {
                char p_procname[TASK_COMM_LEN];
                if (get_procname (ppid_dir_fd, p_procname, sizeof (p_procname))) {
                    if (option_json) {
                        putchar(',');
                        print_json_str("comm", p_procname);
                    } else
                      printf(" comm=%s", p_procname);
                }
                if (option_exe) {
                    ssize_t len = readlinkat (ppid_dir_fd, "exe", exepath, sizeof (exepath) - 1);
                    if (len >= 0) {
                        exepath[len] = '\0';
                        if (option_json) {
                            putchar(',');
                            print_json_str("exe", exepath);
                        } else
                          printf(" exe=%s", exepath);
                    }
                }
                /* get next parent */
                if (ppid == 1)
                    ppid = 0;
                else
                    ppid = get_ppid (ppid_dir_fd);
                close (ppid_dir_fd);
            } else {
                ppid = 0;
            }
            putchar(option_json ? '}' : ')');
        } while (ppid > 0);
        if (option_json)
            putchar(']');
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
"  -P, --parents\t\tInclude information about all parent processes.\n"
"  -e, --exe\t\t\tAdd executable path to events.\n"
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
        {"parents",       no_argument,       0, 'P'},
        {"exe",           no_argument,       0, 'e'},
        {"help",          no_argument,       0, 'h'},
        {0,               0,                 0,  0 }
    };

    while (1) {
        c = getopt_long (argc, argv, "C:co:s:tup:f:jPeh", long_options, NULL);

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
                        case '>':
                            option_filter_mask |= FAN_MOVE;
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
                option_json = true;
                break;

            case 'P':
                option_parents = true;
                break;

            case 'e':
                option_exe = true;
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
