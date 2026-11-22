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

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <mntent.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/fanotify.h>
/* for MIN() */
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/types.h>

#include "event.h"

#define BUFSIZE 256*1024

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
static enum fatrace_timestamp option_timestamp = TIMESTAMP_NONE;
static bool option_user = false;
/* both get allocated for the maximum possible number of arguments */
static pid_t *ignored_pids;
static unsigned int ignored_pids_len = 0;
static char* option_comm = NULL;
static bool option_json = false;
static bool option_parents = false;
static bool option_exe = false;
static const char **option_dirs;
static unsigned int option_dirs_len = 0;

/* SIGINT and the --seconds alarm set this to 0 */
static volatile int running = 1;
static volatile int signaled = 0;

static int mark_mode = FAN_MARK_ADD | FAN_MARK_FILESYSTEM;

/* fsid → mount point map, for resolving file handles. Mount points only get opened while handling an event,
 * so that fatrace does not keep the file systems busy. */

static struct {
    fsid_t fsid;
    dev_t dev;                  /* of the watched path, to notice different file systems with the same fsid */
    char *mount_point;
    dev_t mount_dev;            /* to notice when mount_point got unmounted or mounted over */
} *fsids;
static size_t fsids_len;

/* return the fsids[] index for an fsid, or -1 if unknown */
static ssize_t
find_fsid (const fsid_t *fsid)
{
    for (size_t i = 0; i < fsids_len; ++i)
        if (memcmp (fsid, &fsids[i].fsid, sizeof (fsids[i].fsid)) == 0)
            return i;

    debug ("fsid not found");
    return -1;
}

/* return the mount point of an open file with the given absolute and canonical path, or NULL on failure */
static char *
get_mount_point (int fd, const char *path)
{
    struct statx stx;
    char parent[PATH_MAX];
    char *mount_point;
    uint64_t mnt_id;

    if (statx (fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &stx) < 0)
        return NULL;
    mnt_id = stx.stx_mnt_id;

    mount_point = strdup (path);
    if (!mount_point)
        err (EXIT_FAILURE, "strdup");

    /* walk up until the parent is on a different mount */
    while (strcmp (mount_point, "/") != 0) {
        strcpy (parent, mount_point);
        char *slash = strrchr (parent, '/');
        slash[slash == parent ? 1 : 0] = '\0';
        if (statx (AT_FDCWD, parent, AT_SYMLINK_NOFOLLOW, STATX_MNT_ID, &stx) < 0 || stx.stx_mnt_id != mnt_id)
            break;
        strcpy (mount_point, parent);
    }

    return mount_point;
}

/**
 * add_fsid:
 *
 * Add fsid → mount point map entry for the file system of a watched directory, unless it is already known.
 * @path must be absolute and canonical.
 */
static void
add_fsid (int fd, const char* path)
{
    struct statfs s;
    struct stat st, mount_st;
    char *mount_point;
    ssize_t i;

    if (fstatfs (fd, &s) < 0 || fstat (fd, &st) < 0) {
        warn ("Failed to stat %s, not resolving its paths", path);
        return;
    }

    i = find_fsid (&s.f_fsid);
    if (i >= 0) {
        /* e. g. a copy of an ext4 file system image, which has the same UUID; events only carry the fsid, so
         * file handles get resolved on the first one */
        if (st.st_dev != fsids[i].dev)
            warnx ("%s has the same file system ID as %s, its paths may be reported below the latter",
                   path, fsids[i].mount_point);
        /* otherwise e. g. bind mounts; keep the first one, as in the default mode the root dir comes first */
        return;
    }

    mount_point = get_mount_point (fd, path);
    if (!mount_point || stat (mount_point, &mount_st) < 0) {
        warn ("Failed to find mount point of %s, not resolving its paths", path);
        free (mount_point);
        return;
    }

    /* only called at startup, so growing one by one is fine */
    fsids = reallocarray (fsids, fsids_len + 1, sizeof (*fsids));
    if (!fsids)
        err (EXIT_FAILURE, "Failed to allocate fsid map");

    memcpy (&fsids[fsids_len].fsid, &s.f_fsid, sizeof (s.f_fsid));
    fsids[fsids_len].dev = st.st_dev;
    fsids[fsids_len].mount_point = mount_point;
    fsids[fsids_len++].mount_dev = mount_st.st_dev;
    debug ("%s: mount point %s", path, mount_point);
}

/* return an fd for open_by_handle_at() on the file system with the given fsid, or -1 if that is not possible */
static int
open_mount (const fsid_t *fsid)
{
    ssize_t i = find_fsid (fsid);
    struct stat st;
    int fd;

    /* add_fsid() failed and already warned; decoding the handle relative to another file system would fail or
     * open an unrelated file */
    if (i < 0)
        return -1;

    fd = open (fsids[i].mount_point, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return -1;
    if (fstat (fd, &st) < 0 || st.st_dev != fsids[i].mount_dev) {
        close (fd);
        return -1;
    }
    return fd;
}

/* readlink() an fd's path; "" on failure */
static void
get_fd_path (int fd, char *path, size_t path_size)
{
    char procpath[32];
    snprintf (procpath, sizeof (procpath), "/proc/self/fd/%i", fd);
    ssize_t len = readlink (procpath, path, path_size - 1);
    path[len >= 0 ? len : 0] = '\0';
}

/* return an fd for the file handle of a fanotify info record */
static int
open_fid (int mount_fd, const struct fanotify_event_info_fid *fid)
{
    int fd = open_by_handle_at (mount_fd, (struct file_handle *) fid->handle,
                                O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_PATH);
    /* ignore ESTALE for deleted fds between the notification and handling it */
    if (fd < 0 && errno != ESTALE)
        warn ("open_by_handle_at");

    return fd;
}

/**
 * get_fid_event_fd:
 *
 * Return an fd for the event's target, or -1 if it cannot be opened.
 *
 * Events on a non-directory and directory entry events (create, delete, move) also identify the parent
 * directory and the name of the target. Then write that into @path: the target fd's path is ambiguous with
 * hard links, as open_by_handle_at() picks an arbitrary one, and the target may have vanished already.
 * Otherwise, set @path to "".
 */
static int
get_fid_event_fd (const struct fanotify_event_metadata *data, char *path, size_t path_size)
{
    const struct fanotify_event_info_fid *object = NULL, *dir = NULL;
    const char *name = NULL;
    int mount_fd, fd;

    path[0] = '\0';

    /* the kernel does not guarantee the order of info records */
    for (const char *p = (const char *) data + data->metadata_len; p < (const char *) data + data->event_len; ) {
        const struct fanotify_event_info_fid *info = (const struct fanotify_event_info_fid *) p;
        p += info->hdr.len;

        switch (info->hdr.info_type) {
            case FAN_EVENT_INFO_TYPE_FID:
                object = info;
                break;
            case FAN_EVENT_INFO_TYPE_DFID_NAME: {
                const struct file_handle *handle = (const struct file_handle *) info->handle;
                dir = info;
                name = (const char *) handle->f_handle + handle->handle_bytes;
                break;
            }
            default:
                warnx ("Ignoring unexpected event info type %i", info->hdr.info_type);
        }
    }

    /* Events on a directory itself only have a DFID_NAME record with the name "."; report the directory.
     * Unlinked files only have a FID record. */
    if (!object && dir && strcmp (name, ".") == 0) {
        object = dir;
        dir = NULL;
    }
    if (!object && !dir) {
        warnx ("Received event without file handle, cannot get affected file");
        return -1;
    }

    /* both records are on the same file system */
    mount_fd = open_mount ((const fsid_t *) &(object ? object : dir)->fsid);
    if (mount_fd < 0)
        return -1;

    fd = object ? open_fid (mount_fd, object) : -1;

    /* directories cannot be hard linked, so their path is unique */
    if (dir) {
        int dir_fd = open_fid (mount_fd, dir);
        if (dir_fd >= 0) {
            get_fd_path (dir_fd, path, path_size);
            close (dir_fd);
            size_t len = strlen (path);
            if (len > 0)
                snprintf (path + len, path_size - len, "%s%s", path[len - 1] == '/' ? "" : "/", name);
        }
    }

    close (mount_fd);
    return fd;
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
    while (len > 0 && procname[len-1] == '\n')
        len--;
    procname[len] = '\0';
    return true;
}

/* given an fd to /proc/PID, return the parent PID if it can be determined,
   otherwise 0. */
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

    pid_t ret;
    if (sscanf(statbuf, "%*d (%*[^)]) %*c %d", &ret) == 1)
        return ret;
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
    int event_fd;
    static char procpath[100];
    static char procname[TASK_COMM_LEN];
    static int procname_pid = -1;
    bool got_procname = false;
    pid_t ppid = 0;

    if ((data->mask & option_filter_mask) == 0 || !show_pid (data->pid))
        return false;

    /* parents[] is the bulk of the struct and only valid up to parents_len */
    memset (ev, 0, offsetof (struct fatrace_event, parents));
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
        procname[0] != '\0')
        return false;
    memcpy (ev->proc.comm, procname, sizeof (procname));

    event_fd = get_fid_event_fd (data, ev->path, sizeof (ev->path));
    if (event_fd >= 0) {
        struct stat st;

        if (fstat (event_fd, &st) < 0) {
            warn ("stat");
        } else {
            ev->have_stat = true;
            ev->dev = st.st_dev;
            ev->ino = st.st_ino;
        }

        if (!ev->path[0])
            get_fd_path (event_fd, ev->path, sizeof (ev->path));

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

/* add a watch for a directory or its mount, depending on mark_mode, and register its file system for
 * resolving paths; @dir must be absolute and canonical; return whether adding the watch succeeded */
static bool
do_mark (int fan_fd, const char *dir)
{
    uint64_t mask = FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD |
                    FAN_CREATE | FAN_DELETE | FAN_MOVE;
    bool success = false;

    /* look up the path only once, so that the watch and the registration are on the same file system */
    int fd = open (dir, O_RDONLY | O_DIRECTORY);
    if (fd >= 0 && fanotify_mark (fan_fd, mark_mode, mask, fd, NULL) == 0) {
        add_fsid (fd, dir);
        success = true;
    } else {
        warn ("Failed to add watch for %s", dir);
    }

    if (fd >= 0)
        close (fd);
    return success;
}

/**
 * setup_fanotify:
 *
 * @fan_fd: fanotify file descriptor as returned by fanotify_init().
 *
 * Set up fanotify watches on all mount points, or on the current directory
 * mount if --current-mount is given.
 *
 * Returns: true if at least one watch was added.
 */
static bool
setup_fanotify (int fan_fd)
{
    bool watched = false;

    if (option_dirs_len > 0) {
        mark_mode = FAN_MARK_ADD;
        char resolved[PATH_MAX];
        struct stat st;
        for (unsigned i = 0; i < option_dirs_len; i++) {
            if (realpath(option_dirs[i], resolved) &&
                stat(resolved, &st) == 0) {
                if (S_ISDIR(st.st_mode))
                    watched |= do_mark (fan_fd, resolved);
                else
                    errx(EXIT_FAILURE,
                         "Not a directory: %s", option_dirs[i]);
            }
            else
                err(EXIT_FAILURE,
                    "Cannot resolve directory: %s", option_dirs[i]);
        }
        return watched;
    }

    FILE* mounts;
    struct mntent* mount;
    struct stat st;

    if (option_current_mount) {
        char cwd[PATH_MAX];
        if (!getcwd (cwd, sizeof (cwd)))
            err (EXIT_FAILURE, "getcwd");
        return do_mark (fan_fd, cwd);
    }

    /* iterate over all mounts; explicitly start with the root dir, to get
     * the shortest possible paths on fsid resolution on e. g. OSTree */
    watched = do_mark (fan_fd, "/");

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

        /* files mounted over files: their file system usually is watched through another mount, and opening
         * them could block (FIFOs) or have side effects (devices) */
        if (stat (mount->mnt_dir, &st) < 0 || !S_ISDIR (st.st_mode)) {
            debug ("ignore non-directory mount %s", mount->mnt_dir);
            continue;
        }

        debug ("add watch for %s mount %s", mount->mnt_type, mount->mnt_dir);
        watched |= do_mark (fan_fd, mount->mnt_dir);
    }

    endmntent (mounts);
    return watched;
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
"  -c, --current-mount           Only record events on the file system of the\n"
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

    /* each argument is at most one PID or directory, plus our own PID */
    ignored_pids = calloc (argc + 1, sizeof (*ignored_pids));
    option_dirs = calloc (argc, sizeof (*option_dirs));
    if (!ignored_pids || !option_dirs)
        err (EXIT_FAILURE, "Failed to allocate argument arrays");

    /* always ignore events from ourselves (writing log file) */
    ignored_pids[ignored_pids_len++] = getpid ();

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
                ignored_pids[ignored_pids_len++] = pid;
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
    for (int i = optind; i < argc; i++)
        option_dirs[option_dirs_len++] = argv[i];
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
    int fan_fd;
    int res;
    void *buffer;
    struct fanotify_event_metadata *data;
    struct sigaction sa;
    struct timeval event_time;
    static struct fatrace_event event;
    void (*format_event) (FILE *, const struct fatrace_event *, enum fatrace_timestamp);

    parse_args (argc, argv);
    format_event = option_json ? format_fatrace_event_json : format_fatrace_event_text;

    /* Unprivileged users can initialize fanotify with file handles, but then the kernel only allows
     * --dir watches, hides the pid of other processes, and open_by_handle_at() fails. Requesting the
     * admin-only FAN_UNLIMITED_MARKS makes fanotify_init() fail without privileges. */
    fan_fd = fanotify_init (FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME_TARGET | FAN_UNLIMITED_MARKS, O_LARGEFILE);
    if (fan_fd < 0) {
        if (errno == EINVAL)
            errx (EXIT_FAILURE,
                  "Cannot initialize fanotify: fatrace requires Linux 5.17, 5.15.154, 5.10.220, or newer");
        err (EXIT_FAILURE, "Cannot initialize fanotify");
    }

    if (!setup_fanotify (fan_fd))
        errx (EXIT_FAILURE, "Could not add any watch");

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

    /* set up --seconds alarm */
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
            /* the kernel queues this once its event queue is full; it has no process or file */
            if (data->mask & FAN_Q_OVERFLOW)
                warnx ("Event queue overflowed, some events were lost");
            else if (process_event (data, &event_time, &event))
                format_event (stdout, &event, option_timestamp);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
}
