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
#include <sys/fanotify.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <ctype.h>

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
static int option_current_mount = 0;
static int option_timestamp = 0;
static pid_t ignored_pids[1024];
static unsigned int ignored_pids_len = 0;
static char* option_comm = NULL;

/* --time alarm sets this to 0 */
static volatile int running = 1;
static volatile int signaled = 0;

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
    buffer[offset] = '\0';

    return buffer;
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
    int proc_fd;
    ssize_t len;
    static char printbuf[100];
    static char procname[100];
    static char pathname[PATH_MAX];
    struct stat st;

    if ((data->mask & option_filter_mask) == 0)
        return;

    /* read process name */
    snprintf (printbuf, sizeof (printbuf), "/proc/%i/comm", data->pid);
    len = 0;
    proc_fd = open (printbuf, O_RDONLY);
    if (proc_fd >= 0) {
        len = read (proc_fd, procname, sizeof (procname));
        while (len > 0 && procname[len-1] == '\n') {
            len--;
        }
    }
    if (len > 0)
        procname[len] = '\0';
    else
        strcpy (procname, "unknown");
    if (proc_fd >= 0)
        close (proc_fd);

    if (option_comm && strcmp (option_comm, procname) != 0)
        return;

    /* try to figure out the path name */
    snprintf (printbuf, sizeof (printbuf), "/proc/self/fd/%i", data->fd);
    len = readlink (printbuf, pathname, sizeof (pathname));
    if (len < 0) {
        /* fall back to the device/inode */
        if (fstat (data->fd, &st) < 0)
            err (EXIT_FAILURE, "stat");
        snprintf (pathname, sizeof (pathname), "device %i:%i inode %ld\n", major (st.st_dev), minor (st.st_dev), st.st_ino);
    } else {
        pathname[len] = '\0';
    }

    /* print event */
    if (option_timestamp == 1) {
        strftime (printbuf, sizeof (printbuf), "%H:%M:%S", localtime (&event_time->tv_sec));
        printf ("%s.%06li ", printbuf, event_time->tv_usec);
    } else if (option_timestamp == 2) {
        printf ("%li.%06li ", event_time->tv_sec, event_time->tv_usec);
    }
    printf ("%s(%i): %s %s\n", procname, data->pid, mask2str (data->mask), pathname);
}

static void
do_mark (int fan_fd, const char *dir, bool fatal)
{
    int res;

    res = fanotify_mark (
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_CLOSE |  FAN_ONDIR | FAN_EVENT_ON_CHILD,
            AT_FDCWD, dir);

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

    /* iterate over all mounts */
    mounts = setmntent ("/proc/self/mounts", "r");
    if (mounts == NULL)
        err (EXIT_FAILURE, "setmntent");

    while ((mount = getmntent (mounts)) != NULL) {
        /* Only consider mounts which have an actual device or bind mount
         * point. The others are stuff like proc, sysfs, binfmt_misc etc. which
         * are virtual and do not actually cause disk access. */
        if (mount->mnt_fsname == NULL || access (mount->mnt_fsname, F_OK) != 0 ||
            mount->mnt_fsname[0] != '/') {
            debug ("ignore: fsname: %s dir: %s type: %s", mount->mnt_fsname, mount->mnt_dir, mount->mnt_type);
            continue;
        }

        debug ("add watch for %s mount %s", mount->mnt_type, mount->mnt_dir);
        do_mark (fan_fd, mount->mnt_dir, false);
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
"  -p PID, --ignore-pid PID\tIgnore events for this process ID. Can be specified multiple times.\n"
"  -f TYPES, --filter=TYPES\tShow only the given event types; choose from C, R, O, or W, e. g. --filter=OC.\n"
"  -C COMM, --command=COMM\tShow only events for this command.\n"
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
        {"ignore-pid",    required_argument, 0, 'p'},
        {"filter",        required_argument, 0, 'f'},
        {"command",       required_argument, 0, 'C'},
        {"help",          no_argument,       0, 'h'},
        {0,               0,                 0,  0 }
    };

    while (1) {
        c = getopt_long (argc, argv, "C:co:s:tp:f:h", long_options, NULL);

        if (c == -1)
            break;

        switch (c) {
            case 'C':
                option_comm = strdup (optarg);
                break;

            case 'c':
                option_current_mount = 1;
                break;

            case 'o':
                option_output = strdup (optarg);
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
                if (ignored_pids_len < sizeof (ignored_pids))
                    ignored_pids[ignored_pids_len++] = pid;
                else
                    errx (EXIT_FAILURE, "Error: Too many ignored PIDs");
                break;

            case 't':
                if (++option_timestamp > 2)
                    errx (EXIT_FAILURE, "Error: --timestamp option can be given at most two times");
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

/**
 * show_pid:
 *
 * Check if events for given PID should be logged.
 *
 * Returns: 1 if PID is to be logged, 0 if not.
 */
static int
show_pid (pid_t pid)
{
    unsigned int i;
    for (i = 0; i < ignored_pids_len; ++i)
        if (pid == ignored_pids[i])
            return 0;

    return 1;
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

    /* always ignore events from ourselves (writing log file) */
    ignored_pids[ignored_pids_len++] = getpid ();

    parse_args (argc, argv);

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
            errx (EXIT_FAILURE, "read");
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
            if (show_pid (data->pid))
                print_event (data, &event_time);
            close (data->fd);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
}

