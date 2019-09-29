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
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <mntent.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <ctype.h>

#define BUFSIZE 256*1024

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
print_event(const struct fanotify_event_metadata *data,
            const struct timeval *event_time)
{
    int fd;
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
    fd = open (printbuf, O_RDONLY);
    if (fd >= 0) {
        len = read (fd, procname, sizeof (procname));
        while (len > 0 && procname[len-1] == '\n') {
            len--;
        }
    }
    if (len > 0) {
	procname[len] = '\0';
    } else {
        strcpy (procname, "unknown");
    }
    if (fd >= 0)
	close (fd);

    if (option_comm && strcmp (option_comm, procname) != 0)
        return;

    /* try to figure out the path name */
    snprintf (printbuf, sizeof (printbuf), "/proc/self/fd/%i", data->fd);
    len = readlink (printbuf, pathname, sizeof (pathname));
    if (len < 0) {
        /* fall back to the device/inode */
        if (fstat (data->fd, &st) < 0) {
            perror ("stat");
            exit (1);
        }
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

/**
 * fanotify_mark_mounts:
 *
 * @fan_fd: fanotify file descriptor as returned by fanotify_init().
 *
 * Set up fanotify watches on all mount points, or on the current directory
 * mount if --current-mount is given.
 */
static void
setup_fanotify(int fan_fd)
{
    int res;
    FILE* mounts;
    struct mntent* mount;

    if (option_current_mount) {
        res = fanotify_mark (fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE |  FAN_ONDIR | FAN_EVENT_ON_CHILD,
                AT_FDCWD, ".");
        if (res < 0) {
            fprintf(stderr, "Failed to add watch for current directory: %s\n", strerror (errno));
            exit (1);
        }

        return;
    }

    /* iterate over all mounts */
    mounts = setmntent ("/proc/self/mounts", "r");
    if (mounts == NULL) {
        perror ("setmntent");
        exit (1);
    }

    while ((mount = getmntent (mounts)) != NULL) {
        /* Only consider mounts which have an actual device or bind mount
         * point. The others are stuff like proc, sysfs, binfmt_misc etc. which
         * are virtual and do not actually cause disk access. */
        if (mount->mnt_fsname == NULL || access (mount->mnt_fsname, F_OK) != 0 ||
            strchr(mount->mnt_fsname, '/') == NULL) {
            //printf("IGNORE: fsname: %s dir: %s type: %s\n", mount->mnt_fsname, mount->mnt_dir, mount->mnt_type);
            continue;
        }

        //printf("Adding watch for %s mount %s\n", mount->mnt_type, mount->mnt_dir);
        res = fanotify_mark (fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD,
                AT_FDCWD, mount->mnt_dir);
        if (res < 0) {
            fprintf(stderr, "Failed to add watch for %s mount %s: %s\n",
                    mount->mnt_type, mount->mnt_dir, strerror (errno));
        }
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
                            fprintf (stderr, "Error: Unknown --filter type '%c'\n", optarg[j]);
                            exit (1);
                    }
                    j++;
                }
                break;

            case 's':
                option_timeout = strtol (optarg, &endptr, 10);
                if (*endptr != '\0' || option_timeout <= 0) {
                    fputs ("Error: Invalid number of seconds\n", stderr);
                    exit (1);
                }
                break;

            case 'p':
                pid = strtol (optarg, &endptr, 10);
                if (*endptr != '\0' || pid <= 0) {
                    fputs ("Error: Invalid PID\n", stderr);
                    exit (1);
                }
                if (ignored_pids_len < sizeof (ignored_pids))
                    ignored_pids[ignored_pids_len++] = pid;
                else {
                    fputs ("Error: Too many ignored PIDs\n", stderr);
                    exit (1);
                }
                break;

            case 't':
                if (++option_timestamp > 2) {
                    fputs ("Error: --timestamp option can be given at most two times\n", stderr);
                    exit (1);
                };
                break;

            case 'h':
                help ();
                exit (0);

            case '?':
                /* getopt_long() already prints error message */
                exit (1);

            default:
                fprintf (stderr, "Internal error: unexpected option '%c'\n", c);
                exit (1);
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
        _exit(1);
}

int
main (int argc, char** argv)
{
    int fan_fd;
    int res;
    int err;
    void *buffer;
    struct fanotify_event_metadata *data;
    struct sigaction sa;
    struct timeval event_time;

    /* always ignore events from ourselves (writing log file) */
    ignored_pids[ignored_pids_len++] = getpid();

    parse_args (argc, argv);

    fan_fd = fanotify_init (0, O_LARGEFILE);
    if (fan_fd < 0) {
        err = errno;
        fprintf (stderr, "Cannot initialize fanotify: %s\n", strerror (err));
        if (err == EPERM)
            fputs ("You need to run this program as root.\n", stderr);
        exit(1);
    }

    setup_fanotify (fan_fd);

    /* allocate memory for fanotify */
    buffer = NULL;
    err = posix_memalign (&buffer, 4096, BUFSIZE);
    if (err != 0 || buffer == NULL) {
        fprintf(stderr, "Failed to allocate buffer: %s\n", strerror (err));
        exit(1);
    }

    /* output file? */
    if (option_output) {
        int fd = open (option_output, O_CREAT|O_WRONLY|O_EXCL, 0666);
        if (fd < 0) {
            perror ("Failed to open output file");
            exit (1);
        }
        fflush (stdout);
        dup2 (fd, STDOUT_FILENO);
        close (fd);
    }

    /* setup signal handler to cleanly stop the program */
    sa.sa_handler = signal_handler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction (SIGINT, &sa, NULL) < 0) {
        perror ("sigaction");
        exit (1);
    }

    /* set up --time alarm */
    if (option_timeout > 0) {
        sa.sa_handler = signal_handler;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction (SIGALRM, &sa, NULL) < 0) {
            perror ("sigaction");
            exit (1);
        }
        alarm (option_timeout);
    }

    /* clear event time if timestamp is not required */
    if (!option_timestamp) {
        memset(&event_time, 0, sizeof(struct timeval));
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
            perror ("read");
            exit(1);
        }

        /* get event time, if requested */
        if (option_timestamp) {
            if (gettimeofday (&event_time, NULL) < 0) {
                perror ("gettimeofday");
                exit (1);
            }
        }

        data = (struct fanotify_event_metadata *) buffer;
        while (FAN_EVENT_OK (data, res)) {
            if (show_pid (data->pid))
                print_event (data, &event_time);
            close (data->fd);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
}

