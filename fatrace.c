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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <mntent.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/fanotify.h>

/* command line options */
char* option_output = NULL;
long option_timeout = -1;

/* --time alarm sets this to 0 */
volatile int running = 1;

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

    memset (buffer, 0, sizeof (buffer));
    if (mask & FAN_ACCESS)
        buffer[offset++] = 'A';
    if (mask & FAN_MODIFY)
        buffer[offset++] = 'M';
    if (mask & FAN_CLOSE_WRITE || mask & FAN_CLOSE_NOWRITE)
        buffer[offset++] = 'C';
    if (mask & FAN_OPEN)
        buffer[offset++] = 'O';

    return buffer;
}

/**
 * stat2path:
 *
 * Try to resolve a struct stat from a PID to a pathname.
 *
 * Returns: File path that corresponds to the given stat, or NULL if it cannot
 * be determined. Only valid until the next call. Do not free.
 */
const char*
stat2path (pid_t pid, const struct stat *search)
{
    static char fddirname[PATH_MAX];
    static char buffer[PATH_MAX];
    DIR* fddir;
    int fddirfd;
    struct dirent* entry;
    struct stat st;
    char* result = NULL;
    int len;

    snprintf (fddirname, sizeof (fddirname), "/proc/%i/fd", pid);
    fddir = opendir (fddirname);
    if (fddir == NULL)
        return NULL;
    fddirfd = dirfd (fddir);

    while ((entry = readdir (fddir)) != NULL) {
        if (fstatat (fddirfd, entry->d_name, &st, 0) < 0)
            continue;
        if (st.st_ino == search->st_ino && st.st_dev == search->st_dev) {
            len = readlinkat (fddirfd, entry->d_name, buffer, sizeof (buffer));
            if (len > 0) {
                buffer[len] = '\0';
                result = buffer;
            }
        }
    }
    closedir (fddir);
    return result;
}

/**
 * print_event:
 *
 * Print data from fanotify_event_metadata struct to stdout.
 */
void
print_event(struct fanotify_event_metadata *data)
{
    int fd, len;
    static char buffer[4096];
    struct stat st;
    const char* path;

    /* read process name */
    snprintf (buffer, sizeof (buffer), "/proc/%i/comm", data->pid);
    fd = open (buffer, O_RDONLY);
    if (fd > 0) {
        len = read (fd, buffer, 100);
        while (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
            len--;
        }
    } else
        strcpy (buffer, "unknown");
    close (fd);

    if (fstat (data->fd, &st) < 0) {
        perror ("stat");
        exit (1);
    }
    path = stat2path (data->pid, &st);
    printf ("%s(%i): %s ", buffer, data->pid, mask2str (data->mask));
    if (path != NULL)
        puts (path);
    else
        printf ("device %i:%i inode %ld\n", major (st.st_dev), minor (st.st_dev), st.st_ino);
}

/**
 * fanotify_mark_mounts:
 *
 * @fan_fd: fanotify file descriptor as returned by fanotify_init().
 *
 * Set up fanotify watches on all mount points.
 */
void
setup_fanotify(int fan_fd)
{
    int res;
    FILE* mounts;
    struct mntent* mount;
    
    /* blacklist */

    mounts = setmntent ("/proc/self/mounts", "r");
    if (mounts == NULL) {
        perror ("setmntent");
        exit (1);
    }

    while ((mount = getmntent (mounts)) != NULL) {
        /* Only consider mounts which have an actual device or bind mount
         * point. The others are stuff like proc, sysfs, binfmt_misc etc. which
         * are virtual and do not actually cause disk access. */
        if (access (mount->mnt_fsname, F_OK) != 0) {
            //printf("IGNORE: fsname: %s dir: %s type: %s\n", mount->mnt_fsname, mount->mnt_dir, mount->mnt_type);
            continue;
        }

        //printf("Adding watch for %s mount %s\n", mount->mnt_type, mount->mnt_dir);
        res = fanotify_mark (fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, 
                FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_ONDIR | FAN_EVENT_ON_CHILD,
                AT_FDCWD, mount->mnt_dir);
        if (res < 0) {
            perror ("fanotify_mark");
            exit (1);
        }
    }

    endmntent (mounts);
}

/**
 * help:
 *
 * Show help.
 */
void
help ()
{
    puts ("Usage: fatrace [options...] \n"
"\n"
"Options:\n"
"  -o FILE, --output=FILE\tWrite events to a file instead of standard output.\n"
"  -t SECONDS, --time=SECONDS\tStop after the given number of seconds.\n"
"  -h, --help\t\t\tShow help.");
}

/**
 * parse_args:
 *
 * Parse command line arguments and set the global option_* variables.
 */
void
parse_args (int argc, char** argv)
{
    int c;
    char *endptr;

    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"time",   required_argument, 0, 't'},
        {"help",   no_argument,       0, 'h'},
        {0,        0,                 0,  0 }
    };

    while (1) {
        c = getopt_long (argc, argv, "ho:t:", long_options, NULL);

        if (c == -1)
            break;

        switch (c) {
            case 'o':
                option_output = strdup (optarg);
                break;

            case 't':
                option_timeout = strtol (optarg, &endptr, 10);
                if (*endptr != '\0' || option_timeout <= 0) {
                    fputs ("Error: Invalid number of seconds\n", stderr);
                    exit (1);
                }
                break;

            case 'h':
                help ();
                exit (0);

            case '?':
                exit (1);

            default:
                fprintf (stderr, "Internal error: unexpected option '%c'\n", c);
                exit (1);
        }
    }
}

void
alarm_handler (int signal)
{
    if (signal == SIGALRM)
        running = 0;
}

int
main (int argc, char** argv)
{
    int fan_fd;
    int res;
    static char buffer[4096];
    struct fanotify_event_metadata *data;
    pid_t my_pid;

    parse_args (argc, argv);

    my_pid = getpid();

    fan_fd = fanotify_init (0, 0);
    if (fan_fd < 0) {
        perror ("fanotify_init");
        exit(1);
    }

    setup_fanotify (fan_fd);

    /* output file? */
    if (option_output) {
        int fd = open (option_output, O_CREAT|O_WRONLY, 0666);
        if (fd < 0) {
            perror ("Failed to open output file");
            exit (1);
        }
        dup2 (fd, STDOUT_FILENO);
    }

    /* set up --time alarm */
    if (option_timeout > 0) {
        struct sigaction sa;
        sa.sa_handler = alarm_handler; 
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        if (sigaction (SIGALRM, &sa, NULL) < 0) {
            perror ("sigaction");
            exit (1);
        }
        alarm (option_timeout);
    }

    /* read all events in a loop */
    while (running) {
        res = read (fan_fd, &buffer, 4096);
        if (res < 0 && errno != EINTR) {
            perror ("read");
            exit(1);
        }
        data = (struct fanotify_event_metadata *) &buffer;
        while (FAN_EVENT_OK (data, res)) {
            if (data->pid != my_pid)
                print_event (data);
            close (data->fd);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
} 

