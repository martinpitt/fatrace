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
#include <sys/stat.h>
#include <sys/fanotify.h>

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

int
main()
{
    int fan_fd;
    int res;
    static char buffer[4096];
    struct fanotify_event_metadata *data;

    fan_fd = fanotify_init (0, 0);
    if (fan_fd < 0) {
        perror ("fanotify_init");
        exit(1);
    }

    res = fanotify_mark (fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, 
            FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_ONDIR | FAN_EVENT_ON_CHILD,
            AT_FDCWD, ".");
    if (res < 0) {
        perror ("fanotify_mark");
        exit(1);
    }
    
    while (1) {
        res = read (fan_fd, &buffer, 4096);
        if (res < 0) {
            perror ("read");
            exit(1);
        }
        data = (struct fanotify_event_metadata *) &buffer;
        while (FAN_EVENT_OK (data, res)) {
            print_event (data);
            close (data->fd);
            data = FAN_EVENT_NEXT (data, res);
        }
    }
} 

