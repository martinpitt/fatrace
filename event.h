/**
 * fatrace - Trace system wide file access events.
 *
 * Event formatting, independent from fanotify and the process environment
 * so that it can be unit tested.
 *
 * (C) 2026 Martin Pitt <martin@piware.de>
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

#ifndef FATRACE_EVENT_H
#define FATRACE_EVENT_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/time.h>
#include <sys/types.h>

/* https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html ; not defined in any include file */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* deeper process trees get truncated with a warning */
#define MAX_PARENTS 64

enum fatrace_timestamp {
    TIMESTAMP_NONE,
    TIMESTAMP_LOCAL,    /* HH:MM:SS.uuuuuu wall clock time */
    TIMESTAMP_EPOCH,    /* seconds.uuuuuu since the epoch */
};

struct fatrace_event_proc {
    pid_t pid;
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

const char* mask2str (uint64_t mask);
void print_json_str (FILE *out, const char* key, const char* value);

void format_fatrace_event_text (FILE *out, const struct fatrace_event *ev, enum fatrace_timestamp timestamp_mode);
void format_fatrace_event_json (FILE *out, const struct fatrace_event *ev, enum fatrace_timestamp timestamp_mode);

#endif /* FATRACE_EVENT_H */
