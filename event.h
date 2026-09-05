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

#include <stdint.h>
#include <stdio.h>

/* https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html ; not defined in any include file */
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

const char* mask2str (uint64_t mask);
void print_json_str (FILE *out, const char* key, const char* value);

#endif /* FATRACE_EVENT_H */
