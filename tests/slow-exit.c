/*
 * LD_PRELOAD library to slow down program exits
 * This gives fatrace enough time to read process metadata from /proc
 */

#define _GNU_SOURCE
#include <unistd.h>

__attribute__((destructor))
static void slow_exit_cleanup(void) {
    usleep (100000);
}
