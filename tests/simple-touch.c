/*
 * Simple touch-like utility for testing.
 * This is a standalone binary that can be copied/renamed, unlike
 * the multi-call Rust coreutils binary.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <utime.h>

int main(int argc, char *argv[]) {
    if (argc != 2)
        err(1, "Usage: %s FILE", argv[0]);

    const char *path = argv[1];

    /* Try to update timestamp if file exists */
    if (utime(path, NULL) == 0)
        return 0;

    /* If file doesn't exist, create it */
    if (errno != ENOENT)
        err(1, "%s", path);

    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd < 0)
        err(1, "%s", path);

    close(fd);
    return 0;
}
