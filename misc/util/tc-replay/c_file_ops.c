/*
 * c_file_ops.c
 *
 *  Created on: Jun 5, 2018
 *      Author: chenbo
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int crete_raw_read_file(const char *file_name, char *buf, int size)
{
    int fd = open(file_name, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "[CRETE ERROR] open file failed: %s!\n", file_name);
        return -1;
    }

    int ret = read(fd, buf, size);
    close(fd);

    return ret;
}
