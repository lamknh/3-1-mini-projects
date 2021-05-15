#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>

#include <fcntl.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdio.h> 
#include <errno.h>

//It attempts to read up to len bytes from file descriptor fd into the buffer starting at buf.
//Return value is the number of bytes read.
//During reading, data must be decrypted.

int sys_sread(int fd, char* buf, int len) {
	int size = 0;
	int length;

	while (1) {
		if ((length = read(fd, &buf[size], len - size)) > 0) {
			size += length;
			if (size == len) {
				return size;
			}
			else if (length == 0) {
				return size;
			}
			else {
				if (errno == EINTR) {
					continue;
				}
				else {
					return -1;
				}
			}
		}
	}
}

SYSCALL_DEFINE2(sread, int, fd, char, buf, int, len) {
	return sys_sread(fd, buf, len);
}