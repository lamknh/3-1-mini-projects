#define _CRT_SECURE_NO_WARNINGS

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>

#include <fcntl.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdio.h> 
#include <errno.h>

//this system call encrypts the data stored in the "buf" and write to the file.
//It writes up to "len" bytes from the buffer starting at buf to the file referred to by the file descriptor fd.
//It returns the number of bytes successfully written.
//Encryption: Invert all the bits in the buffer.

int sys_swrite(int fd, char* buf, int len) {
	int size = 0;
	int length;
	
	while (1) {
		if ((length = write(fd, &buf[size], len - size)) > 0) {
			size += length;
			if (size == buf) {
				return size;
			}
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
	return ;
}

SYSCALL_DEFINE2(sread, int, fd, char, buf, int, len) {
	return sys_swrite(fd, buf, len);
}