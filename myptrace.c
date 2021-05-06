#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

int main(int argc, char *argv[])
{
        pid_t pid;
        int count = 0;
        int waitstatus;
        int syscall_entry = 1;
		char address[50] = "/bin/";

		int orig_rax;

		int array[314] = { 0 };
		char* nameArray[314] = {"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap",
			"mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv",
			"writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget",
			"shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid",
			"sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind",
			"listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve",
			"exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd",
			"msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
			"chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink",
			"chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
			"times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid",
			"getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
			"getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
			"rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs",
			"getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock",
			"munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
			"setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot",
			"sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl",
			"nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr",
			"fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
			"tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit",
			"io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall",
			"semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres",
			"clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
			"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
			"keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat",
			"fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
			"pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
			"utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4",
			"eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg",
			"fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu",
			"process_vm_readv", "process_vm_writev", "kcmp", "finit_module"
		}; //https://www.cnblogs.com/gavanwanggw/p/6920826.html

		int temp1 = 0;
		char* temp2 = "";

        pid = fork();

		int i;
		if (argc >= 2)
		{
			for (i = 1; i < argc; i++)
			{
				if (pid == 0) {
					ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
					strcat(address, argv[i]);
					execl(address, argv[i], NULL);
					exit(0);
				}
				else if (pid > 0) {
					wait(&waitstatus);
					while (1) {
						if (syscall_entry == 1) {
							count++;
							syscall_entry = 0;
							struct user_regs_struct regs;
							ptrace(PTRACE_GETREGS, pid, NULL, &regs);
							orig_rax = regs.orig_rax;
							//printf("orig_rax: %d\n", orig_rax);
							if(orig_rax >= 0){
								array[orig_rax]++;
							}
						}
						else {
							syscall_entry = 1;
						}		
						ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
						wait(&waitstatus);
						if (WIFEXITED(waitstatus)) {
							break;
						}						
					}
				}
				else {
					printf("fork error\n");
				}			
			}
		}
		else
		{
			printf("argument list is empty.\n");
		}

		for (int i = 0; i < 314; i++) {
			for (int j = 0; j < 313 - i; j++) {
				if (array[j] < array[j + 1]) {
					temp1 = array[j];
					temp2 = nameArray[j];

					array[j] = array[j + 1];
					nameArray[j] = nameArray[j + 1];

					array[j + 1] = temp1;
					nameArray[j + 1] = temp2;
				}
			}
		}

		printf("Total number of syscalls: %d\n", count);
		for (int i = 0; i < 314; i++) {
			if (array[i] != 0) {
				printf("\t%d %s\n", array[i], nameArray[i]);
			}
		}
		return 0;
}