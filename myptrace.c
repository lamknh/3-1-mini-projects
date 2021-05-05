#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

typedef struct Node {
	char* syscallName; //system Call 이름
	int sysCallNum; // system Call resgister 상 번호
	int syscallCount; // system Call 호출 횟수
	struct Node* next;
} Node;

typedef struct {
	Node* head;
	int size;
}LinkedList;

int main(int argc, char *argv[])
{
        pid_t pid;
        int count = 0;
        int waitstatus;
        int syscall_entry = 1;
		char address[50] = "/bin/";

		int orig_rax;

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
							printf("orig_rax: %d\n", orig_rax);
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

		printf("Total number of syscalls: %d\n", count);
		return 0;
}