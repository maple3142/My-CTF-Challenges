#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>
#include "obfuscate.h"

extern char **environ;
char flag[128];
char *cmd_argv[] = {
    AY_OBFUSCATE("python3"), AY_OBFUSCATE("-c"),
    AY_OBFUSCATE("__import__('pickle').loads(bytes.fromhex('PLACEHOLDER'))"),
    flag + 5, 0};
char *py = AY_OBFUSCATE("/usr/bin/python3");

void gadgets() {
	asm("syscall");
	asm("pop %rax\nret");
	asm("pop %rdi\nret");
	asm("pop %rsi\nret");
	asm("pop %rdx\nret");
}
long syc = (long)(gadgets) + 4;
long pop_rax = (long)(gadgets) + 6;
long pop_rdi = (long)(gadgets) + 8;
long pop_rsi = (long)(gadgets) + 10;
long pop_rdx = (long)(gadgets) + 12;

bool check_str(char *s) {
	while (*s != 0) {
		if ((*s < 20) || (*s > 127))
			return false;
		s++;
	}
	return true;
}

bool check() {
	long val;
	long *p = (long *)&val;
	if (strncmp("AIS3{", flag, 5) != 0) {
		return false;
	} else if (check_str(flag)) {
		p[3] = pop_rax;
		p[4] = SYS_execve;
		p[5] = pop_rdi;
		p[6] = (long)py;
		p[7] = pop_rsi;
		p[8] = (long)cmd_argv;
		p[9] = pop_rdx;
		p[10] = (long)environ;
		p[11] = syc;
		return true;
	}
	return false;
}

__attribute__((constructor)) void before() {
	struct stat sb;
	if (stat(AY_OBFUSCATE("/usr/bin/python3"), &sb) != 0) {
		puts("Bad OS");
		exit(1);
	}
	if ((sb.st_mode & S_IXUSR) == 0) {
		puts("Bad OS");
		exit(1);
	}
}

int main(int argc, char **argv) {
	scanf("%s", flag);
	if (!check()) {
		puts("Bad");
	} else {
		puts("Good");
	}
	return 0;
}
