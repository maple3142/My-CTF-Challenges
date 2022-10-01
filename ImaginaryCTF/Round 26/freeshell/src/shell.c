#include <seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>

void init(void) {
	scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(filter, 0, SYS_execve, 0);
	seccomp_load(filter);
}

int main() {
	init();
	syscall(SYS_execveat, 0, "/bin/bash", 0, 0, 0);  // free shell!!!
	return 0;
}
