#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/random.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#define zero_regs()                    \
	do {                               \
		asm(".intel_syntax noprefix"); \
		asm("xor rax, rax");           \
		asm("xor rbx, rbx");           \
		asm("xor rcx, rcx");           \
		asm("xor rdx, rdx");           \
		asm("xor rdi, rdi");           \
		asm("xor rsi, rsi");           \
		asm("xor r8,  r8");            \
		asm("xor r9,  r9");            \
		asm("xor r10, r10");           \
		asm("xor r11, r11");           \
		asm("xor r12, r12");           \
		asm("xor r13, r13");           \
		asm("xor r14, r14");           \
		asm("xor r15, r15");           \
		asm(".att_syntax noprefix");   \
	} while (0)

void setup_seccomp(void) {
	scmp_filter_ctx filter = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(filter, SCMP_ACT_ALLOW, SYS_read, 0);
	seccomp_load(filter);
}

void *randaddr() {
	long x;
	syscall(SYS_getrandom, &x, 8, 0);
	x &= ~0xfffffffffff00fffL;
	return (void *)x;
}

int main() {
	int flagfd = open("flag.txt", O_RDONLY);
	mmap(randaddr(), 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, flagfd, 0);
	close(flagfd);
	long (*fn)() = mmap(randaddr(), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
	                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	read(0, fn, 0x20);
	setup_seccomp();
	zero_regs();
	fn();
	return 0;
}
