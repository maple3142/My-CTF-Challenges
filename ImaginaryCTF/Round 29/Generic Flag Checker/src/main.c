#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#define FLAG_LEN 56

int check_i = 0;
long flag = 0;
void *final;

int data[FLAG_LEN / 4] = {35457810,  990774802, 132637,    939787282, 34148153,
                          386730044, 755696188, 956894252, 302714898, 437067070,
                          470025275, 503971899, 1819241506};

void sigfault_handler(int signal, siginfo_t *si, void *arg) {
	void *p = &&cont;
	asm("\n\
    mov rcx, %[v]\n\
    push rcx\n\
    ret\n\
    "
	    : [v] "=r"(p));
cont:
	ucontext_t *uc = (ucontext_t *)arg;
	int val = (int)(long)si->si_addr;
	// printf("si_addr = %p\n", si->si_addr);
	// printf("val = %p\n", val);
	// printf("rip = %p\n", uc->uc_mcontext.gregs[REG_RIP]);
	if (check_i > 0)
		data[check_i - 1] ^= val;
	if (check_i < FLAG_LEN / 4 - 1)
		data[check_i] ^= val;
	check_i += 1;
	int bad = 0;
	for (int i = 0; i < FLAG_LEN / 4; i++) {
		bad |= data[i];
	}
	if (check_i == FLAG_LEN / 4) {
		if (!bad) {
			flag = 0xdeadbeef;
		}
		uc->uc_mcontext.gregs[REG_RIP] = (long) final;
	} else {
		uc->uc_mcontext.gregs[REG_RIP] += 3;
	}
}

__attribute__((constructor)) void init() {
	void *p = &&cont;
	asm("\n\
    mov rcx, %[v]\n\
    push rcx\n\
    ret\n\
    "
	    : [v] "=r"(p));
cont:
	struct sigaction sa;
	sa.sa_sigaction = &sigfault_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
}

int main() {
	printf("Flag: ");
	final = &&check;
	for (int i = 0; i < FLAG_LEN / 4; i++) {
		scanf("%4s", &flag);
		flag ^= (*(long *)flag + 0x1337);
	}
check:
	if (flag == 0xdeadbeef) {
		puts("Good");
	} else {
		puts("Bad");
	}
	return 0;
}
// gcc -masm=intel main.c -o chall && strip chall
