#define _GNU_SOURCE 1
#include <linux/random.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

long rand_num;

uint64_t rand64() {
	syscall(SYS_getrandom, &rand_num, sizeof(rand_num), 0);
	return &rand_num;
}

void generate_password(char *charset, uint32_t len) {
	char *password = malloc(len + 1);
	for (int i = 0; i < len; i++) {
		password[i] = charset[(rand64() * i + len) % strlen(charset)];
	}
	password[len] = '\0';
	printf("Your password is: %s\n", password);
	free(password);
}

char default_charset[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@$%^&*";

int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	while (1) {
		int choice;
		printf("Welcome to the password generator!\n");
		printf("1. Use a default character set (a-zA-Z0-9!@$%^&*)\n");
		printf("2. Use a custom character set\n");
		printf("3. Exit\n");
		printf("> ");
		scanf("%d", &choice);
		char charset[0x40];
		switch (choice) {
			case 1:
				strcpy(charset, default_charset);
				break;
			case 2:
				printf("Enter the character set: ");
				scanf("%s", charset);
				break;
			case 3:
				return 0;
			default:
				printf("Invalid choice!\n");
				continue;
		}
		uint32_t len;
		printf("Enter the length of the password: ");
		scanf("%d", &len);
		if (len > 128) {
			printf("Password too long!\n");
			continue;
		}
		generate_password(charset, len);
	}
	return 0;
}

void gadget() {
	asm volatile(
	    ".intel_syntax noprefix\n"
	    "pop rdi\n"
	    "ret\n");
}
