#include <stdio.h>
#include <stdlib.h>

int main() {
	FILE *fp = fopen("/flag", "r");
	if (fp == NULL) {
		puts("Error opening file");
		return 1;
	}
	char flag[1024];
	fgets(flag, 1024, fp);
	puts(flag);
	fclose(fp);
	return 0;
}
