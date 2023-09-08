#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

void dump_memory(unsigned long start, unsigned long end, FILE *output) {
	long *ptr = (long *)start;
	while ((unsigned long)ptr < end) {
		fwrite(ptr, sizeof(long), 1, output);
		ptr++;
	}
}

__attribute__((constructor)) static void init(void) {
	FILE *output = fopen("dump.bin", "wb");
	if (output == NULL) {
		perror("Error opening output file");
		return;
	}

	FILE *maps = fopen("/proc/self/maps", "r");
	if (maps == NULL) {
		perror("Error opening maps file");
		return;
	}

	while (!feof(maps)) {
		unsigned long start, end;
		char permissions[5];
		char line[256];

		if (fgets(line, sizeof(line), maps) == NULL)
			break;

		sscanf(line, "%lx-%lx %4s", &start, &end, permissions);
		printf("%lx-%lx %4s\n", start, end, permissions);

		if (permissions[0] == 'r' &&
		    (start & 0x7f0000000000) != 0x7f0000000000) {
			printf("Dumping %lx-%lx\n", start, end);
			dump_memory(start, end, output);
		}
	}
	fclose(output);
}
// thanks ChatGPT :)
// musl-gcc -shared -fPIC -o hook.so hook.c -ld
