#include <stdint.h>
#include <stdio.h>

uint64_t f(uint64_t x) {
	for (int i = 0; i < 0x13371337; i++) {
		x = 7211443149775049351 * (x - 1337);
		// x = 7211443149775049351 * x + 5947659300854512881;
	}
	return x;
}

uint64_t ar[] = {3850171132014162800ull, 5340012885551996783ull,
                 7570249252805341466ull, 15654706945287115546ull,
                 3351868198033773624ull};

uint64_t f0(uint64_t x) {
	for (int i = 0; i < 0x13371337; i++) {
		x = 0x1337 * x + 1337;
	}
	return x;
}
int main() {
	for (int i = 0; i < 5; i++) {
		uint64_t x = f(ar[i]);
		printf("%s", &x);
		fflush(stdout);
	}
	puts("");
	uint64_t b = f0(0);
	uint64_t a = f0(1) - b;
	printf("%lu\n", a);
	printf("%lu\n", b);
	printf("%lu\n", f0(48763));
	printf("%lu\n", a * 48763 + b);
	return 0;
}
