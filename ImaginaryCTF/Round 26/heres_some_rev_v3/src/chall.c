#include <stdint.h>
#include <stdio.h>

uint64_t f(uint64_t x) {
	for (int i = 0; i < 0x13371337; i++) {
		x = 0x1337 * x + 1337;
	}
	return x;
}

uint64_t ar[] = {3850171132014162800ull, 5340012885551996783ull,
                 7570249252805341466ull, 15654706945287115546ull,
                 3351868198033773624ull};

int main() {
	unsigned char flag[0x100];
	printf("Flag: ");
	scanf("%100s", flag);
	if (strlen(flag) != 40) {
		puts("Bad");
		return 1;
	}
	for (int i = 0; i < 5; i++) {
		long p = ((uint64_t *)flag)[i];
		if (f(p) != ar[i]) {
			puts("Bad");
			return 1;
		}
	}
	puts("Good");
	return 0;
}
