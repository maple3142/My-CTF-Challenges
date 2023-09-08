#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FLAG_SIZE 38

const char check[] = {-34,  28,  -125, 108, 70,  -34,  78,  8,    16, -92,
                      -103, -76, -42,  -63, 51,  -112, 26,  49,   26, -39,
                      30,   54,  0,    -76, -45, 8,    87,  -100, 58, -33,
                      -12,  50,  35,   8,   62,  83,   -28, 13};
int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage: %s <flag>\n", argv[0]);
		exit(1);
	}
	char *flag = argv[1];
	if (strlen(flag) != FLAG_SIZE) {
		printf("Incorrect!\n");
		exit(1);
	}
	unsigned int tmp;
	memcpy(&tmp, flag, sizeof(tmp));
	srand(tmp);
	for (int i = 0; i < FLAG_SIZE; i++) {
		flag[i] ^= rand() % 256;
	}
	if (!memcmp(flag, check, FLAG_SIZE)) {
		printf("Correct!\n");
	} else {
		printf("Incorrect!\n");
		exit(1);
	}
	return 0;
}
