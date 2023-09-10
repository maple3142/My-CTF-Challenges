#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define _le64toh(x) ((uint64_t)(x))

#define ROTATE(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define HALF_ROUND(a, b, c, d, s, t) \
	a += b;                          \
	c += d;                          \
	b = ROTATE(b, s) ^ a;            \
	d = ROTATE(d, t) ^ c;            \
	a = ROTATE(a, 32);

#define SINGLE_ROUND(v0, v1, v2, v3)    \
	HALF_ROUND(v0, v1, v2, v3, 13, 16); \
	HALF_ROUND(v2, v1, v0, v3, 17, 21);

uint64_t siphash13(uint64_t k0, uint64_t k1, const void *src, size_t src_sz) {
	uint64_t b = (uint64_t)src_sz << 56;
	const uint8_t *in = (const uint8_t *)src;

	uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
	uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
	uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
	uint64_t v3 = k1 ^ 0x7465646279746573ULL;

	uint64_t t;
	uint8_t *pt;

	while (src_sz >= 8) {
		uint64_t mi;
		memcpy(&mi, in, sizeof(mi));
		mi = _le64toh(mi);
		in += sizeof(mi);
		src_sz -= sizeof(mi);
		v3 ^= mi;
		SINGLE_ROUND(v0, v1, v2, v3);
		v0 ^= mi;
	}

	t = 0;
	pt = (uint8_t *)&t;
	switch (src_sz) {
		case 7:
			pt[6] = in[6]; /* fall through */
		case 6:
			pt[5] = in[5]; /* fall through */
		case 5:
			pt[4] = in[4]; /* fall through */
		case 4:
			memcpy(pt, in, sizeof(uint32_t));
			break;
		case 3:
			pt[2] = in[2]; /* fall through */
		case 2:
			pt[1] = in[1]; /* fall through */
		case 1:
			pt[0] = in[0]; /* fall through */
	}
	b |= _le64toh(t);

	v3 ^= b;
	SINGLE_ROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	SINGLE_ROUND(v0, v1, v2, v3);
	SINGLE_ROUND(v0, v1, v2, v3);
	SINGLE_ROUND(v0, v1, v2, v3);

	/* modified */
	t = (v0 ^ v1) ^ (v2 ^ v3);
	return t;
}

void gen_lcg(unsigned char *buf, uint32_t x, size_t sz) {
	for (size_t i = 0; i < sz; i++) {
		x = 214013 * x + 2531011;
		buf[i] = (x >> 16) & 0xff;
	}
}

void hex_decode(unsigned char *dest, const char *src, size_t len) {
	for (size_t i = 0; i < len; i += 2) {
		unsigned char *p = dest + i / 2;
		sscanf(src + i, "%2hhx", p);
	}
}

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: %s <output file> <plaintext>\n", argv[0]);
		return 1;
	}
	int fd = open(argv[1], O_RDWR | O_CREAT, 0644);
	const size_t tbl_size = (1 << 24) * sizeof(uint64_t);
	ftruncate(fd, tbl_size);
	char *dest =
	    mmap(NULL, tbl_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	unsigned char pt[128];
	// printf("%s\n", argv[2]);
	hex_decode(pt, argv[2], strlen(argv[2]));
	size_t ptln = strlen(argv[2]) / 2;
	// printf("%lu\n", ptln);
	// for(size_t i = 0; i < ptln; i++) {
	// 	printf("%02x", pt[i]);
	// }
	// printf("\n");
	unsigned char key[16];
	for (uint32_t i = 0; i < (1 << 24); i++) {
		gen_lcg(key, i, 16);
		uint64_t k0 = *(uint64_t *)key;
		uint64_t k1 = *(uint64_t *)(key + 8);
		uint64_t hash = siphash13(k0, k1, pt, ptln);
		memcpy(dest, &hash, sizeof(hash));
		dest += sizeof(hash);
	}
	close(fd);
	return 0;
}
