#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <map>

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

// #define k0 123477ull
// #define k1 456777ull
// #define prefix 0x6f6b696d6f6b6570ull

// modified from https://github.com/python/cpython/blob/7d07e5891d2843f269fac00dc8847abfe3671765/Python/pyhash.c#L377
// license https://github.com/python/cpython/blob/7d07e5891d2843f269fac00dc8847abfe3671765/LICENSE

// inline uint64_t siphash13(uint64_t k0, uint64_t k1, const void *src, size_t src_sz) {
__attribute__((always_inline)) inline uint64_t siphash13(const void *src,
                                                         size_t src_sz) {
	assert(src_sz == 8);  // help compiler optimize
#ifdef prefix
	uint64_t b = (uint64_t)(src_sz + 8) << 56;
#else
	uint64_t b = (uint64_t)src_sz << 56;
#endif
	const uint8_t *in = (const uint8_t *)src;

	uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
	uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
	uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
	uint64_t v3 = k1 ^ 0x7465646279746573ULL;

#ifdef prefix
	v3 ^= prefix;
	SINGLE_ROUND(v0, v1, v2, v3);
	v0 ^= prefix;
#endif

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

typedef struct {
	uint64_t start;
	uint64_t length;
	uint64_t dp;
} trace;

#define MASK 0x00ffffff
#define SEARCH_LENGTH (1UL << 28)

std::map<uint64_t, trace> traces;

void evalutate_traces(const trace &t1, const trace &t2) {
	trace ta = t1.length > t2.length ? t1 : t2;
	trace tb = t1.length > t2.length ? t2 : t1;
	uint64_t diff = ta.length - tb.length;
	fprintf(stderr, "diff = %lu\n", diff);
	uint64_t xa = ta.start;
	uint64_t xb = tb.start;
	while (diff > 0) {
		xa = siphash13(&xa, sizeof(xa));
		diff--;
	}
	fprintf(stderr, "Looking for collision...\n");
	uint64_t pxa = 0, pxb = 0;
	while (xa != xb) {
		pxa = xa;
		pxb = xb;
		xa = siphash13(&xa, sizeof(xa));
		xb = siphash13(&xb, sizeof(xb));
	}
	fprintf(stderr, "Collision found!\n");
	printf("%lx %lx\n", pxa, pxb);
	fprintf(stderr, "%lx %lx\n", xa, xb);
	exit(0);
}

bool found_coll = false;

void find_cycle(uint64_t x) {
	uint64_t start = x;
	for (uint64_t i = 0; i < SEARCH_LENGTH; i++) {
		if (found_coll)
			return;
		x = siphash13(&x, sizeof(x));
		if ((x & MASK) == 0) {
			// distinguished point
			fprintf(stderr, "DP: start=%lx length=%lx x=%lx\n", start, i, x);
			trace t = {start, i, x};
			if (traces.find(x) != traces.end()) {
				fprintf(stderr, "Two traces collided on same DP\n");
				trace t2 = traces[x];
				if (t2.start == t.start) {
					// this would be the same as floyd cycle finding
					// continue;
				}
				found_coll = true;
				evalutate_traces(t, t2);
				break;
			}
			traces[x] = t;
		}
	}
}

#define NUM_THREADS 8

uint64_t rand64() {
	uint64_t x;
	syscall(SYS_getrandom, &x, sizeof(x), 0);
	return x;
}

void thread() {
	while (1) {
		find_cycle(rand64());
	}
}

int main() {
#ifdef prefix
	fprintf(stderr, "Doing prefix coliision search with %llx\n", prefix);
#endif
	pthread_t threads[NUM_THREADS];

	for (uint64_t i = 0; i < NUM_THREADS; i++) {
		// pthread_create(&threads[i], NULL, (void *(*)(void *))find_cycle,
		//                (void *)rand64());
		pthread_create(&threads[i], NULL, (void *(*)(void *))thread, NULL);
	}
	for (uint64_t i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}
	return 0;
}
