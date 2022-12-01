#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define FLAG_LEN 144
#define N_THREADS (FLAG_LEN / 8)

int check(uint64_t a, uint64_t b, uint64_t input) {
	uint64_t v = input;
	while (v == input) {
		v = a * v + b;
	}
	return 0;
}

typedef struct {
	int id;
	int result;
	uint64_t a, b, input;
} check_data_t;

void *do_work(void *t) {
	check_data_t *task = t;
	task->result = check(task->a, task->b, task->input);
	return NULL;
}

check_data_t checks[N_THREADS] = {
    {0, 1, 10105059151405969556ull, 3638161745144216245ull, 0},
    {1, 1, 16963598052469450230ull, 16374932956393034803ull, 0},
    {2, 1, 982171186172475446ull, 4408990653950337109ull, 0},
    {3, 1, 1199534010640194268ull, 441989708272465413ull, 0},
    {4, 1, 3970698370858041460ull, 6612128509933608097ull, 0},
    {5, 1, 4135294579233198566ull, 11502362204479744316ull, 0},
    {6, 1, 9136748554805213520ull, 15051824954946646681ull, 0},
    {7, 1, 3324133223185780352ull, 977669937175735013ull, 0},
    {8, 1, 8387212428015515172ull, 799019783018684371ull, 0},
    {9, 1, 4057866833744368092ull, 17575176142086040257ull, 0},
    {10, 1, 13333356010782068068ull, 17659029992744595929ull, 0},
    {11, 1, 4120352682052346570ull, 1421674113312036332ull, 0},
    {12, 1, 162600003931582046ull, 7123990653832302858ull, 0},
    {13, 1, 5658467538575665640ull, 17245663064433717825ull, 0},
    {14, 1, 4770411265745418588ull, 7683702773211297544ull, 0},
    {15, 1, 17555518888307253946ull, 12427923566490062993ull, 0},
    {16, 1, 9260680416232703190ull, 10407256304192294309ull, 0},
    {17, 1, 17296750777182405916ull, 4092275939527309050ull, 0},
};

int main() {
	char flag[201];
	printf("Flag: ");
	scanf("%200s", flag);
	if (strlen(flag) != FLAG_LEN) {
		puts("Bad");
		return 0;
	}
	uint64_t *p = (uint64_t *)flag;
	pthread_t threads[N_THREADS];
	for (int i = 0; i < N_THREADS; i++) {
		checks[i].input = p[i];
		pthread_create(&threads[i], NULL, do_work, &checks[i]);
	}
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 1337;
	for (int i = 0; i < N_THREADS; i++) {
		int ret = pthread_timedjoin_np(threads[i], NULL, &ts);
		if (ret == ETIMEDOUT) {
			pthread_cancel(threads[i]);
		}
	}
	int result = 1;
	for (int i = 0; i < N_THREADS; i++) {
		result &= checks[i].result;
	}
	if (result) {
		puts("Good");
	} else {
		puts("Bad");
	}
	return 0;
}
