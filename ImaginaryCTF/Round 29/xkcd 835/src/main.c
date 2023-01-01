#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_NODES 64
#define LEFT(i) (2 * i + 1)
#define RIGHT(i) (2 * i + 2)
#define PARENT(i) ((i - 1) / 2)
#define MAX_CONTENT_LEN 1024

// https://en.wikipedia.org/wiki/Binary_heap

typedef struct {
	void *nodes[MAX_NODES];
	int size;
	int (*cmp)(void *, void *);
} Heap;

void heap_init(Heap *heap, int (*cmp)(void *, void *)) {
	heap->size = 0;
	heap->cmp = cmp;
}

void heap_maintain(Heap *heap, int cur) {
	int left = LEFT(cur);
	int right = RIGHT(cur);
	int mx = cur;

	if (left < heap->size &&
	    heap->cmp(heap->nodes[left], heap->nodes[mx]) > 0) {
		mx = left;
	}
	if (right < heap->size &&
	    heap->cmp(heap->nodes[right], heap->nodes[mx]) > 0) {
		mx = right;
	}

	if (mx != cur) {
		void *tmp = heap->nodes[cur];
		heap->nodes[cur] = heap->nodes[mx];
		heap->nodes[mx] = tmp;
		heap_maintain(heap, mx);
	}
}

int heap_insert(Heap *heap, void *node) {
	if (heap->size >= MAX_NODES) {
		return 0;
	}
	heap->nodes[heap->size] = node;
	int cur = heap->size++;
	while (cur != PARENT(cur) &&
	       heap->cmp(heap->nodes[cur], heap->nodes[PARENT(cur)]) > 0) {
		void *tmp = heap->nodes[cur];
		heap->nodes[cur] = heap->nodes[PARENT(cur)];
		heap->nodes[PARENT(cur)] = tmp;
		cur = PARENT(cur);
	}
	return 1;
}

void *heap_pop(Heap *heap) {
	if (heap->size == 0) {
		return NULL;
	}
	void *ret = heap->nodes[0];
	heap->nodes[0] = heap->nodes[--heap->size];
	heap_maintain(heap, 0);
	return ret;
}

void *heap_peak(Heap *heap) {
	if (heap->size == 0) {
		return NULL;
	}
	return heap->nodes[0];
}

typedef struct {
	char *content;
	unsigned int len;
	unsigned int price;
} Present;

Present *new_present() {
	unsigned int len;
	printf("Length: ");
	scanf("%u%*c", &len);
	if (len > MAX_CONTENT_LEN) {
		puts("Too long");
		return NULL;
	}
	Present *present = malloc(sizeof(Present));
	present->len = len;
	present->content = malloc(len);
	printf("Content: ");
	read(0, present->content, len);
	printf("Price: ");
	scanf("%u", &present->price);
	return present;
}

void free_present(Present *present) {
	if (present != NULL) {
		free(present->content);
		free(present);
	}
}

void print_present(Present *present) {
	if (present == NULL) {
		puts("No present");
	} else {
		printf("Content: %.*s\n", present->len, present->content);
		printf("Price: %d\n", present->price);
	}
}

int present_cmp(Present *a, Present *b) {
	return a->price - b->price;
}

void init() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
}

void greetings() {
	puts("Marry Christmas!");
	puts("Welcome to the new Christmas tree system!");
	system("date");
}

int menu() {
	puts("=== Menu ===");
	puts("1. Add a present");
	puts("2. Take a look at the best present");
	puts("3. Take the best present");
	puts("4. Exit");
	printf("> ");
	int choice;
	scanf("%d%*c", &choice);
	return choice;
}

int main() {
	init();
	greetings();
	Heap *tree = malloc(sizeof(Heap));
	heap_init(tree, (int (*)(void *, void *))present_cmp);
	while (1) {
		switch (menu()) {
			case 1: {
				Present *present = new_present();
				if (present != NULL) {
					if (!heap_insert(tree, present)) {
						puts("Tree is full");
						free_present(present);
					}
				} else {
					puts("Failed to add present");
				}
				continue;
			}
			case 2: {
				print_present(heap_peak(tree));
				continue;
			}
			case 3: {
				Present *present = heap_pop(tree);
				print_present(present);
				free_present(present);
				continue;
			}
			case 4: {
				free(tree);
				break;
			}
			default: {
				puts("Invalid choice");
				continue;
			}
		}
	}
	return 0;
}
