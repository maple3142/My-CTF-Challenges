#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

// copied from bash
typedef struct word_desc {
	char *word; /* Zero terminated string. */
	int flags;  /* Flags associated with this word. */
} WORD_DESC;

typedef struct word_list {
	struct word_list *next;
	WORD_DESC *word;
} WORD_LIST;

struct builtin {
	char *name;                       /* The name that the user types. */
	int (*function)(WORD_LIST *list); /* The address of the invoked function. */
	int flags;                        /* One of the #defines above. */
	char *const *long_doc;            /* NULL terminated array of strings. */
	const char *short_doc;            /* Short version of documentation. */
	char *handle;                     /* for future use */
};

extern char **environ;

int run_builtin(WORD_LIST *list) {
	char *argc[256];
	int i = 0;
	while (list) {
		// puts(list->word->word);
		argc[i++] = list->word->word;
		list = list->next;
	}
	argc[i] = 0;
	pid_t pid = fork();
	if (pid == -1) {
		return -1;
	}
    int status;
	if (pid == 0) {
		syscall(SYS_execveat, 0, argc[0], argc, environ, 0);
	} else {
        waitpid(pid, &status, 0);
	}
	return status;
}

char *doc_str[] = {"run", (char *)NULL};

struct builtin run_struct = {"run", run_builtin, 1, doc_str, "run", 0};
