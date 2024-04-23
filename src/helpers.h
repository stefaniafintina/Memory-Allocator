#pragma once
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define DIE(assertion, call_description)						\
	do {										\
		if (assertion) {							\
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);		\
			perror(call_description);					\
			exit(errno);							\
		}									\
	} while (0)

struct block_meta {
	size_t size;
	int status;
	struct block_meta *prev;
	struct block_meta *next;
};
