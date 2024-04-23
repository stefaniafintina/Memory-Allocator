#pragma once
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "helpers.h"
#include "functions.h"

#define threshold (128 * 1024)
#define STATUS_FREE   0
#define STATUS_ALLOC  1
#define STATUS_MAPPED 2

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
