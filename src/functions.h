#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "helpers.h"
#include "osmem.h"

int padded(size_t size);

void add_node(struct block_meta **list_mmap, struct block_meta *block);

int find_block(struct block_meta *list_mmap, void *address);

void remove_node(struct block_meta **list_mmap, void *ptr);

void coalesce_blocks(struct block_meta **list_brk);

struct block_meta *find_free_space(struct block_meta *list_brk, size_t total_size);

void split(struct block_meta **list_brk, struct block_meta *free_space, size_t total_size);

struct block_meta *find_best_fit(struct block_meta *list_brk, size_t total_size);
