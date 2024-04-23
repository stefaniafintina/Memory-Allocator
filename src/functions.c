// SPDX-License-Identifier: BSD-3-Clause
#include "functions.h"

int padded(size_t size)
{
	if (size % 8)
		return (size / 8 + 1) * 8;
	return size;
}

void coalesce_blocks(struct block_meta **list_brk)
{
	struct block_meta *list = *list_brk;

	if (list) {
		while (list->next) {
			if (list->status == STATUS_FREE && list->next->status == STATUS_FREE) {
				list->size += (list->next->size + padded(sizeof(struct block_meta)));
				list->next = list->next->next;
			} else {
				list = list->next;
			}
		}
	}
}

struct block_meta *find_free_space(struct block_meta *list_brk, size_t total_size)
{
	while (list_brk) {
		if (list_brk->status == STATUS_FREE && list_brk->size + padded(sizeof(struct block_meta)) >= total_size)
			return list_brk;
		list_brk = list_brk->next;
	}
	return NULL;
}

void add_node(struct block_meta **list_mmap, struct block_meta *block)
{
	if (*list_mmap == NULL) {
		*list_mmap = block;
		(*list_mmap)->next = NULL;
	} else {
		struct block_meta *list = *list_mmap;

		while (list->next)
			list = list->next;
		list->next = block;
		block->next = NULL;
	}
}

int find_block(struct block_meta *list_mmap, void *address)
{
	while (list_mmap) {
		if ((void *)(list_mmap + 1) == address)
			return 1;
		list_mmap = list_mmap->next;
	}
	return 0;
}

void remove_node(struct block_meta **list_mmap, void *ptr)
{
	struct block_meta *list = *list_mmap;

	if ((void *)(list + 1) == ptr) {
		*list_mmap = list->next;
		return;
	}
	struct block_meta *prev = list;

	list = list->next;
	while (list) {
		if ((void *)(list + 1) == ptr) {
			prev->next = list->next;
			return;
		}
		prev = list;
		list = list->next;
	}
}

void split(struct block_meta **list_brk, struct block_meta *free_space, size_t total_size)
{
	struct block_meta *list = *list_brk;

	while (list) {
		if (list == free_space) {
			if (list->size + 32 >= total_size  && list->size >= padded(1) + total_size) {
				size_t new_size = list->size - total_size;
				struct block_meta *new = (struct block_meta *)((char *)list + total_size);

				new->status = STATUS_FREE;
				new->size = new_size;
				new->next = list->next;
				list->next = new;
				list->size = total_size - padded(sizeof(struct block_meta));
				list->status = STATUS_ALLOC;
				return;
			}
			list->status = STATUS_ALLOC;
		}
		list = list->next;
	}
}


struct block_meta *find_best_fit(struct block_meta *list_brk, size_t total_size)
{
	size_t minim = 9999999;
	struct block_meta *ptr = NULL;

	while (list_brk) {
		if (list_brk->status == STATUS_FREE && list_brk->size + padded(sizeof(struct block_meta)) >= total_size) {
			if (list_brk->size + padded(sizeof(struct block_meta)) < minim)  {
				minim = list_brk->size + padded(sizeof(struct block_meta));
				ptr = list_brk;
			}
		}
		list_brk = list_brk->next;
	}
	return ptr;
}
