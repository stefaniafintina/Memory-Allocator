// SPDX-License-Identifier: BSD-3-Clause
#include <stdio.h>
#include "osmem.h"
#include "helpers.h"

struct block_meta *list_mmap;
struct block_meta *list_brk;
static int init;

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	size_t total_size = padded(sizeof(struct block_meta)) + padded(size);
	void *start;
	struct block_meta *block;

	if (size == 0)
		return NULL;
	if (total_size > threshold) {
		start = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(start == MAP_FAILED, "mmap failed");
		block = (struct block_meta *)start;
		block->status = STATUS_MAPPED;
		block->size = padded(size);
		add_node(&list_mmap, block);
		return (void *)(block + 1);
	}
	if (init == 0) {
		init = 1;
		start = sbrk(threshold);
		DIE(start == MAP_FAILED, "sbrk failed");
		struct block_meta *new = (struct block_meta *)((char *)start + total_size);

		block = (struct block_meta *)start;
		if (threshold >= total_size + padded(sizeof(struct block_meta)) + padded(1)) {
			new->size = threshold - total_size - padded(sizeof(struct block_meta));
			new->status = STATUS_FREE;
			block->next = NULL;
			new->next = NULL;
			block->status = STATUS_ALLOC;
			block->size = padded(size);
			add_node(&list_brk, block);
			add_node(&list_brk, new);
			return (void *)(block + 1);
		}
		block->status = STATUS_ALLOC;
		block->size = padded(size);
		add_node(&list_brk, block);

		return (void *)(block + 1);
	}
	coalesce_blocks(&list_brk);
	struct block_meta *free_space = find_free_space(list_brk, total_size);

	if (free_space == NULL) {
		struct block_meta *last_block = list_brk;

		while (last_block->next)
			last_block = last_block->next;
		if (last_block->status == STATUS_FREE) {
			size_t remaining_size = padded(size) - padded(last_block->size);

			start = sbrk(remaining_size);
			DIE(start == MAP_FAILED, "sbrk failed");
			block = (struct block_meta *)start;
			last_block->status = STATUS_ALLOC;
			last_block->size = padded(size);
			return (void *)(last_block + 1);
		}

		start = sbrk(padded(total_size));
		DIE(start == MAP_FAILED, "sbrk failed");
		block = (struct block_meta *)start;
		block->status = STATUS_ALLOC;
		add_node(&list_brk, block);
		block->size = padded(size);
		return (void *)(block + 1);
	}
	split(&list_brk, free_space, total_size);
	free_space->status = STATUS_ALLOC;
	return (void *)(free_space + 1);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */

	if (ptr == NULL)
		return;

	if (find_block(list_mmap, ptr)) {
		remove_node(&list_mmap, ptr);
		munmap((char *)ptr - padded(sizeof(struct block_meta)), ((struct block_meta *)((char *)ptr -
				padded(sizeof(struct block_meta))))->size + padded(sizeof(struct block_meta)));
		return;
	}
	if (find_block(list_brk, ptr)) {
		struct block_meta *list = list_brk;

		while (list) {
			if ((void *)(list + 1) == ptr) {
				list->status = STATUS_FREE;
				coalesce_blocks(&list_brk);
				return;
			}
			list = list->next;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size = size * nmemb;
	/* TODO: Implement os_calloc */
	size_t total_size = padded(sizeof(struct block_meta)) + padded(size);
	void *start;
	struct block_meta *block;

	if (size == 0)
		return NULL;
	if (total_size > (size_t)getpagesize()) {
		start = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(start == MAP_FAILED, "mmap failed");
		block = (struct block_meta *)start;
		block->status = STATUS_MAPPED;
		block->size = padded(size);
		add_node(&list_mmap, block);
		memset((void *)(block + 1), 0, size);
		return (void *)(block + 1);
	}

	if (init == 0) {
		init = 1;
		start = sbrk(threshold);
		DIE(start == MAP_FAILED, "sbrk failed");

		struct block_meta *new = (struct block_meta *)((char *)start + total_size);

		block = (struct block_meta *)start;
		if ((size_t)getpagesize() >= total_size + padded(sizeof(struct block_meta)) + padded(1)) {
			new->size = getpagesize() - total_size - padded(sizeof(struct block_meta));

			new->status = STATUS_FREE;
			block->next = NULL;
			new->next = NULL;
			block->status = STATUS_ALLOC;
			block->size = padded(size);
			add_node(&list_brk, block);
			add_node(&list_brk, new);
			memset((void *)(block + 1), 0, size);
			return (void *)(block + 1);
		}
		block->status = STATUS_ALLOC;
		block->size = padded(size);
		add_node(&list_brk, block);
		memset((void *)(block + 1), 0, size);
		return (void *)(block + 1);
	}
	coalesce_blocks(&list_brk);
	struct block_meta *free_space = find_free_space(list_brk, total_size);

	if (free_space == NULL) {
		struct block_meta *last_block = list_brk;

		while (last_block->next)
			last_block = last_block->next;
		if (last_block->status == STATUS_FREE) {
			size_t remaining_size = padded(size) - padded(last_block->size);

			start = sbrk(remaining_size);
			DIE(start == MAP_FAILED, "sbrk failed");
			block = (struct block_meta *)start;
			last_block->status = STATUS_ALLOC;
			last_block->size = padded(size);
			memset((void *)(last_block + 1), 0, size);
			return (void *)(last_block + 1);
		}
		start = sbrk(padded(total_size));
		DIE(start == MAP_FAILED, "sbrk failed");
		block = (struct block_meta *)start;
		block->status = STATUS_ALLOC;
		add_node(&list_brk, block);
		block->size = padded(size);
		memset((void *)(block + 1), 0, size);
		return (void *)(block + 1);
	}
	split(&list_brk, free_space, total_size);
	free_space->status = STATUS_ALLOC;
	memset((void *)(free_space + 1), 0, size);
	return (void *)(free_space + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (size == 0 && ptr == NULL) {
		return NULL;
	} else if (size == 0) {
		os_free(ptr);
		coalesce_blocks(&list_brk);
		return NULL;
	}
	if (ptr == NULL)
		return os_malloc(size);
	if (((struct block_meta *)ptr - 1)->size == (size_t)padded(size))
		return ptr;
	if (!(find_block(list_brk, ptr) || find_block(list_mmap, ptr)))
		return NULL;
	if (find_block(list_brk, ptr) && ((struct block_meta *)ptr - 1)->status == STATUS_FREE)
		return NULL;
	if (((struct block_meta *)ptr - 1)->size  > threshold) {
		void *start = os_malloc(size);
		size_t cpy_size = ((size_t)padded(size) < ((struct block_meta *)ptr - 1)->size) ?
						  (size_t)padded(size) : ((struct block_meta *)ptr - 1)->size;

		memcpy(start, ptr, cpy_size);
		os_free(ptr);
		return start;
	}
	if (padded(size) < threshold) {
		if ((size_t)padded(size) < ((struct block_meta *)ptr - 1)->size) {
			if (((struct block_meta *)ptr - 1)->size - (size_t)padded(size) >= (size_t)padded(1) +
				padded(sizeof(struct block_meta))) {
				struct block_meta *new = (struct block_meta *)(ptr + padded(size));

				new->status = STATUS_FREE;
				new->size  = ((struct block_meta *)ptr - 1)->size - padded(size) - padded(sizeof(struct block_meta));
				new->next = ((struct block_meta *)ptr - 1)->next;
				((struct block_meta *)ptr - 1)->size = padded(size);
				((struct block_meta *)ptr - 1)->status = STATUS_ALLOC;
				((struct block_meta *)ptr - 1)->next = new;
				coalesce_blocks(&list_brk);
			}
			return ptr;
		}

		if (((struct block_meta *)ptr - 1)->next && ((struct block_meta *)ptr - 1)->next->status == STATUS_FREE) {
			if (((struct block_meta *)ptr - 1)->size + ((struct block_meta *)ptr - 1)->next->size +
				(size_t)padded(sizeof(struct block_meta)) >= (size_t)padded(size)) {
				size_t remaining_size = padded(size) - ((struct block_meta *)ptr - 1)->size;

				if (((struct block_meta *)ptr - 1)->next->size >= (size_t)padded(remaining_size) + padded(1)) {
					((struct block_meta *)ptr - 1)->size = padded(size);
					size_t old_free_size = ((struct block_meta *)ptr - 1)->next->size;
					struct block_meta *old_next_next = ((struct block_meta *)ptr - 1)->next->next;
					((struct block_meta *)ptr - 1)->next = (struct block_meta *)((char *)ptr + padded(size));
					((struct block_meta *)ptr - 1)->next->size = old_free_size - padded(remaining_size);
					((struct block_meta *)ptr - 1)->next->status = STATUS_FREE;
					((struct block_meta *)ptr - 1)->next->next = old_next_next;

					coalesce_blocks(&list_brk);
				} else {
					((struct block_meta *)ptr - 1)->size += (((struct block_meta *)ptr - 1)->next->size +
															 padded(sizeof(struct block_meta)));

					remove_node(&list_brk, ((struct block_meta *)ptr - 1)->next + 1);
					coalesce_blocks(&list_brk);
				}
				return ptr;
			}
		}
		size_t total_size = padded(size) + padded(sizeof(struct block_meta));

		if (((struct block_meta *)ptr - 1)->next == NULL) {
			size_t remaining_size = padded(size) - ((struct block_meta *)ptr - 1)->size;
			void *start = sbrk(remaining_size);

			DIE(start == MAP_FAILED, "sbrk failed");
			((struct block_meta *)ptr - 1)->status = STATUS_ALLOC;
			((struct block_meta *)ptr - 1)->size = padded(size);
			return ptr;
		}
		struct block_meta *neww = find_best_fit(list_brk, total_size);

		if (neww) {
			split(&list_brk, neww, total_size);
			coalesce_blocks(&list_brk);
			neww->status = STATUS_ALLOC;
			memcpy((void *)(neww + 1), ptr, ((struct block_meta *)ptr - 1)->size);
			os_free(ptr);
			coalesce_blocks(&list_brk);
			return (void *)(neww + 1);
		}

		struct block_meta *new = (struct block_meta *)sbrk(total_size);

		new->size = padded(size);
		new->status = STATUS_ALLOC;
		new->next = NULL;
		add_node(&list_brk, new);
		memcpy((void *)(new + 1), ptr, ((struct block_meta *)ptr - 1)->size);
		os_free(ptr);
		coalesce_blocks(&list_brk);
		return (void *)(new + 1);
	}
	void *new = os_malloc(size);

	memcpy(new, ptr, ((struct block_meta *)ptr - 1)->size);
	os_free(ptr);
	coalesce_blocks(&list_brk);
	return new;
}
