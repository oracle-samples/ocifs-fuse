/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <stdlib.h>

#include <sys/types.h>

#include "utils.h"

#define RLIST_WALK_CALLB(callb, begin, end, overlap, data)	\
	do {							\
		int rv;						\
		rv = (callb)(begin, end, overlap, data);	\
		if (rv < 0)					\
			return -1;				\
		if (rv == RANGE_WALK_DONE)			\
			return 0;				\
	} while (0)

int range_list_walk_range(struct range_list *range_list,
			   off_t offset, size_t size,
			   range_list_walk_cb callb, void *data)
{
	off_t begin = offset;
	off_t end = offset + size - 1;
	struct range *r;

	/*
	 * Find the first range from the list which overlaps with
	 * [begin, end]
	 */
	for (r = range_list->range; r; r = r->next) {
		if (begin <= r->end && end >= r->begin)
			break;
	}

	if (!r) {
		/* no overlap */
		RLIST_WALK_CALLB(callb, begin, end, RANGE_OVERLAP_FALSE, data);
		return 0;
	}

	/*
	 * Check if [begin, end] starts inside the range it overlaps
	 * with.
	 */
	if (begin >= r->begin) {
		if (end <= r->end) {
			RLIST_WALK_CALLB(callb, begin, end, RANGE_OVERLAP_TRUE,
					 data);
			return 0;
		}
		RLIST_WALK_CALLB(callb, begin, r->end, RANGE_OVERLAP_TRUE,
				 data);
		begin = r->end + 1;
		r = r->next;
	}

	while (r && end >= r->begin) {
		/*
		 * At this point, we have begin < r->begin and
		 * [begin, end] overlaps with r = [r->begin, r->end]
		 */
		RLIST_WALK_CALLB(callb, begin, r->begin - 1,
				 RANGE_OVERLAP_FALSE, data);
		if (end <= r->end) {
			RLIST_WALK_CALLB(callb, r->begin, end,
					 RANGE_OVERLAP_TRUE, data);
			return 0;
		}
		RLIST_WALK_CALLB(callb, r->begin, r->end, RANGE_OVERLAP_TRUE,
				 data);
		begin = r->end + 1;
		r = r->next;
	}

	/* no more range to overlap with */
	RLIST_WALK_CALLB(callb, begin, end, RANGE_OVERLAP_FALSE, data);

	return 0;
}

/*
 * Safe version of range_list_walk_range() to be used if the callback
 * can modify range_list. This function will be range_list and then
 * walk the range_list copy.
 */
int range_list_walk_range_safe(struct range_list *range_list,
			       off_t offset, size_t size,
			       range_list_walk_cb callb, void *data)
{
	struct range_list rlist_copy;
	struct range *r;
	int count;
	int rv;
	int i;

	if (!range_list)
		return 0;

	count = 0;
	for (r = range_list->range; r; r = r->next)
		count++;

	if (count) {
		rlist_copy.range = calloc(count, sizeof(struct range));
		if (!rlist_copy.range)
			return -1;

		i = 0;
		for (r = range_list->range; r; r = r->next) {
			rlist_copy.range[i].begin = r->begin;
			rlist_copy.range[i].end = r->end;
			if (r->next)
				rlist_copy.range[i].next = &rlist_copy.range[i + 1];
			else
				rlist_copy.range[i].next = NULL;
		}
	} else {
		rlist_copy.range = NULL;
	}

	rv = range_list_walk_range(&rlist_copy, offset, size,
				   callb, data);

	free(rlist_copy.range);

	return rv;
}

void range_list_init(struct range_list *range_list)
{
	range_list->range = NULL;
}

void range_list_fini(struct range_list *range_list)
{
	struct range *r, *next;

	if (!range_list)
		return;

	for (r = range_list->range; r; r = next) {
		next = r->next;
		free(r);
	}

	range_list->range = NULL;
}

void range_list_clear(struct range_list *range_list)
{
	range_list_fini(range_list);
}

struct range_list *range_list_create(void)
{
	struct range_list *range_list;

	range_list = malloc(sizeof(*range_list));
	range_list_init(range_list);

	return range_list;
}

void range_list_destroy(struct range_list *range_list)
{
	range_list_fini(range_list);
	free(range_list);
}

int range_list_add(struct range_list *range_list, off_t offset, size_t size)
{
	struct range *r, *n, *next, *range, **prev_nextp;
	size_t begin = offset;
	size_t end = offset + size - 1;

	prev_nextp = &range_list->range;
	r = range_list->range;

	while (r) {

		if (begin > r->end + 1) {
			prev_nextp = &r->next;
			r = r->next;
			continue;
		}

		if (end + 1 < r->begin) {

			/* insert new range before current range */

			range = malloc(sizeof(*range));
			if (!range)
				return -1;

			range->begin = begin;
			range->end = end;
			range->next = r;

			*prev_nextp = range;

			return 0;
		}

		if (begin < r->begin)
			r->begin = begin;

		if (end <= r->end)
			return 0;

		for (n = r->next; n; n = next) {
			if (end + 1 < n->begin) {
				r->end = end;
				return 0;
			}

			r->next = n->next;

			if (end <= n->end) {
				r->end = n->end;
				free(n);
				return 0;
			}

			next = n->next;
			free(n);
		}

		r->end = end;
		return 0;
	}

	/* add new range after last range */

	range = malloc(sizeof(*range));
	if (!range)
		return -1;

	range->begin = begin;
	range->end = end;
	range->next = NULL;

	*prev_nextp = range;

	return 0;
}

/*
 * Truncate the range list at the specified offset.
 */
void range_list_truncate(struct range_list *range_list, off_t offset)
{
	struct range *r, *next, **prev_nextp;

	/* find the first range which is beyond 'offset' */
	prev_nextp = &range_list->range;
	for (r = range_list->range; r; r = r->next) {
		if (r->begin > offset) {
			*prev_nextp = NULL;
			break;
		}
		if (r->end > offset) {
			r->end = offset;
			next = r->next;
			r->next = NULL;
			r = next;
			break;
		}
		prev_nextp = &r->next;
	}

	if (!r)
		return;

	/* remove ranges beyond 'offset' */
	for ( ; r; r = next) {
		next = r->next;
		free(r);
	}
}
