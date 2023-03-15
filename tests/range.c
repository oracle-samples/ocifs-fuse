/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

/*
 * Range Test Utility Command.
 *
 * Provides a CLI to exercice the range_list interfaces provided
 * by libutils.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#include "utils.h"

static int parse_range(const char *range_str, off_t *begin, off_t *end)
{
	int count;

	count = sscanf(range_str, "[%jd,%jd]", begin, end);
	if (count != 2)
		return -1;

	if (*end < *begin)
		return -1;

	return 0;
}

static void print_range_list(struct range_list *range_list)
{
	struct range *r;

	for (r = range_list->range; r; r = r->next)
		printf("[%jd,%jd] ", r->begin, r->end);

	printf("\n");
}

static int walk_print_range(off_t begin, off_t end, enum range_overlap overlap,
		     void *data)
{
	if (overlap)
		printf("[");
	printf("[%jd,%jd]", begin, end);
	if (overlap)
		printf("]");
	printf(" ");

	return RANGE_WALK_CONTINUE;
}

static void usage(void)
{
	printf("Usage: range <range> ... [walk <range>]\n");
}

int main(int argc, char *argv[])
{
	struct range_list *range_list;
	off_t begin, end;
	int length, i, err;

	if (argc < 2) {
		usage();
		return 2;
	}

	range_list = range_list_create();
	if (!range_list) {
		printf("Failed to create range list\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		err = parse_range(argv[i], &begin, &end);
		if (err)
			break;
		printf("adding [%jd,%jd]\n", begin, end);
		range_list_add(range_list, begin, end - begin + 1);
		printf("list : ");
		print_range_list(range_list);
		printf("\n");
	}

	if (i >= argc)
		goto done;

	if (strcmp(argv[i], "walk") == 0) {
		i++;
		if (i + 1 != argc) {
			usage();
			return 2;
		}
		err = parse_range(argv[i], &begin, &end);
		if (err) {
			printf("Invalid range '%s'\n", argv[i]);
			range_list_destroy(range_list);
			return 1;
		}
		printf("walking [%jd,%jd] in ", begin, end);
		print_range_list(range_list);
		range_list_walk_range(range_list, begin, end - begin + 1,
				      walk_print_range, NULL);
		printf("\n");

	} else if (strcmp(argv[i], "truncate") == 0) {
		i++;
		if (i + 1 != argc) {
			usage();
			return 2;
		}
		length = atoi(argv[i]);
		printf("truncate to %d\n", length);
		range_list_truncate(range_list, length);
		print_range_list(range_list);

	} else {
		printf("Invalid range '%s'\n", argv[i]);
		range_list_destroy(range_list);
		return 1;
	}

done:
	range_list_destroy(range_list);

	return 0;
}
