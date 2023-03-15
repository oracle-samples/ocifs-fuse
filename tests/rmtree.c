/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

/*
 * rmtree Test Utility Command.
 *
 * Provides a CLI to exercice the rmtree interfaces provided
 * by libutils.
 */

#include <stdio.h>

#include "utils.h"

int main(int argc, char *argv[])
{
	char *prefix;
	char *dir;
	int err;

	if (argc == 2) {
		prefix = NULL;
		dir = argv[1];
	} else if (argc == 3) {
		prefix = argv[1];
		dir = argv[2];
	} else {
		printf("test_rmtree [<root_prefix>] <dir>\n");
		return 2;
	}

	if (prefix)
		rmtree_set_root_prefix(prefix);

	err = rmtree(dir);
	if (err) {
		perror("rmtree");
		return 1;
	}

	return 0;
}
