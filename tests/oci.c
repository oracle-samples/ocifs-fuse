/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

/*
 * OCI Test Utility Command.
 *
 * Provides a CLI to exercice the OCI API provided by liboci.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "oci.h"
#include "utils.h"

static int oci_init(struct oci_config **configp,
		    char *cmd_name, bool instance_principal,
		    char *region, char *cfgfile, char *bucket,
		    int debug)
{
	struct oci_config *config;
	int err;

	if (strcmp(cmd_name, "imds_get") == 0) {
		/*
		 * IMDS requests do not need a config, but we create
		 * an empty config to just configure debug.
		 */
		config = oci_config_create_empty(debug);
		if (!config) {
			printf("Failed to create empty config\n");
			return -1;
		}
		*configp = config;
		return 0;
	}

	if (strcmp(cmd_name, "config") == 0) {
		printf("Config from %s:\n", cfgfile);
		printf("\n");
	} else if (strcmp(cmd_name, "head_bucket") == 0) {
		if (bucket) {
			printf("Option --bucket is not compatible with "
			       "the head_bucket command\n");
			return 2;
		}
	} else if (!bucket) {
		printf("No OCI Object Storage bucket is provided.\n");
		return 2;
	}

	if (instance_principal)
		config = oci_config_instance_principal(region, NULL, debug);
	else
		config = oci_config_create_from_file(cfgfile, region, NULL,
						     debug);

	if (!config) {
		printf("Failed to create config\n");
		return -1;
	}

	config->debug = debug;

	err = oci_config_init_object_storage(config, bucket);
	if (err) {
		printf("Failed to init Object Storage\n");
		oci_config_destroy(config);
		return -1;
	}

	*configp = config;

	return 0;
}

static int write_file(char *filename, char *buf, size_t size)
{
	int fd, count;

	/* write read object to file */
	fd = open(filename, O_CREAT | O_WRONLY, 0644);
	if (fd == -1) {
		perror("open");
		return -1;
	}

	count = write(fd, buf, size);
	if (count == -1) {
		perror("write");
		return 1;
	}

	if (count != size)
		printf("write %d/%zd\n", count, size);

	printf("\n");

	close(fd);

	return 0;
}

static int cmd_head_bucket(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	struct oci_os_bucket_head bucket;
	char *bucket_name;
	int err;

	if (argc != 1)
		return 2;

	bucket_name = argv[0];

	err = oci_os_head_bucket(config, bucket_name, &bucket, &error);
	if (err) {
		printf("Failed to get head of bucket '%s'\n", bucket_name);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	printf("Bucket %s:\n", bucket_name);
	printf("  etag: %s\n", bucket.etag);

	oci_os_bucket_head_fini(&bucket);

	return 0;
}

static int cmd_head_object(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	struct oci_os_object_head object;
	char *object_name;
	char date[64];
	int err;

	if (argc != 1)
		return 2;

	object_name = argv[0];

	err = oci_os_head_object(config, object_name, &object, &error);
	if (err) {
		printf("Failed to get head of object '%s'\n", object_name);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	printf("Object %s:\n", object_name);
	printf("  etag: %s\n", object.etag);
	printf("  content_length: %zd\n", object.content_length);
	strftime(date, 64, "%Y-%m-%d %H:%M:%S %z", &object.last_modified);
	printf("  last_modified: %s\n", date);

	oci_os_object_head_fini(&object);

	return 0;
}

static int cmd_list_objects(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	struct oci_os_list_objects_param param = { 0 };
	struct oci_os_list_objects list_objects;
	struct oci_os_object_summary *objects;
	char date[64], *next;
	int i, count, total;
	bool all, verbose;
	char **prefixes;
	char *start;
	int ptotal;
	int opt;

	/* reset arguments so that we can reuse getopt() */
	argv--;
	argc++;
	optind = 1;

	start = NULL;
	all = false;
	verbose = false;
	while ((opt = getopt(argc, argv, "ad:e:f:l:p:s:v")) != -1) {
		switch (opt) {
		case 'a':
			/* list all objects (use paging) */
			all = true;
			break;
		case 'd':
			param.delimiter = optarg;
			break;
		case 'e':
			param.end = optarg;
			break;
		case 'f':
			param.fields = optarg;
			break;
		case 'l':
			param.limit = atoi(optarg);
			break;
		case 'p':
			param.prefix = optarg;
			break;
		case 's':
			start = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		return 2;

	if (start) {
		/*
		 * strdup() start because it will be freed
		 * for paging.
		 */
		param.start = strdup(start);
	}

	if (verbose)
		param.fields = "size,timeCreated,timeModified,etag";

	total = 0;
	ptotal = 0;

	printf("\n");

	while (1) {

		printf("S %s\n", param.start);

		count = oci_os_list_objects(config, &list_objects, &param,
					    &error);
		free(param.start);
		if (count < 0) {
			printf("Failed to list objects\n");
			oci_error_print(&error);
			oci_error_fini(&error);
			return 1;
		}

		objects = list_objects.objects;

		for (i = 0; i < count; i++) {
			printf("O %s\n", objects[i].name);
			if (!verbose)
				continue;
			printf("  size: %zd\n", objects[i].size);
			printf("  etag: %s\n", objects[i].etag);
			strftime(date, 64, "%Y-%m-%d %H:%M:%S %z",
				 &objects[i].created);
			printf("  created:  %s\n", date);
			strftime(date, 64, "%Y-%m-%d %H:%M:%S %z",
				 &objects[i].modified);
			printf("  modified: %s\n", date);
		}

		total += count;

		prefixes = list_objects.prefixes;
		count = list_objects.prefixes_count;
		ptotal += count;

		for (i = 0; i < count; i++)
			printf("P %s\n", prefixes[i]);

		next = list_objects.next_start_with;

		printf("N %s\n", next);

		if (!next || !all)
			break;

		param.start = strdup(next);
		oci_os_list_objects_fini(&list_objects);
		printf("\n");
	}

	oci_os_list_objects_fini(&list_objects);

	printf("\n");
	printf("------------\n");
	printf("S = Start\n");
	printf("O = Object\n");
	printf("P = Prefix\n");
	printf("N = Next\n");
	printf("------------\n");
	printf("\n");

	printf("Total: %d Objects, %d Prefixes\n\n", total, ptotal);

	return 0;
}

static int cmd_list_object(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	struct oci_os_object_summary obj;
	char *object_name;
	int count;

	if (argc != 1)
		return 2;

	object_name = *argv++;

	count = oci_os_list_object(config, object_name, &obj, &error);
	if (count < 0) {
		printf("Failed to list object %s\n", object_name);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	if (count == 0) {
		printf("Object %s not found\n", object_name);
	} else {
		printf("Object %s:\n", object_name);
		printf("  name: %s\n", obj.name);
		printf("  size: %zd\n", obj.size);
		printf("\n");
	}

	oci_os_object_summary_fini(&obj);

	return 0;
}

static int cmd_delete_object(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	char *object_name;
	int err;

	if (argc != 1)
		return 2;

	object_name = *argv++;

	err = oci_os_delete_object(config, object_name, &error);
	if (err) {
		printf("Failed to delete object %s\n", object_name);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	printf("Object %s deleted\n", object_name);

	return 0;
}

static int cmd_rename_object(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	char *old_name;
	char *new_name;
	int err;

	if (argc != 2)
		return 2;

	old_name = *argv++;
	new_name = *argv++;

	err = oci_os_rename_object(config, old_name, new_name, &error);
	if (err) {
		printf("Failed to rename object %s to %s\n",
		       old_name, new_name);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	printf("Object %s renamed to %s\n", old_name, new_name);

	return 0;
}

static int cmd_get_object(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	struct oci_os_get_object_param param = { 0 };
	char *object_name;
	size_t start, len;
	char *filename;
	size_t size;
	char *buf;
	int err;

	if (argc < 2 || argc > 4)
		return 2;

	object_name = *argv++;
	filename = *argv++;

	start = 0;
	len = 0;

	if (argc >= 3) {
		start = atol(*argv++);
		if (argc >= 4)
			len = atol(*argv++);
	}

	buf = NULL;
	size = 0;

	param.range_start = start;
	param.range_size = len;

	err = oci_os_get_object(config, object_name, &buf, &size, &param,
				&error);
	if (err) {
		printf("Failed to get object %s\n", object_name);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	printf("Get object %s", filename);

	if (len > 0)
		printf(" (offset=%zd, size=%zu)", start, len);

	if (filename) {
		printf(" to file %s (%zu bytes)\n", filename, size);

		if (write_file(filename, buf, size) < 0) {
			free(buf);
			return 1;
		}

	} else {
		printf(":\n\n%.*s\n\n", (int)size, buf);
	}

	free(buf);
	return 0;
}

static int cmd_put_object(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	char *object_name, *filename;
	int err, fd;

	if (argc < 1)
		return 2;

	object_name = *argv++;

	if (argc == 1)
		filename = NULL;
	else if (argc == 2)
		filename = *argv++;
	else
		return 2;

	if (!filename) {

		printf("Put object %s (empty)\n", object_name);

		err = oci_os_put_object(config, object_name, NULL, 0, &error);

	} else {
		fd = open(filename, O_RDONLY);
		if (fd == -1) {
			printf("Failed to open %s: %s\n",
			       filename, strerror(errno));
			return 1;
		}

		printf("Put object %s from file %s\n", object_name, filename);

		err = oci_os_put_object_from_file(config, object_name, fd,
						  &error);
	}

	if (err) {
		printf("Failed to put object %s\n", object_name);
		if (filename)
			close(fd);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	if (filename)
		close(fd);

	return 0;
}

static int cmd_imds_get(struct oci_config *config, int argc, char *argv[])
{
	struct oci_error error = OCI_ERROR_INIT_DEBUG;
	char *result;
	char *path;

	if (argc != 1)
		return 2;

	path = argv[0];

	result = oci_imds_get_str(config, path, &error);
	if (!result) {
		printf("Failed to get '%s' from IMDS\n", path);
		oci_error_print(&error);
		oci_error_fini(&error);
		return 1;
	}

	printf("%s: %s\n", path, result);

	free(result);

	return 0;
}

static int cmd_config(struct oci_config *config, int argc, char *argv[])
{
	if (argc != 0)
		return 2;

	printf("  tenancy: %s\n", config->tenancy);
	printf("  user: %s\n", config->user);
	printf("  fingerprint: %s\n", config->fingerprint);
	printf("  domain: %s\n", config->domain);
	printf("  keyfile: %s\n", config->keyfile);
	printf("\n");

	return 0;
}

struct cmd {
	char *name;
	int (*func)(struct oci_config *, int argv, char *arg[]);
	char *param;
};

#define CMD(name, param)	{ #name, cmd_ ## name, param }

static struct cmd cmd_list[] = {
	CMD(head_bucket,	"<bucket>"),
	CMD(head_object,	"<object>"),
	CMD(list_objects,	"[-a] [-d <delimiter>] [-f <fields>] "
				"[-p <prefix>] [-s <start>] [-e <end>] "
				"[-l <limit>] [-v]"),
	CMD(list_object,	"<object>"),
	CMD(delete_object,	"<object>"),
	CMD(rename_object,	"<object_old_name> <object_new_name>"),
	CMD(get_object,		"<object> <file> [<start> [<length>]]"),
	CMD(put_object,		"<object> [<file>]"),
	CMD(imds_get,		"<path>"),
	CMD(config,		""),
};

static void usage(int index)
{
	int i;

	printf("Usage: oci [options] <cmd> <arguments> ...\n");
	printf("\n");
	printf("Options:\n");
	printf("\n");
	printf("    --bucket=<bucket>: OCI Object Storage bucket\n");
	printf("    --config=<config-file>: OCI configuration file\n");
	printf("    --debug: debug\n");
	printf("    --region=<oci-region>: OCI region or domain\n");
	printf("    --instance-principal: call services from instance\n");
	printf("\n");
	printf("Commands:\n");
	printf("\n");

	if (index < 0 || index >= ARRAY_SIZE(cmd_list)) {
		for (i = 0; i < ARRAY_SIZE(cmd_list); i++) {
			printf("    %s %s\n",
			       cmd_list[i].name, cmd_list[i].param);
		}
	} else {
		printf("    %s %s\n",
		       cmd_list[index].name, cmd_list[index].param);
	}

	printf("\n");
}

static struct option long_options[] = {
	{ "bucket", required_argument, 0, 'b' },
	{ "config", required_argument, 0, 'c' },
	{ "debug", no_argument, 0, 'd' },
	{ "region", required_argument, 0, 'r' },
	{ "instance-principal", no_argument, 0, 'i' },
	{ 0 }
};

int main(int argc, char *argv[])
{
	bool instance_principal = false;
	struct oci_config *config;
	char *region = NULL;
	char *bucket = NULL;
	char *cfgfile = NULL;
	int debug = 0, opt;
	char *cmd_name;
	char *cmd;
	int i, rv;

	while ((opt = getopt_long(argc, argv, "+", long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			bucket = optarg;
			break;
		case 'c':
			cfgfile = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'i':
			instance_principal = true;
			break;
		case 'r':
			region = optarg;
			break;
		default:
			usage(-1);
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage(-1);
		return 2;
	}

	cmd = argv[0];
	argv += 1;
	argc -= 1;

	cmd_name = NULL;
	for (i = 0; i < sizeof(cmd_list) / sizeof(struct cmd); i++) {
		if (strcmp(cmd, cmd_list[i].name) == 0) {
			cmd_name = cmd_list[i].name;
			break;
		}
	}

	if (!cmd_name) {
		usage(-1);
		return 2;
	}

	rv = oci_init(&config, cmd_name, instance_principal, region,
		      cfgfile, bucket, debug);
	if (rv) {
		if (rv == 2)
			usage(i);
		return 1;
	}

	rv = (cmd_list[i].func)(config, argc, argv);
	if (rv == 2)
		usage(i);

	if (config != (struct oci_config *)cfgfile)
		oci_config_destroy(config);

	return rv;
}
