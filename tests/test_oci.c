/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

/*
 * Test OCI functions provided by liboci.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cmocka.h>

#include "oci.h"

static int debug;
static int clean_bucket;
static const char *bucket_name;
static const char *config_filename = NULL;
static struct oci_config *oci_config;

#define OBJECT_NONE "none"

#define OBJECT1_NAME "object1"
#define OBJECT1_SIZE 1024
static int object1_size = OBJECT1_SIZE;
static char object1_data[OBJECT1_SIZE];

#define OBJECT2_NAME "object2"
#define OBJECT2_SIZE (100 * 1024)
static int object2_size = OBJECT2_SIZE;
#define OBJECT2_DATA "object2.data"
#define OBJECT2_READ "object2.read"

#define OBJECT3_NAME "object3"
#define OBJECT4_NAME "object4"

/*
 * Delete all objects present in the bucket.
 */
static int clear_bucket(struct oci_config *config)
{
	struct oci_os_list_objects_param param = { 0 };
	struct oci_os_list_objects list_objects;
	char *next;
	char *name;
	int count;
	int err;
	int i;

	param.start = NULL;
	do {
		count = oci_os_list_objects(config, &list_objects, &param, NULL);
		free(param.start);
		if (count < 0)
			return -1;

		for (i = 0; i < count; i++) {
			name = list_objects.objects[i].name;
			printf("DELETE OBJECT %s\n", name);
			err = oci_os_delete_object(config, name, NULL);
			if (err) {
				printf("DELETE OBJECT %s failed\n", name);
				goto error;
			}
		}

		next = list_objects.next_start_with;
		if (next) {
			param.start = strdup(next);
			if (!param.start) {
				printf("Failed to setup start parameter\n");
				goto error;
			}
		}
		oci_os_list_objects_fini(&list_objects);

	} while (next);

	return 0;

error:
	oci_os_list_objects_fini(&list_objects);
	return -1;
}

static int setup(void **state)
{
	struct oci_os_list_objects_param param = { 0 };
	struct oci_config *config;
	const char *region;
	char input[10];
	int count;
	int len;
	int err;

	region = getenv("OCI_DOMAIN");
	debug = debug;

	if (getenv("OCI_INSTANCE_PRINCIPAL"))
		config = oci_config_instance_principal(region, NULL, debug);
	else
		config = oci_config_create_from_file(config_filename,
						     region, NULL, debug);

	if (!config) {
		printf("Failed to create OCI configuration\n");
		return -1;
	}

	err = oci_config_init_object_storage(config, bucket_name);
	if (err) {
		oci_config_destroy(config);
		printf("Failed to init Object Storage\n");
		return -1;
	}

	param.limit = 1;
	count = oci_os_list_objects(config, NULL, &param, NULL);
	if (count < 0) {
		oci_config_destroy(config);
		printf("Failed to count objects in bucket '%s'\n", bucket_name);
		return -1;
	}

	if (count == 0) {
		oci_config_destroy(config);
		return 0;
	}

	if (!clean_bucket) {
		oci_config_destroy(config);
		printf("Bucket '%s' is not empty. ", bucket_name);
		printf("Use the -C option to clear the bucket.\n");
		printf("WARNING: Using the -C option will delete "
		       "*ALL* objects from the bucket\n");
		return -1;
	}

	printf("Bucket '%s' is not empty, cleaning the bucket.\n", bucket_name);
	printf("WARNING: This will delete *ALL* objects from the '%s' bucket\n",
	       bucket_name);

	while (1) {
		printf("Do you really want to delete *ALL* objects from "
		       "the '%s' bucket? (yes|[no]) ",
		       bucket_name);
		fflush(stdout);
		fgets(input, sizeof(input), stdin);

		len = strlen(input);
		if (len > 0 && input[len - 1] == '\n')
			input[len - 1] = '\0';

		if (input[0] == '\0' ||
		    strcmp(input, "n") == 0 || strcmp(input, "no") == 0) {
			oci_config_destroy(config);
			printf("Aborting.\n");
			return -1;
		}

		if (strcmp(input, "yes") == 0)
			break;

		printf("Please answer with 'yes' or 'no'\n");
	}

	err = clear_bucket(config);
	oci_config_destroy(config);

	return err;
}

static void test_config_create(void **state)
{
	const char *region;

	region = getenv("OCI_DOMAIN");
	debug = debug;

	if (getenv("OCI_INSTANCE_PRINCIPAL"))
		oci_config = oci_config_instance_principal(region, NULL, debug);
	else
		oci_config = oci_config_create_from_file(NULL,
							 region, NULL, debug);

	assert_non_null(oci_config);
	oci_config->debug = debug;
}

static void test_config_init_object_storage(void **state)
{
	int err;

	err = oci_config_init_object_storage(oci_config, bucket_name);
	assert_int_equal(err, 0);
	assert_non_null(oci_config->os_namespace);
	assert_non_null(oci_config->os_bucket);
}

static void test_get_namespace(void **state)
{
	char *namespace;

	namespace = oci_os_get_namespace(oci_config, NULL);
	assert_non_null(namespace);
	free(namespace);
}

static void test_head_bucket(void **state)
{
	struct oci_os_bucket_head bucket;
	int err;

	err = oci_os_head_bucket(oci_config, bucket_name, &bucket, NULL);
	assert_int_equal(err, 0);
	assert_non_null(bucket.etag);
	oci_os_bucket_head_fini(&bucket);
}

static void test_put_object(void **state)
{
	int err;
	int rv;

	rv = getrandom(object1_data, object1_size, 0);
	assert_int_equal(rv, object1_size);
	err = oci_os_put_object(oci_config, OBJECT1_NAME,
				object1_data, object1_size, NULL);
	assert_int_equal(err, 0);
}

static void head_object(char *object_name, size_t object_size)
{
	struct oci_os_object_head object;
	int err;

	err = oci_os_head_object(oci_config, object_name, &object, NULL);
	assert_int_equal(err, 0);
	assert_int_equal(object.content_length, object_size);
	oci_os_object_head_fini(&object);
}

static void test_head_object(void **state)
{
	struct oci_error error = OCI_ERROR_INIT;
	struct oci_os_object_head object;
	int err;

	/* head of existing object */
	head_object(OBJECT1_NAME, object1_size);

	/* try to get head of non-existing object */
	err = oci_os_head_object(oci_config, OBJECT_NONE, &object, &error);
	assert_int_equal(err, -1);
	assert_int_equal(error.http_status, 404);
	oci_error_fini(&error);
}

static void test_get_object(void **state)
{
	struct oci_error error = OCI_ERROR_INIT;
	char *buf = NULL;
	size_t size = 0;
	int err;

	err = oci_os_get_object(oci_config, OBJECT1_NAME, &buf, &size, NULL,
				NULL);
	assert_int_equal(err, 0);
	assert_non_null(buf);
	assert_int_equal(size, object1_size);
	assert_memory_equal(buf, object1_data, size);
	free(buf);

	/* try to get non-existing object */
	buf = NULL;
	size = 0;
	err = oci_os_get_object(oci_config, OBJECT_NONE, &buf, &size, NULL,
				&error);
	assert_int_equal(err, -1);
	assert_int_equal(error.http_status, 404);
	oci_error_fini(&error);
}


static void test_put_object_file(void **state)
{
	char buf[1024];
	size_t size;
	ssize_t s;
	int err, fd, rv;;

	fd = open(OBJECT2_DATA, O_CREAT | O_RDWR, 0644);
	assert_int_not_equal(fd, -1);

	for (size = 0; size < object2_size; size += 1024) {
		rv = getrandom(buf, 1024, 0);
		assert_int_equal(rv, 1024);
		s = write(fd, buf, 1024);
		assert_int_equal(s, 1024);
	}

	err = oci_os_put_object_from_file(oci_config, OBJECT2_NAME, fd, NULL);
	assert_int_equal(err, 0);
	close(fd);
}

static void test_head_object_file(void **state)
{
	head_object(OBJECT2_NAME, object2_size);
}

static void test_get_object_file(void **state)
{
	char buf_read[1024], buf_data[1024];
	int obj_read, obj_data;
	int size, err;
	ssize_t s;

	obj_read = open(OBJECT2_READ, O_CREAT | O_RDWR, 0644);
	assert_int_not_equal(obj_read, -1);

	err = oci_os_get_object_to_file(oci_config, OBJECT2_NAME,
					obj_read, NULL, NULL);
	assert_int_equal(err, 0);
	s = lseek(obj_read, 0, SEEK_SET);
	assert_int_equal(s, 0);

	obj_data = open(OBJECT2_DATA, O_RDONLY);
	assert_int_not_equal(obj_data, -1);

	for (size = 0; size < object2_size; size += 1024) {
		s = read(obj_data, buf_data, 1024);
		assert_int_equal(s, 1024);
		s = read(obj_read, buf_read, 1024);
		assert_int_equal(s, 1024);
		assert_memory_equal(buf_read, buf_data, 1024);
	}

	close(obj_read);
	close(obj_data);

	unlink(OBJECT2_DATA);
	unlink(OBJECT2_READ);
}

static void list_objects(char *obj1_name, char *obj2_name)
{
	struct oci_os_list_objects_param param = { 0 };
	struct oci_os_list_objects list_objects;
	bool object1_found;
	bool object2_found;
	char *next;
	char *name;
	int total;
	int count;
	int i;

	object1_found = false;
	object2_found = false;
	total = 0;
	param.start = NULL;
	param.fields = "size";
	do {
		count = oci_os_list_objects(oci_config, &list_objects, &param,
					    NULL);
		free(param.start);
		assert_in_range(count, 0, 1000);

		for (i = 0; i < count; i++) {
			name = list_objects.objects[i].name;
			if (obj1_name && strcmp(name, obj1_name) == 0) {
				assert_false(object1_found);
				assert_int_equal(object1_size,
						 list_objects.objects[i].size);
				object1_found = true;
				total++;
				continue;
			}
			if (obj2_name && strcmp(name, obj2_name) == 0) {
				assert_false(object2_found);
				assert_int_equal(object2_size,
						 list_objects.objects[i].size);
				object2_found = true;
				total++;
				continue;
			}
			fail_msg("Unexpected object name '%s'", name);
		}

		next = list_objects.next_start_with;
		if (next) {
			param.start = strdup(next);
			assert_non_null(param.start);
		}
		oci_os_list_objects_fini(&list_objects);

	} while (next);

	count = 0;
	if (obj1_name) {
		assert_true(object1_found);
		count++;
	}

	if (obj2_name) {
		assert_true(object2_found);
		count++;
	}

	assert_int_equal(total, count);
}

static void test_list_objects(void **state)
{
	list_objects(OBJECT1_NAME, OBJECT2_NAME);
}

static void test_rename_object(void **state)
{
	struct oci_error error = OCI_ERROR_INIT;
	int err;

	/* rename object using a non-used name */
	err = oci_os_rename_object(oci_config, OBJECT1_NAME, OBJECT3_NAME,
				   NULL);
	assert_int_equal(err, 0);
	err = oci_os_rename_object(oci_config, OBJECT2_NAME, OBJECT4_NAME,
				   NULL);
	assert_int_equal(err, 0);
	list_objects(OBJECT3_NAME, OBJECT4_NAME);

	/* rename and overwritte an existing object */
	err = oci_os_rename_object(oci_config, OBJECT3_NAME, OBJECT4_NAME,
				   NULL);
	assert_int_equal(err, 0);

	/* try to rename a non-existing object */
	err = oci_os_rename_object(oci_config, OBJECT_NONE, OBJECT1_NAME,
				   &error);
	assert_int_equal(err, -1);
	assert_int_equal(error.http_status, 404);
	oci_error_fini(&error);

	list_objects(OBJECT4_NAME, NULL);
}

static void test_delete_object(void **state)
{
	struct oci_error error = OCI_ERROR_INIT;
	int err;

	/* delete existing objects */
	err = oci_os_delete_object(oci_config, OBJECT4_NAME, NULL);
	assert_int_equal(err, 0);
	list_objects(NULL, NULL);

	/* try to delete non-existing object */
	err = oci_os_delete_object(oci_config, OBJECT_NONE, &error);
	assert_int_equal(err, -1);
	assert_int_equal(error.http_status, 404);
	oci_error_fini(&error);
}

static const struct CMUnitTest tests[] =
{
	cmocka_unit_test(test_config_create),
	cmocka_unit_test(test_config_init_object_storage),
	cmocka_unit_test(test_get_namespace),
	cmocka_unit_test(test_head_bucket),

	cmocka_unit_test(test_put_object),
	cmocka_unit_test(test_head_object),
	cmocka_unit_test(test_get_object),

	cmocka_unit_test(test_put_object_file),
	cmocka_unit_test(test_head_object_file),
	cmocka_unit_test(test_get_object_file),

	cmocka_unit_test(test_list_objects),
	cmocka_unit_test(test_rename_object),
	cmocka_unit_test(test_delete_object),
};

static void usage(void)
{
	printf("Usage: test_oci [options] <bucket>\n");
	printf("\n");
	printf("Options:\n");
	printf("\n");
	printf("    -c <config-file>: OCI configuration file\n");
	printf("    -d: debug\n");
	printf("    -C: Cleart the OCI Object Storage bucket\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "+c:dC")) != -1) {
		switch (opt) {
		case 'c':
			config_filename = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'C':
			clean_bucket = true;
			break;
		default:
			usage();
			return 2;
		}
	}

	if (argc != optind + 1) {
		usage();
		return 2;
	}

	bucket_name = argv[optind];

	return cmocka_run_group_tests(tests, setup, NULL);
}
