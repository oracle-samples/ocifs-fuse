/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

/*
 * Some OCIFS (specific) tests.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <mntent.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cmocka.h>

#include "oci.h"

#define FILE1	"file1"
#define FILE2	"file2"
#define DIR1	"dir1"

static char long_name[300];
static char *ocifs_root;

static struct oci_config *oci_config;

/*
 * Return the bucket of an OCIFS mountpoint.
 */
static char *get_bucket(char *dir)
{
	struct mntent *mntent;
	char path[PATH_MAX];
	char *bucket;
	FILE *mtab;

	if (!realpath(dir, path)) {
		printf("Failed to resolve path '%s': %s\n",
		       dir, strerror(errno));
		return NULL;
	}

	mtab = setmntent("/etc/mtab", "r");
	if (!mtab) {
		printf("Failed to open /etc/mtab\n");
		return NULL;
	}

	while ((mntent = getmntent(mtab)) != NULL) {
		if (strcmp(path, mntent->mnt_dir) == 0)
			break;
	}

	if (!mntent) {
		endmntent(mtab);
		printf("Error: %s was not found in /etc/mtab\n", path);
		return NULL;
	}

	if (strcmp(mntent->mnt_type, "fuse.ocifs") != 0) {
		endmntent(mtab);
		printf("Error: %s is not an OCIFS mount point\n", dir);
		return NULL;
	}

	bucket = strdup(mntent->mnt_fsname);

	endmntent(mtab);

	return bucket;
}

static int setup(void **state)
{
	const char *region;
	const char *bucket;
	int err;
	int i;

	for (i = 0; i < sizeof(long_name) - 1; i++)
		long_name[i] = 'A';

	long_name[sizeof(long_name) - 1] = '\0';

	region = getenv("OCI_DOMAIN");
	if (getenv("OCI_INSTANCE_PRINCIPAL"))
		oci_config = oci_config_instance_principal(region, NULL, 0);
	else if (getenv("OCI_RESOURCE_PRINCIPAL_VERSION"))
		oci_config = oci_config_resource_principal(region, NULL, 0);
	else
		oci_config = oci_config_create_from_file(NULL,
							 region, NULL, 0);

	if (!oci_config) {
		printf("Failed to create OCI configuration\n");
		return -1;
	}

	bucket = get_bucket(ocifs_root);
	if (!bucket) {
		oci_config_destroy(oci_config);
		oci_config = NULL;
		printf("Failed to get OCIFS bucket for %s\n", ocifs_root);
		return -1;
	}

	err = oci_config_init_object_storage(oci_config, bucket);
	free((char *)bucket);
	if (err) {
		oci_config_destroy(oci_config);
		oci_config = NULL;
		printf("Failed to init Object Storage\n");
		return -1;
	}

	(void) oci_os_delete_object(oci_config, long_name, NULL);

	err = chdir(ocifs_root);
	if (err) {
		printf("Failed to change directory to mnt\n");
		return -11;
	}

	(void) remove(FILE1);
	(void) remove(FILE2);
	(void) remove(DIR1);

	return 0;
}

static int cleanup(void **state)
{
	(void) remove(FILE1);
	(void) remove(FILE2);
	(void) remove(DIR1);

	oci_config_destroy(oci_config);

	return 0;
}

static void test_open(void **state)
{
	int fd;

	/* open non-existing path */
	fd = open(FILE1, O_RDWR);
	assert_int_equal(fd, -1);

	/* open create */
	fd = open(FILE1, O_RDWR | O_EXCL | O_CREAT, 0644);
	assert_int_not_equal(fd, -1);
	close(fd);

	/* open existing */
	fd = open(FILE1, O_RDWR);
	assert_int_not_equal(fd, -1);
	close(fd);
}

static void test_dir(void **state)
{
	struct stat stbuf;
	ssize_t size;
	int err;
	int fd;

	/* create dir */
	err = mkdir(DIR1, 0755);
	assert_int_equal(err, 0);

	/* open existing dir read-write */
	fd = open(DIR1, O_RDWR);
	assert_int_equal(fd, -1);
	assert_int_equal(errno, EISDIR);

	/* open existing dir write-only */
	fd = open(DIR1, O_WRONLY);
	assert_int_equal(fd, -1);
	assert_int_equal(errno, EISDIR);

	/* open existing dir read-only */
	fd = open(DIR1, O_RDONLY);
	assert_int_not_equal(fd, -1);

	/* read from dir */
	size = read(fd, "foo", 3);
	assert_int_equal(size, -1);
	assert_int_equal(errno, EISDIR);

	/* fstat dir */
	err = fstat(fd, &stbuf);
	assert_int_equal(err, 0);
	assert_true(S_ISDIR(stbuf.st_mode));

	close(fd);

}

static int create_fd(char *filename, size_t size)
{
	char *buffer;
	ssize_t s;
	int fd;
	int rv;

	buffer = malloc(size);
	assert_non_null(buffer);

	rv = getrandom(buffer, size, 0);
	assert_int_equal(rv, size);

	fd = open(FILE1, O_RDWR | O_CREAT | O_TRUNC, 0644);
	assert_int_not_equal(fd, -1);

	s = write(fd, buffer, size);
	assert_int_equal(s, size);

	free(buffer);

	return fd;
}

static void create_file(char *filename, size_t size)
{
	int fd;

	fd = create_fd(filename, size);
	close(fd);
}

static void test_truncate(void **state)
{
	int err;

	create_file(FILE1, 10000);

	/* grow */
	err = truncate(FILE1, 15000);
	assert_int_equal(err, 0);

	/* shrink */
	err = truncate(FILE1, 5000);
	assert_int_equal(err, 0);
}

static void test_truncate_max(void **state)
{
	int error;
	int err;

	create_file(FILE1, 1024);

	/* grow should fail beyond 50GiB*/
	err = truncate(FILE1, (50UL * 1024 * 1024 * 1024) + 1);
	error = errno;
	assert_int_not_equal(err, 0);
	assert_int_equal(error, EFBIG);
}

static int test_write_max_setup(void **state)
{
	int fd;

	fd = create_fd(FILE1, 1024);
	if (fd == -1) {
		*state = (void *)-1;
		return -1;
	}

	*state = (void *)(long)fd;

	return 0;
}

static int test_write_max_cleanup(void **state)
{
	int fd = *((int *)state);

	if (fd == -1)
		return 0;

	/*
	 * Truncate the file so that we don't flush a large (50GiB)
	 * file.
	 */
	ftruncate(fd, 0);
	close(fd);

	return 0;
}

static void test_write_max(void **state)
{
	int fd = *((int *)state);
	size_t count;
	off_t offset;
	int error;

	offset = 50UL * 1024 * 1024 * 1024;

	/* write succeeds up to the 50GiB limit */
	count = pwrite(fd, "1234567890", 10, offset - 5);
	assert_int_equal(count, 5);

	/* write fails beyond 50GiB */
	count = pwrite(fd, "X", 1, offset);
	error = errno;
	assert_int_equal(count, -1);
	assert_int_equal(error, EFBIG);

	count = lseek(fd, offset, SEEK_SET);
	assert_int_equal(count, offset);

	count = write(fd, "X", 1);
	error = errno;
	assert_int_equal(count, -1);
	assert_int_equal(error, EFBIG);
}

static void test_long_name(void **state)
{
	char buffer[] = "TEST FOR LONG NAME";
	struct stat stbuf;
	ssize_t ssize;
	char data[50];
	off_t off;
	int err;
	int fd;

	/*
	 * OCIFS prevents creating file or directory with names too
	 * long for caching.
	 */
	fd = open(long_name, O_RDWR | O_EXCL | O_CREAT, 0644);
	assert_int_equal(fd, -1);
	assert_int_equal(errno, ENAMETOOLONG);

	err = mkdir(long_name, 0755);
	assert_int_equal(err, -1);
	assert_int_equal(errno, ENAMETOOLONG);

	/*
	 * OCIFS also prevents renaming with a name too long for caching.
	 */
	err = rename(FILE1, long_name);
	assert_int_equal(err, -1);
	assert_int_equal(errno, ENAMETOOLONG);

	err = rename(DIR1, long_name);
	assert_int_equal(err, -1);
	assert_int_equal(errno, ENAMETOOLONG);

	/*
	 * Existing objects with long names should be accessible. They
	 * can be read but not written to, unless they are renamed.
	 */

	/* create object with long name */
	err = oci_os_put_object(oci_config, long_name, buffer, sizeof(buffer),
				NULL);
	assert_int_equal(err, 0);

	/* stat object with long name */
	err = stat(long_name, &stbuf);
	assert_int_equal(err, 0);
	assert_true(S_ISREG(stbuf.st_mode));
	assert_int_equal(stbuf.st_size, sizeof(buffer));

	/* open object with long name */
	fd = open(long_name, O_RDWR);
	assert_int_not_equal(fd, -1);

	/* read works */
	ssize = read(fd, data, sizeof(data));
	assert_int_equal(ssize, sizeof(buffer));
	assert_memory_equal(data, buffer, sizeof(buffer));

	/* write doesn't */
	ssize = write(fd, buffer, sizeof(buffer));
	assert_int_equal(ssize, -1);
	assert_int_equal(errno, ENAMETOOLONG);

	/* rename with short name */
	err = rename(long_name, FILE2);
	assert_int_equal(err, 0);

	/* read should still work */
	off = lseek(fd, 0, SEEK_SET);
	assert_int_equal(off, 0);
	ssize = read(fd, data, sizeof(data));
	assert_int_equal(ssize, sizeof(buffer));
	assert_memory_equal(data, buffer, sizeof(buffer));

	/* write should work too now */
	ssize = write(fd, buffer, sizeof(buffer));
	assert_int_equal(ssize, sizeof(buffer));

	close(fd);
}

static void oci_check_file(char *name, size_t size, char *buffer)
{
	size_t content_size = 0;
	char *content = NULL;
	int err;

	err = oci_os_get_object(oci_config, name, &content, &content_size,
				NULL, NULL);
	assert_int_equal(err, 0);
	assert_int_equal(content_size, size);
	if (size) {
		assert_memory_equal(content, buffer, size);
		free(content);
	}
}

enum {
	TEST_NO_SYNC,
	TEST_SYNC,
	TEST_DSYNC,
	TEST_FSYNC,
};

static void check_fsync(int test)
{
	struct oci_os_object_head object;
	struct oci_error error;
	char *buffer;
	size_t size;
	ssize_t s;
	int flags;
	int err;
	int fd;
	int rv;

	size = 1024;
	buffer = malloc(size);
	assert_non_null(buffer);

	rv = getrandom(buffer, size, 0);
	assert_int_equal(rv, size);

	/* ensure that file doesn't exist */
	(void) remove(FILE1);

	flags = O_RDWR | O_CREAT;
	if (test == TEST_SYNC)
		flags |= O_SYNC;
	else if (test == TEST_DSYNC)
		flags |= O_DSYNC;

	fd = open(FILE1, flags, 0644);
	assert_int_not_equal(fd, -1);

	/* open() shouldn't create OCI object */
	err = oci_os_head_object(oci_config, FILE1, &object, &error);
	assert_int_not_equal(err, 0);
	assert_int_equal(error.http_status, 404);
	oci_error_fini(&error);

	s = write(fd, buffer, size);
	assert_int_equal(s, size);

	if (test == TEST_SYNC || test == TEST_DSYNC) {
		/* write() should update OCI object */
		oci_check_file(FILE1, size, buffer);
	} else {
		/* write() not should update OCI object */
		err = oci_os_head_object(oci_config, FILE1, &object, &error);
		assert_int_not_equal(err, 0);
		assert_int_equal(error.http_status, 404);
		oci_error_fini(&error);

		if (test == TEST_FSYNC) {
			err = fsync(fd);
			assert_int_equal(err, 0);
			/* fsync() should update OCI object */
			oci_check_file(FILE1, size, buffer);
		}
	}

	close(fd);

	/* close() should update OCI object */
	oci_check_file(FILE1, size, buffer);

	free(buffer);
}

static void test_no_sync(void **state)
{
	check_fsync(TEST_NO_SYNC);
}

static void test_sync(void **state)
{
	check_fsync(TEST_SYNC);
}

static void test_dsync(void **state)
{
	check_fsync(TEST_DSYNC);
}

static void test_fsync(void **state)
{
	check_fsync(TEST_FSYNC);
}

static const struct CMUnitTest tests[] =
{
	cmocka_unit_test(test_open),
	cmocka_unit_test(test_dir),
	cmocka_unit_test(test_truncate),
	cmocka_unit_test(test_truncate_max),
	cmocka_unit_test_setup_teardown(test_write_max,
					test_write_max_setup,
					test_write_max_cleanup),
	cmocka_unit_test(test_long_name),
	cmocka_unit_test(test_no_sync),
	cmocka_unit_test(test_sync),
	cmocka_unit_test(test_dsync),
	cmocka_unit_test(test_fsync),
};

static void usage(void)
{
	printf("Usage: test_ocifs <ocifs-mountpoint>\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		usage();
		return 2;
	}

	ocifs_root = argv[1];
	return cmocka_run_group_tests(tests, setup, cleanup);
}
