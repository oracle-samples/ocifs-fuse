/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>

#include "utils.h"

struct base64_encoding {
	char *data;
	char *encoding;
	char *encoding_url;
};

struct base64_encoding base64_examples[] = {
	{ "", "" },
	
	{ "f",		"Zg=="		},
	{ "fo",		"Zm8="		},
	{ "foo",	"Zm9v"		},
	{ "foob",	"Zm9vYg=="	},
	{ "fooba",	"Zm9vYmE="	},
	{ "foobar",	"Zm9vYmFy"	},
	{ "té",		"dMOp"		},

	{ "nim",	"bmlt"		},
	{ "c\xf7>",	"Y/c+",	"Y_c-"	},
	{ "\001\002\003\004\005", "AQIDBAU=" },

	{ " !\"#$%&'()*+,-./",	"ICEiIyQlJicoKSorLC0uLw==" },
	{ "0123456789",		"MDEyMzQ1Njc4OQ==" },
	{ ":;<=>?@",		"Ojs8PT4/QA==",	"Ojs8PT4_QA=="},
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	  			"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" },
	{ "[\\]^_`",		"W1xdXl9g"},
	{ "abcdefghijklmnopqrstuvwxyz",
	  			"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=" },
	{ "{|}~", 		"e3x9fg==" },

	{ "Hello World", 	"SGVsbG8gV29ybGQ=" },
	{ "data to be encoded",	"ZGF0YSB0byBiZSBlbmNvZGVk" },
	{ "Many hands make light work.",
	  			"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu" },
};

static const char *base64url_invalid[] = {
	"A", "ABCDE", "=", "==", "===", "====", "A=", "A==",
	"A===", "A==A", "A=AA", "A=A=",	"AA=A"
};

static void test_base64_encode(void **state)
{
	unsigned char c;
	char result[5];
	char *data;
	char *str;
	int i;

	/*
	 * Check the encoding of the first 6 bits, the remaining 2 bits
	 * are set to 0 i.e. check the encoded of binary values xxxxxx00
	 * with 0 <= xxxxxx <= 63.
	 */
	strcpy(result, "AA==");
	for (i = 0; i < 63; i++) {
		c = (i << 2);
		if (i < 26)
			result[0] = 'A' + i;
		else if (i < 52)
			result[0] = 'a' + i - 26;
		else if (i < 62)
			result[0] = '0' + i - 52;
		else if (i == 62)
			result[0] = '+';
		else if (i == 63)
			result[0] = '/';
		str = base64_encode(&c, 1);
		assert_string_equal(str, result);
		free(str);
	}

	for (i = 0; i < ARRAY_SIZE(base64_examples); i++) {
		data = base64_examples[i].data;
		str = base64_encode((unsigned char *)data, strlen(data));
		assert_string_equal(str, base64_examples[i].encoding);
		free(str);
	}
}

static void test_base64url_decode(void **state)
{
	unsigned char *buffer;
	unsigned char c;
	int buffer_size;
	char result[5];
	char *data;
	char *str;
	int i;

	strcpy(result, "AA==");
	for (i = 0; i < 63; i++) {
		c = (i << 2);
		if (i < 26)
			result[0] = 'A' + i;
		else if (i < 52)
			result[0] = 'a' + i - 26;
		else if (i < 62)
			result[0] = '0' + i - 52;
		else if (i == 62)
			result[0] = '-';
		else if (i == 63)
			result[0] = '_';
		buffer_size = base64url_decode(result, &buffer);
		assert_int_equal(buffer_size, 1);
		assert_int_equal(buffer[0], c);
		free(buffer);
	}

	for (i = 0; i < ARRAY_SIZE(base64_examples); i++) {
		str = base64_examples[i].encoding_url;
		if (!str)
			str = base64_examples[i].encoding;
		buffer_size = base64url_decode(str, &buffer);
		assert_true(buffer_size >= 0);

		data = base64_examples[i].data;
		assert_int_equal(buffer_size, strlen(data));
		assert_string_equal(buffer, data);
		free(buffer);
	}

	for (i = 0; i < ARRAY_SIZE(base64url_invalid); i++) {
		buffer_size = base64url_decode((char *)base64url_invalid[i], &buffer);
		assert_true(buffer_size < 0);
		assert_true(errno == EINVAL);
	}

}

static void expand_absolute_path(char *absolute_path)
{
	char *path;

	path = expand_path(absolute_path);
	assert_non_null(path);
	assert_string_equal(path, absolute_path);
	free(path);
}

static void expand_relative_path(char *relative_path, char *result_fmt,
				 char *home)
{
	char *result;
	char *path;

	path = expand_path(relative_path);
	assert_non_null(path);
	result = strfmt(result_fmt, home);
	assert_non_null(result);
	assert_string_equal(path, result);

	free(path);
	free(result);
}

static void test_expand_path(void **state)
{
	char *home;

	expand_absolute_path("/foo");
	expand_absolute_path("/foo/bar");

	home = getenv("HOME");
	assert_non_null(home);

	expand_relative_path("foo", "%s/foo", home);
	expand_relative_path("foo/bar", "%s/foo/bar", home);
	expand_relative_path("~/foo", "%s/foo", home);
	expand_relative_path("~/foo/bar", "%s/foo/bar", home);
}

static void test_escape_path(void **state)
{
	char *strings[] = {
		"aaa/bbb/ccc", "aaa/bbb/ccc",
		"aaa/b%b/ccc", "aaa/b%25b/ccc",
		"foo/té/", "foo/t%C3%A9/",
		"1/2/3/4/5/6/7/8/9/0", "1/2/3/4/5/6/7/8/9/0",
	};
	char *result;
	int i;

	for (i = 0; i < ARRAY_SIZE(strings); i += 2) {
		result = escape_path(strings[i]);
		//printf("%s -> %s\n", strings[i], result);
		assert_string_equal(result, strings[i + 1]);
		if (result != strings[i])
			free(result);
	}
}

static void test_strcmp_array(void **state)
{
	char *strings[] = { "barx/", "dir/", "folder1/", "folder2/",
			    "prefix.4/", "prefix/", "testdir/", "y/",
			    "yyy/" };
	int count = ARRAY_SIZE(strings);
	int rv;

	/* empty array */
	rv = strcmp_array("xxx", NULL, 0);
	assert_int_equal(rv, 1);

	/* single-element array */
	rv = strcmp_array("aaa", strings, 1);
	assert_int_equal(rv, -1);
	rv = strcmp_array("barx/", strings, 1);
	assert_int_equal(rv, 0);
	rv = strcmp_array("xxx", strings, 1);
	assert_int_equal(rv, 2);

	/* two elements array */
	rv = strcmp_array("aaa", strings, 2);
	assert_int_equal(rv, -1);
	rv = strcmp_array("barx/", strings, 2);
	assert_int_equal(rv, 0);
	rv = strcmp_array("ccc", strings, 2);
	assert_int_equal(rv, 2);
	rv = strcmp_array("dir/", strings, 2);
	assert_int_equal(rv, 1);
	rv = strcmp_array("xxx", strings, 2);
	assert_int_equal(rv, 3);

	/* lower than range (return -1) */
	rv = strcmp_array("aaa/", strings, count);
	assert_int_equal(rv, -1);

	/* match (return index) */
	rv = strcmp_array("barx/", strings, count);
	assert_int_equal(rv, 0);
	rv = strcmp_array("prefix/", strings, count);
	assert_int_equal(rv, 5);
	rv = strcmp_array("prefix.4/", strings, count);
	assert_int_equal(rv, 4);
	rv = strcmp_array("yyy/", strings, count);
	assert_int_equal(rv, 8);

	/* no match but in range (return count) */
	rv = strcmp_array("barx/aaa", strings, count);
	assert_int_equal(rv, count);
	rv = strcmp_array("uuu", strings, count);
	assert_int_equal(rv, count);
	rv = strcmp_array("yy", strings, count);
	assert_int_equal(rv, count);

	/* greater than range (return count + 1) */
	rv = strcmp_array("zzz/", strings, count);
	assert_int_equal(rv, count + 1);
}

/*
 * Find a regular file in the specified directory which size is smaller
 * (cmp='<') or larger (cmp='>') than "size".
 */
static char *find_file(const char *dirname, char cmp, blksize_t size)
{
	struct dirent *dent;
	struct stat stbuf;
	char *filename;
	ssize_t diff;
	DIR *dir;
	int rv;

	dir = opendir(dirname);
	assert_non_null(dir);

	filename = NULL;
	while ((dent = readdir(dir)) != NULL) {
		rv = fstatat(dirfd(dir), dent->d_name, &stbuf, 0);
		if (rv != 0)
			continue;
		/*
		 * We are looking for a regular file that anybody
		 * can read, and with a specific size.
		 */
		if (!S_ISREG(stbuf.st_mode))
			continue;
		if ((stbuf.st_mode & 0444) != 0444)
			continue;

		diff = ((ssize_t)stbuf.st_size) - ((ssize_t)size);

		if ((diff > 0 && cmp == '>') ||
		    (diff < 0 && cmp == '<')) {
			filename = dent->d_name;
			break;
		}
	}

	if (filename)
		filename = strfmt("%s/%s", dirname, filename);

	closedir(dir);

	return filename;
}

static void test_file_read(void **state)
{
	char *filename;
	char *content;
	size_t size;
	char *data;
	int fd;
	int rv;

	/* read non-existing file */
	data = file_read("file_does_not_exist", NULL);
	assert_null(data);
	assert_int_equal(errno, ENOENT);

	/*
	 * Find a file larger than 1MB; we are likely to find
	 * one in /bin.
	 */
	filename = find_file("/bin", '>', 1024 * 1024);
	assert_non_null(filename);

	/* read file larger than 1MB */
	data = file_read(filename, NULL);
	assert_null(data);
	assert_int_equal(errno, EFBIG);
	free(filename);

	/*
	 * Find a file smaller than 1MB; we are likely to find
	 * one in /bin.
	 */
	filename = find_file("/bin", '<', 1024 * 1024);
	assert_non_null(filename);

	/* read file smaller than 1MB */
	data = file_read(filename, &size);
	assert_non_null(data);

	/*
	 * Map the file to compare what we have read with the
	 * content of the file.
	 */
	fd = open(filename, O_RDONLY);
	assert_int_not_equal(fd, -1);
	content = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert_int_not_equal(content, MAP_FAILED);
	rv = memcmp(data, content, size);
	assert_int_equal(rv, 0);
	rv = munmap(content, size);
	assert_int_equal(rv, 0);
	close(fd);
	free(filename);

	free(data);
}

static const struct CMUnitTest tests[] =
{
	cmocka_unit_test(test_base64_encode),
	cmocka_unit_test(test_base64url_decode),
	cmocka_unit_test(test_expand_path),
	cmocka_unit_test(test_escape_path),
	cmocka_unit_test(test_strcmp_array),
	cmocka_unit_test(test_file_read),
};

int main(void)
{
	return cmocka_run_group_tests(tests, NULL, NULL);
}
