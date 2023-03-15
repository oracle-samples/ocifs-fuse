/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

/*
 * The getrandom syscall was added to Linux kernel 3.17 but the getrandom()
 * function is only available since glibc 2.25.
 */

#if __GLIBC_MINOR__ >= 25

#include <sys/random.h>

#else

#include <sys/syscall.h>

ssize_t
getrandom (void *buffer, size_t length, unsigned int flags)
{
	return syscall(SYS_getrandom, buffer, length, flags);
}

#endif

char *strfmt(const char *fmt, ...)
{
	va_list args;
	char *str;
	int size;

	va_start(args, fmt);
	size = vasprintf(&str, fmt, args);
	va_end(args);

	if (size == -1)
		return NULL;

	return str;
}

/*
 * Convert a string representing a date and time in the Internet
 * format (RFC 3339) to a struct tm. Such a convertion cannot be
 * done directly with strptime().
 */
int strtotm(const char *internet_date, struct tm *tm)
{
	char *date, *tz, *s;

	/*
	 * The format of the Internet date/time (RFC 3339) is:
	 *
	 * <year>-<month>-<day>T<hour>:<minute>:<seconds>[.<msecs>]<timezone>
	 *
	 * where <timezone> is either "Z" or +/-HH:MM
	 *
	 * strptime() has no support for parsing milliseconds (<msecs>),
	 * and older version support timezone only with the +/-HHMM format
	 * (%z). So we reformat the date to:
	 *
	 * <year>-<month>-<day>T<hour>:<minute>:<seconds><timezone>
	 *
	 * where <timezone> is limited to +/-HHMM for older version.
	 */

#if __GLIBC_MINOR__ >= 23
	/*
	 * We just need to remove milliseconds, so the reformatted date
	 * will always be smaller or equal to the original date.
	 */
	date = strdup(internet_date);
#else
	/*
	 * We need to remove milliseconds, and reformat the "Z" or HH:MM
	 * timezone to HHMM. Reformatting "Z" will four extra characters
	 * (replace "Z" with "+0000") so the reformatted date can grow
	 * by that many characters.
	 */
	date = malloc(strlen(internet_date) + 5);
	if (!date)
		return -1;
	strcpy(date, internet_date);

#endif
	if (!date)
		return -1;

	/*
	 * Go to the 'T' character in the date so that we can look for
	 * the timezone (which starts with 'Z', '+' or '-') without
	 * confusing the '-' character with the ones at the begin of
	 * the date (YYYY-MM-DD).
	 */
	for (s = date; *s != 'T'; s++) {
		if (*s == '\0')
			goto error;
	}

	/*
	 * Look for characters specifying milliseconds ('.') and
	 * timezone ('Z', '+', '-')
	 */
	tz = NULL;
	for (s++; *s != '\0'; s++) {
		if (*s == 'Z' || *s == '+' || *s == '-')
			break;
		if (*s == '.')
			tz = s;
	}

	if (*s == '\0') {
		/* timezone not found */
		goto error;
	}

#if __GLIBC_MINOR__ >= 23
	/*
	 * With glibc 2.23 or newer, %z supports all timezone format of
	 * RFC 3339, so we just have to remove milliseconds (if any).
	 */
	if (tz) {
		/* copy timezone over milliseconds */
		while (*s)
			*tz++ = *s++;
		*tz = '\0';
	}

#else
	/*
	 * With glibc before 2.23, %z supports only timezone format HH
	 * and HHMM. Convert "Z" to +0000, and HH:MM to HHMM.
	 */

	if (*s == 'Z') {
		if (*(s + 1) != '\0')
			goto error;
		if (!tz)
			tz = s;
		strcpy(tz, "+0000");
	} else {
		if (!tz) {
			/* make tz points right after the timezone sign */
			tz = ++s;
		} else {
			/* copy timezone sign [+-] */
			*tz++ = *s++;
		}

		/*
		 * Rewrite the timezone "HH:MM" (pointed by s) as "HHMM"
		 * in the area pointed by tz.
		 */
		if ((*tz++ = *s++) == '\0' || (*tz++ = *s++) == '\0' ||
		    *s++ != ':' ||
		    (*tz++ = *s++) == '\0' || (*tz++ = *s++) == '\0' ||
		    (*tz++ = *s++) != '\0') {
			goto error;
		}
	}
#endif

	s = strptime(date, "%Y-%m-%dT%H:%M:%S%z", tm);
	if (!s || *s)
		goto error;

	free(date);
	return 0;

error:
	free(date);
	return -1;
}

/*
 * Compare a string with an array of strings. The array of strings
 * should be alphabetically sorted.
 *
 * Returned value:
 *  < 0 : if the string is less than the lower boundary of the array.
 *  > count : if string is greater than then the upper boundary of the array.
 *  count : if the string within the array boundaries but has no match.
 *  i (-1 < i < count) : if the string matches an element of the array,
 *    i is then the index of the matching string in the array.
 */
int strcmp_array(char *str, char **strings, int count)
{
	int rv;
	int i;

	if (count == 0)
		goto greater_than_range;

	/* check if string is smaller than lower boundary */
	rv = strcmp(str, strings[0]);
	if (rv == 0)
		return 0;
	if (rv < 0)
		return -1;

	if (count == 1)
		goto greater_than_range;

	/* check if string is larger than upper boundary */
	rv = strcmp(str, strings[count - 1]);
	if (rv == 0)
		return count - 1;
	if (rv > 0)
		goto greater_than_range;

	for (i = 1; i < count - 1; i++) {
		rv = strcmp(str, strings[i]);
		if (rv == 0)
			return i;
		if (rv < 0)
			break;
	}

	/* in range but no match */
	return count;

greater_than_range:
	return count + 1;
}

const char *http_method_names[] = {
	[HTTP_METHOD_DELETE] = "DELETE",
	[HTTP_METHOD_GET] = "GET",
	[HTTP_METHOD_HEAD] = "HEAD",
	[HTTP_METHOD_POST] = "POST",
	[HTTP_METHOD_PUT] = "PUT",
};

static const char *http_day[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *http_month[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char HTTP_DATE_FMT[] = "%3s, %02d %3s %04d %02d:%02d:%02d %3s";

/*
 * Return the current GMT date and time formatted according to
 * the HTTP procotol specification (RFC 2616). The format is
 * defined by RFC 822, updated by RFC 1123.
 *
 * date_len should be equal or greater than HTTP_DATE_FMT_SIZE.
 *
 * Return errno from time(2), gmtime(3)
 */
int http_gmtime(char *date, int date_len)
{
	struct tm tm, *tm_p;
	time_t now;
	int len;

	if (date_len < HTTP_DATE_FMT_SIZE) {
		errno = EINVAL;
		return -1;
	}

	now = time(NULL);
	if (now == -1)
		return -1;

	tm_p = gmtime(&now);
	if (!tm_p)
		return -1;

	/*
	 * gmtime() returns a pointer to a statically allocated struct
	 * so immediately copy the result.
	 */
	tm = *tm_p;

	/*
	 * We don't use strftime() because the result depends on the
	 * locale. The following is equivalent to strftime() with
	 * "%a, %d %b %Y %H:%M:%S %Z" and the C locale.
	 */

	len = snprintf(date, date_len, HTTP_DATE_FMT,
		       http_day[tm.tm_wday],
		       tm.tm_mday, http_month[tm.tm_mon], 1900 + tm.tm_year,
		       tm.tm_hour, tm.tm_min, tm.tm_sec, "GMT");

	if (len != HTTP_DATE_FMT_SIZE - 1) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static char *base64_table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

#define BA64_MAXVAL	63
#define BA64_PADDING	254	/* padding character */
#define BA64_INVALID	255	/* invalid character */

static unsigned char base64url_table_reverse[] = {
	/* + , (not used) */
	BA64_INVALID, BA64_INVALID,
	/* - */
	62,
	/* . / (not used) */
	BA64_INVALID, BA64_INVALID,
	/* 0 -> 9 */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
	/* : ; <  (not used) */
	BA64_INVALID, BA64_INVALID, BA64_INVALID,
	/* = */
	BA64_PADDING,
	/* > ? @ (not used) */
	BA64_INVALID, BA64_INVALID, BA64_INVALID,
	/* A -> N */
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	/* O -> Z */
	14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
	/* [ \ ] ^ (not used) */
	BA64_INVALID, BA64_INVALID, BA64_INVALID, BA64_INVALID,
	/* _ */
	63,
	/* ` (not used) */
	BA64_INVALID,
	/* a -> n */
	26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
	/* o -> z */
	40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

static unsigned char base64url_decode_char(char c)
{
	if (c < '+' || c > 'z')
		return 255;

	return  base64url_table_reverse[c - '+'];
}

int base64url_decodeb(char *str, int len, unsigned char **bufp)
{
	unsigned char v1, v2, v3, v4;
	unsigned char *buffer, *buf;
	int buf_len;
	int i;

	if (len == 0) {
		/*
		 * The base64 encoding of an empty array of data
		 * is the empty string.
		 */
		buffer = malloc(1);
		if (!buffer)
			return -1;
		buffer[0] = '\0';
		*bufp = buffer;
		return 0;
	}

	/*
	 * The base64 string should have a multiple of 4 characters
	 * otherwise it is not valid.
	 */
	if (len % 4 == 1) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Four base64 characters represent a maximum of 3 values,
	 * and we add one extra byte to add a terminating '\0'.
	 */
	buf_len = ((len + 3) / 4) * 3 + 1;

	buffer = malloc(buf_len);
	if (!buffer)
		return -1;

	buf = buffer;

	for (i = 0; i < len; i += 4) {
		/*
		 * Each block of 4 characters start with at least two
		 * values (and these are not padding).
		 */
		v1 = base64url_decode_char(str[i]);
		v2 = base64url_decode_char(str[i + 1]);
		if (v1 > BA64_MAXVAL || v2 > BA64_MAXVAL)
			goto error;

		*(buf++) = (v1 << 2) | (v2 >> 4);

		if (i + 4 < len) {
			v3 = base64url_decode_char(str[i + 2]);
			v4 = base64url_decode_char(str[i + 3]);
			if (v3 > BA64_MAXVAL || v4 > BA64_MAXVAL)
				goto error;
		} else {
			/*
			 * We are at the end of the string, we can have
			 * padding but it is optional.
			 */
			if (len == i + 2)
				break;

			v3 = base64url_decode_char(str[i + 2]);

			if (len == i + 3)
				v4 = BA64_PADDING;
			else
				v4 = base64url_decode_char(str[i + 3]);

			if (v3 == BA64_INVALID || v4 == BA64_INVALID)
				goto error;

			if (v3 == BA64_PADDING && v4 != BA64_PADDING)
				goto error;

			if (v3 == BA64_PADDING)
				break;
		}

		*(buf++) = ((v2 & 0xf) << 4) | (v3 >> 2);

		if (v4 == BA64_PADDING)
			break;

		*(buf++) = ((v3 & 0x3) << 6) | v4;
	}

	*buf = '\0';
	*bufp = buffer;

	return (buf - buffer);

error:
	free(buffer);
	errno = EINVAL;
	return -1;
}

int base64url_decode(char *str, unsigned char **bufp)
{
	return base64url_decodeb(str, strlen(str), bufp);
}

char *base64_encode(unsigned char *buf, int buf_size)
{
	unsigned char b1, b2, b3;
	unsigned int i;
	char *str, *s;
	int len;

	if (!buf)
		return NULL;

	if (!buf_size) {
		/*
		 * The base64 encoding of an empty array of data
		 * is the empty string so allocate and return "".
		 */
		str = malloc(1);
		if (!str)
			return NULL;
		str[0] = '\0';
		return str;
	}


	/* add extra space for padding and '\0' */
	len = ((buf_size * 8) / 6) + 5;
	str = malloc(len);
	if (!str)
		return NULL;

	s = str;

	for (i = 0; i + 2 < buf_size; i += 3) {
		b1 = buf[i];
		b2 = buf[i + 1];
		b3 = buf[i + 2];

		*(s++) = base64_table[b1 >> 2];
		*(s++) = base64_table[((b1 & 0x3) << 4) | (b2 >> 4)];
		*(s++) = base64_table[((b2 & 0xf) << 2) | (b3 >> 6)];
		*(s++) = base64_table[b3 & 0x3f];
	}

	if (i + 1 < buf_size) {
		b1 = buf[i];
		b2 = buf[i + 1];

		*(s++) = base64_table[b1 >> 2];
		*(s++) = base64_table[((b1 & 0x3) << 4) | (b2 >> 4)];
		*(s++) = base64_table[((b2 & 0xf) << 2)];
		*(s++) = '=';

	} else if (i < buf_size) {
		b1 = buf[i];

		*(s++) = base64_table[b1 >> 2];
		*(s++) = base64_table[((b1 & 0x3) << 4)];
		*(s++) = '=';
		*(s++) = '=';
	}

	*s = '\0';

	return str;
}

RSA *load_private_key(const char *filename, char *passphrase)
{
	RSA *pkey;
	FILE *f;

	f = fopen(filename, "r");
	if (!f)
		return NULL;

	pkey = PEM_read_RSAPrivateKey(f, NULL, NULL, passphrase);

	fclose(f);

	return pkey;
}

RSA *read_private_key(const char *key_pem, char *passphrase)
{
	RSA *pkey;
	BIO *bio;

	bio = BIO_new_mem_buf(key_pem, -1);
	if (!bio)
		return NULL;

	pkey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, passphrase);

	BIO_free(bio);

	return pkey;
}

/*
 * Helper function to read the entire content of a file. The function
 * only reads files smaller than 1MB to avoid allocating a large buffer.
 * The return buffer is NUL terminated. The size of the file is
 * returned (if sizep is not NULL); this size is the actual size of the
 * file, it doesn't account for the ending NUL character.
 */
char *file_read(char *filename, size_t *sizep)
{
	size_t count, size;
	struct stat stbuf;
	char *data;
	ssize_t n;
	int err;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	err = fstat(fd, &stbuf);
	if (err)
		goto error;

	size = stbuf.st_size;
	if (size > 1024 * 1024) {
		errno = EFBIG;
		goto error;
	}

	data = malloc(size + 1);
	if (!data)
		goto error;

	for (count = 0; count < size; count += n) {
		n = read(fd, data, size - count);
		if (n == 0)
			break;
		if (n < 0) {
			free(data);
			goto error;
		}
	}

	(void) close(fd);

	/*
	 * Return the amount of data effectively read from the file.
	 * This might be less than 'size' if the file has shrunk after
	 * we read the file size. And if the file has grown then we
	 * will return data only up to 'size'.
	 */
	if (sizep)
		*sizep = count;

	data[count] = '\0';

	return data;

error:
	(void) close(fd);
	return NULL;
}

int seek_data(int fd, struct range_list *range_list)
{
	off_t begin, end;
	int err;

	end = 0;

	while (1) {
		begin = lseek(fd, end, SEEK_DATA);
		if (begin < 0) {
			if (errno != ENXIO)
				return -1;
			break;
		}

		/*
		 * 'begin' points to data inside the file so we should
		 * always find a hole. If there is no hole past 'begin'
		 * then 'end' will point to the end of the file.
		 */
		end = lseek(fd, begin, SEEK_HOLE);
		if (end < 0)
			return -1;

		err = range_list_add(range_list, begin, end - begin);
		if (err)
			return -1;
	}

	/*
	 * We reach this point when there is no more data to seek in the
	 * file. If we haven't reached the end of the file then there is
	 * a hole at the end of file.
	 */

	return 0;
}

static char *rmtree_root_prefix;

void rmtree_set_root_prefix(char *prefix)
{
	rmtree_root_prefix = prefix;
}

/*
 * Use FTS(3) to implement rmtree. However, before GLIBC 2.23, FTS
 * doesn't support large files. In that case, use the chmod and rm
 * commands.
 */

#if defined(__USE_FILE_OFFSET64) && __GLIBC_MINOR__ < 23

static int __rmtree(char *pathname, bool root)
{
	char *cmd;
	int error;

	/*
	 * If we are root, we can directly remove the tree. If not,
	 * before trying to remove the tree, update directory permissions
	 * to ensure we can traverse the tree.
	 */
	if (root) {
		cmd = strfmt("/usr/bin/rm -fr %s", pathname);
	} else {
		cmd = strfmt("/usr/bin/chmod -R u+rwx %s ; /usr/bin/rm -fr %s",
			     pathname, pathname);
	}
	if (!cmd)
		return -1;

	error = system(cmd);

	return error ? -1 : 0;
}

#else

#include <fts.h>

static int __rmtree(char *pathname, bool root)
{
	char *path_argv[] = { pathname, NULL };
	FTSENT *ent;
	int error;
	FTS *fts;
	int err;

	fts = fts_open(path_argv, FTS_PHYSICAL | FTS_NOSTAT | FTS_XDEV, NULL);
	if (!fts)
		return -1;

	error = 0;
	while ((ent = fts_read(fts)) != NULL) {
		switch (ent->fts_info) {

		case FTS_D:
			/*
			 * Change directory permissions to ensure we can
			 * read it and remove entries. Ignore any error,
			 * we will try the traversal/removal anyway.
			 */
			if (!root)
				(void) chmod(ent->fts_path, 0777);
			break;

		case FTS_DP:
			err = rmdir(ent->fts_path);
			if (err)
				error++;
			break;

		case FTS_DEFAULT:
		case FTS_F:
		case FTS_NSOK:
		case FTS_SL:
		case FTS_SLNONE:
			err = unlink(ent->fts_path);
			if (err)
				error++;
			break;

		case FTS_DOT:
		case FTS_DC:
			break;

		case FTS_DNR:
		case FTS_ERR:
		case FTS_NS:
			/* error */
			error++;
			break;

		}
	}

	fts_close(fts);

	return error ? -1 : 0;
}

#endif

int rmtree(char *pathname)
{
	struct stat st;
	bool root;
	int err;

	err = stat(pathname, &st);
	if (err)
		return -1;

	if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return -1;
	}

	root = (geteuid() == 0);

	/*
	 * Safeguard if root is using the command: check that the path
	 * to remove starts with the root prefix. This is an attempt
	 * to prevent mistakes such as removing critical directories.
	 */
	if (root) {
		if (!rmtree_root_prefix) {
			errno = EPERM;
			return -1;
		}
		if (strncmp(pathname, rmtree_root_prefix,
			    strlen(rmtree_root_prefix)) != 0) {
			errno = EPERM;
			return -1;
		}
	}

	return __rmtree(pathname, root);
}

static int __mktree_at(int dirfd, const char *pathname, mode_t mode,
		       bool path_is_filename)
{
	struct stat stat;
	char *path;
	char *str;
	int rv;

	path = strdup(pathname);
	if (!path)
		return -1;

	str = path;
	/* skip the initial slash as the root directory always exits */
	if (*str == '/')
		str++;

	while (1) {

		/* break the string down to the next parent */
		str = strchr(str, '/');
		if (str)
			*str = '\0';
		else if (path_is_filename)
			break;

		rv = fstatat(dirfd, path, &stat,
			     AT_EMPTY_PATH | AT_NO_AUTOMOUNT |
			     AT_SYMLINK_NOFOLLOW);
		if (rv == 0) {
			/*
			 * If a parent path exists, ensure that it is
			 * a directory.
			 */
			if (!S_ISDIR(stat.st_mode))
				goto error;
		} else {
			/*
			 * If a parent path doesn't exist then create
			 * it as a directory.
			 */
			if (errno != ENOENT)
				goto error;

			rv = mkdirat(dirfd, path, mode);
			if (rv)
				goto error;
		}

		if (!str)
			break;

		/* restore the delimiter of the parent */
		*(str++) = '/';
	}

	free(path);
	return 0;

error:
	free(path);
	return -1;
}

int mktree(const char *dirname, mode_t mode)
{
	return __mktree_at(AT_FDCWD, dirname, mode, false);
}

int mktree_at(int dirfd, const char *dirname, mode_t mode)
{
	return __mktree_at(dirfd, dirname, mode, false);
}

int mktree_for_file(const char *filename, mode_t mode)
{
	return __mktree_at(AT_FDCWD, filename, mode, true);
}

int mktree_for_file_at(int dirfd, const char *filename, mode_t mode)
{
	return __mktree_at(dirfd, filename, mode, true);
}

/*
 * Convert a nibble (i.e. a four-bit aggregation) to the corresponding
 * hex digit (0-F).
 */
static char nibble2hexdigit(unsigned char n)
{
	return (n < 10) ? '0' + n : 'A' + (n - 10);
}

/*
 * Return true if a character is an unreserved character according to
 * RFC 3986, i.e. if a character is allowed in a URI and does not have
 * a reserved purposed.
 */
static bool is_unreserved_char(char c)
{
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~');
}

/*
 * Escape all non-unreserved characters, except slash ('/') characters,
 * in the specified path using URL encoding (aka percent encoding).
 *
 * Return the original path if no character was escaped, or a pointer
 * to a newly allocated string containing the escaped path.
 */
char *escape_path(const char *path)
{
	char *escaped_path;
	unsigned char c;
	int len, count;
	const char *p;
	char *e;
	int i;

	/*
	 * Check how many characters need to be escaped, and compute
	 * the length of the path.
	 */
	count = 0;
	len = 0;
	for (p = path; *p; p++) {
		len++;
		if (*p != '/' && !is_unreserved_char(*p))
			count++;
	}

	if (!count)
		return (char *)path;

	/*
	 * The escaped path will have two extra characters for each
	 * escape character.
	 */
	escaped_path = malloc(len + count * 2 + 1);
	if (!escaped_path)
		return NULL;

	/*
	 * Copy the path and escape required characters.
	 */
	e = escaped_path;
	for (i = 0; i < len; i++) {
		c = path[i];
		if (is_unreserved_char(c) || c == '/') {
			*e++ = path[i];
			continue;
		}
		*e++ = '%';
		*e++ = nibble2hexdigit(c >> 4);
		*e++ = nibble2hexdigit(c & 0xf);
	}

	*e = '\0';

	return escaped_path;
}

/*
 * Expand a pathname. A name starting with "~/" or a relative name
 * is expanded relative to the home directory. No other expansion
 * is done.
 *
 * Return the expanded pathname, or NULL in case of an error.
 */
char *expand_path(const char *pathname)
{
	char *home;

	/* absolute path */
	if (pathname[0] == '/')
		return strdup(pathname);

	/* (home) relative path */
	home = getenv("HOME");
	if (!home)
		return NULL;

	if (strncmp(pathname, "~/", 2) == 0)
		pathname += 2;

	return strfmt("%s/%s", home, pathname);
}

void mutex_lock(pthread_mutex_t *mutex)
{
	int err;

	err = pthread_mutex_lock(mutex);
	while (err) {
		assert(err == EAGAIN);
		err = pthread_mutex_lock(mutex);
	}
}

void mutex_unlock(pthread_mutex_t *mutex)
{
	int err;

	err = pthread_mutex_unlock(mutex);
	assert(!err);
}

void rw_rdlock(pthread_rwlock_t *rwlock)
{
	int err;

	err = pthread_rwlock_rdlock(rwlock);
	while (err) {
		assert(err == EAGAIN);
		err = pthread_rwlock_rdlock(rwlock);
	}
}

void rw_wrlock(pthread_rwlock_t *rwlock)
{
	int err;

	err = pthread_rwlock_wrlock(rwlock);
	while (err) {
		assert(err == EAGAIN);
		err = pthread_rwlock_wrlock(rwlock);
	}
}

void rw_unlock(pthread_rwlock_t *rwlock)
{
	int err;

	err = pthread_rwlock_unlock(rwlock);
	assert(!err);
}

void cv_wait(pthread_cond_t *cv, pthread_mutex_t *mutex)
{
	int err;

	err = pthread_cond_wait(cv, mutex);
	assert(!err);
}

int cv_timedwait(pthread_cond_t *cv, pthread_mutex_t *mutex,
		 struct timespec *abstime)
{
	int err;

	err = pthread_cond_timedwait(cv, mutex, abstime);
	assert(!err || err == ETIMEDOUT);
	return err;
}

void cv_signal(pthread_cond_t *cv)
{
	int err;

	err = pthread_cond_signal(cv);
	assert(!err);
}
