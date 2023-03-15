/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "utils.h"

/*
 * Data Store (dstore)
 *
 * Data Store encapsulate storage mechanism, such as a memory buffer or
 * a file, and provides a unify interface to read/write data no matter
 * what the backend storage is.
 */

struct dstore *dstore_create(enum dstore_type type)
{
	struct dstore *dstore;

	dstore = malloc(sizeof(*dstore));
	if (!dstore)
		return NULL;

	dstore->type = DSTORE_TYPE_NONE;

	return dstore;
}

void dstore_init(struct dstore *dstore)
{
	dstore->type = DSTORE_TYPE_NONE;
}

void dstore_clear(struct dstore *dstore)
{
	if (!dstore)
		return;

	switch (dstore->type) {

	case DSTORE_TYPE_NONE:
	case DSTORE_TYPE_FD:
	case DSTORE_TYPE_BUFFER_STATIC:
		break;

	case DSTORE_TYPE_BUFFER_DYNAMIC:
		free(dstore->buffer.addr);
		break;
	}
}

void dstore_wrap_fd(struct dstore *dstore, int fd)
{
	if (!dstore)
		return;

	dstore_clear(dstore);
	dstore->type = DSTORE_TYPE_FD;
	dstore->file.fd = fd;
}

/*
 * Wrap a memory buffer as a dstore.
 *
 * If buffer is not NULL then create a static buffer with the specified
 * buffer size.
 *
 * If buffer is NULL then create a dynamic buffer. The buffer will be
 * dynamically allocated on the first write. During a write, the buffer
 * is reallocated if it is too small. The buffer is allocated with the
 * size of the data it should hold + the specified buffer size (if any).
 */
int dstore_wrap_buffer(struct dstore *dstore, char *buffer, size_t buffer_size)
{
	if (!dstore)
		return 0;

	dstore_clear(dstore);

	if (!buffer) {
		dstore->type = DSTORE_TYPE_BUFFER_DYNAMIC;
		dstore->buffer.size_increment = buffer_size;
		dstore->buffer.size_used = 0;
		dstore->buffer.size_alloc = 0;
	} else {
		if (!buffer_size) {
			dstore->type = DSTORE_TYPE_NONE;
			return -1;
		}
		dstore->type = DSTORE_TYPE_BUFFER_STATIC;
		dstore->buffer.size_increment = 0;
		dstore->buffer.size_used = buffer_size;
		dstore->buffer.size_alloc = buffer_size;
	}

	dstore->buffer.addr = buffer;
	dstore->buffer.offset = 0;

	return 0;
}

ssize_t dstore_size(struct dstore *dstore)
{
	struct stat stat;
	ssize_t size;
	int err;

	if (!dstore)
		return 0;

	switch (dstore->type) {

	case DSTORE_TYPE_NONE:
		size = 0;
		break;

	case DSTORE_TYPE_BUFFER_STATIC:
	case DSTORE_TYPE_BUFFER_DYNAMIC:
		size = dstore->buffer.size_used;
		break;

	case DSTORE_TYPE_FD:
		err = fstat(dstore->file.fd, &stat);
		if (err)
			return -1;
		size = stat.st_size;
		break;

	default:
		return -1;
	}

	return size;
}

char *dstore_buffer(struct dstore *dstore)
{
	char *buffer;

	if (!dstore)
		return NULL;

	switch (dstore->type) {

	case DSTORE_TYPE_BUFFER_STATIC:
	case DSTORE_TYPE_BUFFER_DYNAMIC:
		buffer = dstore->buffer.addr;
		break;

	default:
		buffer = NULL;
		break;
	}

	return buffer;
}

char *dstore_fetch_buffer(struct dstore *dstore)
{
	char *buffer;

	if (!dstore)
		return NULL;

	buffer = dstore_buffer(dstore);
	if (dstore->type == DSTORE_TYPE_BUFFER_DYNAMIC)
		dstore->buffer.addr = NULL;

	return buffer;
}

/*
 * Read from dstore buffer to buf
 */
static ssize_t dstore_buffer_read(struct dstore *dstore,
				  void *buf, size_t count)
{
	size_t buffer_space, buffer_size, size;
	off_t buffer_offset;

	if (!count)
		return 0;

	buffer_offset = dstore->buffer.offset;
	buffer_size = dstore->buffer.size_used;

	if (buffer_offset > buffer_size)
		return 0;

	buffer_space = buffer_size - buffer_offset;
	size = buffer_space < count ? buffer_space : count;

	memcpy(buf, dstore->buffer.addr + buffer_offset, size);

	dstore->buffer.offset += size;

	return size;
}

/*
 * Write to dstore buffer from buf
 */
static ssize_t dstore_buffer_write(struct dstore *dstore,
				   void *buf, size_t count)
{
	size_t buffer_space, buffer_size, size;
	off_t buffer_offset;
	char *buffer;

	if (!count)
		return 0;

	buffer_offset = dstore->buffer.offset;
	buffer_size = dstore->buffer.size_alloc;

	buffer_space = buffer_offset >= buffer_size ?
		0 : buffer_size - buffer_offset;

	/*
	 * If the buffer doesn't have room for the write then shrink
	 * the write if the buffer is static, or increase the buffer
	 * if it is dynamic.
	 */
	if (buffer_space < count) {
		if (dstore->type == DSTORE_TYPE_BUFFER_DYNAMIC) {
			buffer_size += count + dstore->buffer.size_increment;
			/*
			 * A dynamic buffer is allocated with an extra
			 * byte so that a trailing '\0' can always be
			 * added to terminate a string buffer.
			 */
			buffer = realloc(dstore->buffer.addr, buffer_size + 1);
			if (!buffer)
				return 0;
			dstore->buffer.addr = buffer;
			dstore->buffer.size_alloc = buffer_size;
			size = count;
		} else {
			size = buffer_space;
		}
	} else {
		size = count;
	}

	memcpy(dstore->buffer.addr + buffer_offset, buf, size);

	dstore->buffer.offset += size;

	if (dstore->type == DSTORE_TYPE_BUFFER_DYNAMIC &&
	    dstore->buffer.offset > dstore->buffer.size_used)
		dstore->buffer.size_used = dstore->buffer.offset;

	return size;
}

/*
 * Read from dstore to buf
 */
ssize_t dstore_read(struct dstore *dstore, void *buf, size_t count)
{
	ssize_t size;

	switch (dstore->type) {

	case DSTORE_TYPE_FD:
		size = read(dstore->file.fd, buf, count);
		break;

	case DSTORE_TYPE_BUFFER_STATIC:
	case DSTORE_TYPE_BUFFER_DYNAMIC:
		size = dstore_buffer_read(dstore, buf, count);
		break;

	default:
		size = -1;
		break;
	}

	return size;
}

/*
 * Write to dstore from buf
 */
ssize_t dstore_write(struct dstore *dstore, void *buf, size_t count)
{
	ssize_t size;

	switch (dstore->type) {

	case DSTORE_TYPE_FD:
		size = write(dstore->file.fd, buf, count);
		break;

	case DSTORE_TYPE_BUFFER_STATIC:
	case DSTORE_TYPE_BUFFER_DYNAMIC:
		size = dstore_buffer_write(dstore, buf, count);
		break;

	default:
		size = -1;
		break;
	}

	return size;
}

static int dstore_file_sha256_update(struct dstore *dstore, SHA256_CTX *sha_ctx)
{
	int buffer_size = 1024;
	char buffer[buffer_size];
	off_t offset;
	size_t size;
	int fd;
	int rv;

	fd = dstore->file.fd;
	rv = 1;
	offset = 0;
	/* use pread() to not change the file offset */
	while ((size = pread(fd, buffer, buffer_size, offset)) > 0) {
		rv = SHA256_Update(sha_ctx, buffer, size);
		if (rv != 1)
			break;
		offset += size;
	}

	return rv;
}

int dstore_sha256(struct dstore *dstore, unsigned char *digest)
{
	SHA256_CTX sha_ctx;
	int rv;

	rv = SHA256_Init(&sha_ctx);
	if (rv != 1)
		return -1;

	switch (dstore->type) {

	case DSTORE_TYPE_FD:
		rv = dstore_file_sha256_update(dstore, &sha_ctx);
		break;

	case DSTORE_TYPE_BUFFER_STATIC:
	case DSTORE_TYPE_BUFFER_DYNAMIC:
		rv = SHA256_Update(&sha_ctx, dstore->buffer.addr,
				   dstore->buffer.size_used);
		break;

	default:
		return -1;
	}

	if (rv != 1)
		return -1;

	rv = SHA256_Final(digest, &sha_ctx);
	if (rv != 1)
		return -1;

	return 0;

}
