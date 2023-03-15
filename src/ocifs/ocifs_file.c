/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <errno.h>
#include <string.h>

#include "ocifs.h"

/*
 * OCI objects are automatically cached when accessed through OCIFS,
 * except if the object has a name which is incompatible with caching.
 *
 * OCI object names use from 1 to 1024 characters, valid characters are
 * letters (upper or lower case), numbers, and characters other than line
 * feed, carriage return, and NULL.
 *
 * Linux has a maximum path length of 4096 characters (so larger than
 * the OCI object name limit), but the maximum filename length is 255
 * characters for most filesystems (in particular for ext4) so below
 * the OCI object name limit of 1024.
 *
 * When an OCI object is not cached:
 * - write(), truncate() are not supported
 * - chmod(), chown(), utimens() are not supported
 * - all other operations are supported but they can be slower (because
 *   there is no cache)
 *
 * OCIFS operations which create new OCI object names (creat(), mkdir(),
 * rename()) can only be used to create names which are compatible with
 * caching.
 *
 * An OCI object with a name incompatible with caching can be renamed
 * (using rename()) with a name compatible with caching. After that,
 * all OCIFS operations are possible.
 */

struct ocifs_io {
	struct ocifs_cache_handle *handle;
	const char *path;
	char *buf;
	off_t offset;
	size_t size;
	ssize_t count;
};

/*
 * The maximum size of a file that we can write back to OCI is limited
 * to the OCI put object maximum size (50GiB). To go beyond this limit,
 * (up to 10TiB) we need to support multipart uploads.
 */
#define OCIFS_WRITE_MAX OCI_PUT_OBJECT_SIZE_MAX

static int ocifs_flush_handle(const char *path,
			      struct ocifs_cache_handle *handle);
static int ocifs_getattr_locked(const char *path, struct stat *stbuf,
				struct ocifs_cache_ref **refp, bool cache);
static int ocifs_fill_range(off_t begin, off_t end, enum range_overlap overlap,
			    void *data);

/*
 * Functions to store and get an OCIFS cache handle in a FUSE file
 * handle.
 */
static void ocifs_set_fuse_fh(struct fuse_file_info *fi,
			      struct ocifs_cache_handle *cache)
{
	fi->fh = (uint64_t)(long)cache;
}

static struct ocifs_cache_handle *ocifs_get_fuse_fh(struct fuse_file_info *fi)
{
	return (struct ocifs_cache_handle *)(long)fi->fh;
}

/*
 * Get the actual path to a file or directory, and validate that path.
 * The information whether the path can be cached or not is returned
 * if cacheablep is not NULL.
 *
 * If the path is not valid for OCI, or if it is not valid for cache
 * and cache information was not requested (cacheablep is NULL) then
 * fail and return NULL.
 *
 * If there is no subfolder then the specified path is the actual path.
 * If there is a subfolder then the specified path is relative the
 * subfolder.
 */
const char *ocifs_get_path(const char *path, bool *cacheablep)
{
	int rv;

	if (path[0] == '/')
		path++;

	if (path[0] == '\0') {
		if (ocifs_subfolder)
			path = strdup(ocifs_subfolder);
		return path;
	}

	if (ocifs_subfolder)
		path = strfmt("%s/%s", ocifs_subfolder, path);

	if (!path)
		return NULL;

	rv = ocifs_cache_validate_path(ocifs_cache, path);

	if (rv == 0) {
		/* path is valid for OCI and for cache */
		if (cacheablep)
			*cacheablep = true;
		return path;
	}

	if (rv > 0 && cacheablep) {
		/* path is valid for OCI but not for cache */
		*cacheablep = false;
		return path;
	}

	/*
	 * The path is not valid for OCI, or it is not valid for cache
	 * and cache information was not requested. Then fail.
	 */

	ocifs_release_path(path);
	return NULL;
}

/*
 * Release a path.
 */
void ocifs_release_path(const char *path)
{
	if (ocifs_subfolder)
		free((char *)path);
}

int ocifs_getattr(const char *path, struct stat *stbuf)
{
	struct ocifs_cache_ref *ref;
	bool path_cacheable;
	bool use_cache;
	int rv;

#ifdef DEBUG
	OCIFS_DEBUG_FOPS("getattr %s\n", path);
#endif

	bzero(stbuf, sizeof(*stbuf));

	if (strcmp(path, "/") == 0) {
		rv = ocifs_cache_getattr_root(ocifs_cache, stbuf);
		return rv ? -errno : 0;
	}

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	use_cache = OCIFS_CACHE_USABLE(path_cacheable);

	ocifs_ns_rdlock(path);
	rv = ocifs_getattr_locked(path, stbuf, &ref, use_cache);
	ocifs_cache_unref(ref);
	ocifs_ns_unlock(path);

	ocifs_release_path(path);

	return rv;
}

static int ocifs_getattr_locked(const char *path, struct stat *stbuf,
				struct ocifs_cache_ref **refp, bool use_cache)
{
	int rv;

	*refp = NULL;

	if (use_cache) {
		rv = ocifs_cache_getattr(ocifs_cache, path, stbuf, refp);
		if (rv < 0)
			return -errno;

		if (rv)
			return 0;
	}

	rv = ocifs_cloud_getattr(path, stbuf);
	if (rv < 0)
		return -EIO;

	if (!rv)
		return -ENOENT;

	if (!use_cache)
		return 0;

	/*
	 * Add a cache entry for the object. We don't report the failure
	 * to add a cache entry as this won't prevent the filesystem
	 * from working. If a cache entry is needed later then it will be
	 * created then.
	 */

	if (S_ISDIR(stbuf->st_mode))
		(void) ocifs_cache_add_prefix(ocifs_cache, path,
					      OCIFS_CACHE_PERM_DEFAULT_DIR);
	else
		(void) ocifs_cache_add_object(ocifs_cache, path,
					      stbuf->st_size);

	return 0;
}

static int ocifs_getattr_with_cache(const char *path, struct stat *stbuf,
				    struct ocifs_cache_ref **refp)
{
	return ocifs_getattr_locked(path, stbuf, refp, true);
}

static int ocifs_open_cache(const char *path,
			    struct ocifs_cache_handle **handle_p)
{
	struct ocifs_cache_handle *handle;
	struct ocifs_cache_ref *ref;
	struct stat stat;
	int rv;

	rv = ocifs_cache_getattr(ocifs_cache, path, &stat, &ref);
	if (rv < 0)
		return -1;
	if (rv == 0)
		return 0;

	/*
	 * We don't need a cache handle for a directory because
	 * operations using the cache handle (read, write...) are
	 * not supported for a directory.
	 */
	if (S_ISDIR(stat.st_mode)) {
		ocifs_cache_unref(ref);
		*handle_p = NULL;
		return 0;
	}

	/*
	 * Once the object is opened, we can release the reference
	 * because the handle will add its own reference.
	 */
	handle = ocifs_cache_open_object(ocifs_cache, path);
	if (!handle) {
		ocifs_cache_unref(ref);
		return -1;
	}

	ocifs_cache_unref(ref);
	*handle_p = handle;

	return 1;
}

static int ocifs_open_cloud(const char *path,
			    struct ocifs_cache_handle **handle_p,
			    bool use_cache)
{
	struct ocifs_cache_handle *handle;
	struct stat stat;
	int rv;

	rv = ocifs_cloud_getattr(path, &stat);
	if (rv < 0)
		return -1;
	if (rv == 0)
		return 0;

	/*
	 * For a directory, create a cache entry if the directory can be
	 * cached. We don't need a cache handle because operations using
	 * the cache handle (read, write...) are not supported for a
	 * directory.
	 */
	if (S_ISDIR(stat.st_mode)) {
		if (use_cache) {
			(void) ocifs_cache_add_prefix(ocifs_cache, path,
						      OCIFS_CACHE_PERM_DEFAULT_DIR);
		}
		*handle_p = NULL;

		return 1;
	}

	/*
	 * If the object can be cached then create a cache entry,
	 * otherwise just create a cache handle with no entry in
	 * the cache directory. In that case, the cache handle is
	 * used to just cache the object size.
	 */
	if (use_cache) {
		handle = ocifs_cache_create_object(ocifs_cache, path,
						   stat.st_size,
						   OCIFS_CACHE_PERM_DEFAULT_FILE);
	} else {
		/*
		 * Note that this is also called when cache is disabled
		 */
		handle = ocifs_cache_create_handle(ocifs_cache, path,
						   stat.st_size);
	}

	if (!handle)
		return -1;

	*handle_p = handle;

	return 1;
}

static int ocifs_open_handle(const char *path,
			     struct ocifs_cache_handle **handle_p,
			     bool use_cache)
{
	int err;
	int rv;

	ocifs_ns_rdlock(path);

	if (use_cache) {
		rv = ocifs_open_cache(path, handle_p);
		if (rv < 0) {
			err = -errno;
			goto error;
		}
		if (rv > 0)
			goto done;
	}

	rv = ocifs_open_cloud(path, handle_p, use_cache);
	if (rv < 0) {
		err = -EIO;
		goto error;
	}
	if (rv == 0) {
		err = -ENOENT;
		goto error;
	}

done:
	ocifs_ns_unlock(path);
	return 0;

error:
	ocifs_ns_unlock(path);
	return err;
}

int ocifs_open(const char *path, struct fuse_file_info *fi)
{
	struct ocifs_cache_handle *handle;
	bool path_cacheable;
	bool use_cache;
	int rv;

	OCIFS_DEBUG_FOPS("open %s\n", path);

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	use_cache = OCIFS_CACHE_USABLE(path_cacheable);

	rv = ocifs_open_handle(path, &handle, use_cache);
	if (rv) {
		ocifs_release_path(path);
		return rv;
	}

	ocifs_release_path(path);

	ocifs_set_fuse_fh(fi, handle);

	return 0;
}

int ocifs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct ocifs_cache_handle *handle;
	int err;
	int rv;

	OCIFS_DEBUG_FOPS("create %s mode=%o\n", path, mode);

	path = ocifs_get_path(path, NULL);
	if (!path)
		return -errno;

	if (OCIFS_CACHE_DISABLED()) {
		ocifs_release_path(path);
		return -ENOTSUP;
	}

	ocifs_ns_wrlock(path);

	rv = ocifs_cache_check_object(ocifs_cache, path);
	if (rv < 0) {
		err = -ENXIO;
		goto error;
	}
	if (rv > 0) {
		err = -EEXIST;
		goto error;
	}

	rv = ocifs_cloud_check_object(path);
	if (rv < 0) {
		err = -EIO;
		goto error;
	}
	if (rv > 0) {
		err = -EEXIST;
		goto error;
	}

	/*
	 * Create the entry in cache only. It will be flushed to cloud
	 * when flushing.
	 */
	handle = ocifs_cache_create_object(ocifs_cache, path, 0, mode);
	if (!handle) {
		err = -EIO;
		goto error;
	}

	/*
	 * Make sure the cache entry has the appropriate ownership.
	 */
	rv = ocifs_cache_adjust_ownership(ocifs_cache, path);
	if (rv) {
		err = -errno;
		ocifs_cache_close(handle);
		ocifs_cache_invalidate(ocifs_cache, path);
		goto error;
	}

	ocifs_ns_unlock(path);
	ocifs_release_path(path);

	/*
	 * Cache is dirty because the object doesn't exist in cloud.
	 */
	ocifs_cache_set_dirty(handle);

	ocifs_set_fuse_fh(fi, handle);

	return 0;

error:
	ocifs_ns_unlock(path);
	ocifs_release_path(path);
	return err;
}

static int ocifs_unlink_cache(const char *path)
{
	struct ocifs_cache_handle *handle;
	size_t size;
	int rv;

	/* open the file to get a cache handle */
	handle = ocifs_cache_open_object(ocifs_cache, path);
	if (!handle)
		return -1;

	/* now that we have a handle, we can remove the cache file */
	rv = ocifs_cache_unlink(ocifs_cache, path);
	if (rv < 0) {
		ocifs_cache_close(handle);
		return rv;
	}

	/*
	 * If there is no other reference to this file then we are done.
	 */
	if (ocifs_cache_lock_refcount(handle) == 1) {
		/*
		 * We can mark the object as removed without locking the
		 * entry because the cache is locked and we are the only
		 * one referencing the entry.
		 */
		ocifs_cache_set_removed(handle);
		ocifs_cache_close_locked(handle);
		return 0;
	}

	ocifs_cache_unlock_refcount(handle);

	/*
	 * We are removing an opened object. We have to ensure that the
	 * cache file is filled with all object data so that I/Os can
	 * continue without cloud access.
	 *
	 * If we are unable to do that, subsequent I/Os (done from
	 * already opened file handles) can then fail.
	 */

	ocifs_cache_lock_entry(handle);

	size = ocifs_cache_get_size(handle);
	if (size > 0) {
		(void) ocifs_cache_walk_data(handle, 0, size, ocifs_fill_range,
					     handle);
	}

	/*
	 * Mark the object as removed. This will prevent the file to be
	 * flushed to cloud when it gets closed, and also prevent I/Os
	 * to try to get data from the cloud.
	 */
	ocifs_cache_set_removed(handle);

	ocifs_cache_unlock_entry(handle);

	ocifs_cache_close(handle);

	return 0;
}

static int ocifs_unlink_locked(const char *path, bool use_cache)
{
	int rv;

	if (use_cache) {
		rv = ocifs_unlink_cache(path);
		if (rv < 0)
			return -ENXIO;
	}

	rv = ocifs_cloud_unlink(path);
	if (rv < 0)
		return -EIO;
	if (!rv)
		return -ENOENT;

	return 0;
}

int ocifs_unlink(const char *path)
{
	bool path_cacheable;
	int err;

	OCIFS_DEBUG_FOPS("unlink %s\n", path);

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	ocifs_ns_wrlock(path);

	err = ocifs_unlink_locked(path, OCIFS_CACHE_USABLE(path_cacheable));

	ocifs_ns_unlock(path);
	ocifs_release_path(path);
	return err;
}

int ocifs_truncate(const char *path, off_t length)
{
	struct ocifs_cache_handle *handle;
	bool path_cacheable;
	bool use_cache;
	int err;

	OCIFS_DEBUG_FOPS("truncate %s - %jd\n", path, length);

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	if (length > OCIFS_WRITE_MAX) {
		ocifs_release_path(path);
		return -EFBIG;
	}

	if (OCIFS_CACHE_DISABLED()) {
		ocifs_release_path(path);
		return -ENOTSUP;
	}

	use_cache = OCIFS_CACHE_USABLE(path_cacheable);

	/*
	 * truncate = open, truncate cache file, close
	 */

	err = ocifs_open_handle(path, &handle, use_cache);
	if (err) {
		ocifs_release_path(path);
		return err;
	}

	err = ocifs_cache_truncate(handle, length);
	if (err) {
		err = -errno;
		ocifs_cache_close(handle);
		ocifs_release_path(path);
		return -err;
	}

	/*
	 * If oci_flush_handle() fails then we can have a discrepancy
	 * between the cloud object and the cache file. So report an
	 * error and remove the cache file so that the object is cached
	 * again the next time it is accessed.
	 *
	 * XXX what we do with opened file? restore file size?
	 */
	err = ocifs_flush_handle(path, handle);
	ocifs_cache_close(handle);
	if (err) {
		if (use_cache)
			ocifs_cache_unlink(ocifs_cache, path);
		ocifs_release_path(path);
		return err;
	}

	ocifs_release_path(path);

	return 0;
}

static int ocifs_read_range(off_t begin, off_t end, enum range_overlap overlap,
			    void *data)
{
	struct ocifs_io *io = data;
	ssize_t count;
	off_t offset;
	size_t size;
	char *buf;

	if (begin < io->offset || end > io->offset + io->size)
		return RANGE_WALK_ERROR;

	buf = io->buf + (begin - io->offset);
	offset = begin;
	size = end - begin + 1;

	/*
	 * If the range to read overlaps with a range in cache then
	 * read from cache, otherwise read from the cloud and cache
	 * read data.
	 */
	if (overlap) {
		count = ocifs_cache_read(io->handle, buf, size, offset);
	} else if (ocifs_cache_is_removed(io->handle)) {
		/*
		 * The object has been removed and data are not in the
		 * cache so we have no way to get the data.
		 */
		count = -1;
	} else {
		count = ocifs_cloud_read(io->path, buf, size, offset);

		/*
		 * Cache data we just read from the cloud.
		 *
		 * Do not report an error if write to cache fails. Data
		 * are successfully read, they will just not be be
		 * cached.
		 *
		 * Caching data doesn't make the cache dirty because we
		 * are caching data which are already stored in the cloud.
		 */
		if (count > 0)
			(void) ocifs_cache_write(io->handle, buf, size, offset);
	}

	if (count < 0)
		return RANGE_WALK_ERROR;

	io->count += count;

	return RANGE_WALK_CONTINUE;
}

int ocifs_read(const char *path, char *buf, size_t size, off_t offset,
	       struct fuse_file_info *fi)
{
	struct ocifs_cache_handle *handle = ocifs_get_fuse_fh(fi);
	bool path_cacheable;
	size_t object_size;
	struct ocifs_io io;
	bool use_cache;
	ssize_t count;
	int err;

	OCIFS_DEBUG_FOPS("read %s - %jd, %zd\n", path, offset, size);

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	use_cache = OCIFS_CACHE_USABLE(path_cacheable);

	/*
	 * If we use the cache then validate the handle and lock the
	 * entry. Otherwise there is no need to lock because the object
	 * is read-only.
	 */
	if (use_cache) {
		err = ocifs_cache_validate_handle(handle, path);
		if (err) {
			ocifs_release_path(path);
			return -ENXIO;
		}

		ocifs_cache_lock_entry(handle);
	}

	object_size = ocifs_cache_get_size(handle);

	if (offset >= object_size) {
		ocifs_release_path(path);
		if (use_cache)
			ocifs_cache_unlock_entry(handle);
		return 0;
	}

	if (offset + size > object_size)
		size = object_size - offset;

	if (!use_cache) {
		/* read everything from cloud */
		count = ocifs_cloud_read(path, buf, size, offset);
		ocifs_release_path(path);
		if (count < 0)
			return -EIO;
		return count;
	}

	/* read from cache */

	io.handle = handle;
	io.path = path;
	io.buf = buf;
	io.offset = offset;
	io.size = size;
	io.count = 0;

	/*
	 * Walk the cache to read data either from the cache if data
	 * have been cached, or from the cloud if data were not cached.
	 */
	err = ocifs_cache_walk_data(handle, offset, size,
				    ocifs_read_range, &io);
	if (err) {
		ocifs_cache_unlock_entry(handle);
		ocifs_release_path(path);
		return -ENXIO;
	}

	ocifs_cache_unlock_entry(handle);

	ocifs_release_path(path);

	return io.count;
}

int ocifs_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	struct ocifs_cache_handle *handle = ocifs_get_fuse_fh(fi);
	size_t file_size;
	ssize_t count;
	int err;

	OCIFS_DEBUG_FOPS("write %s - %jd, %zd\n", path, offset, size);

	path = ocifs_get_path(path, NULL);
	if (!path)
		return -errno;

	ocifs_release_path(path);

	if (OCIFS_CACHE_DISABLED())
		return -ENOTSUP;

	/*
	 * Write should not extend the file past the maximum
	 * write size.
	 */
	if (offset + size > OCIFS_WRITE_MAX)
		return -EFBIG;

	ocifs_cache_lock_entry(handle);

	/*
	 * Write is not possible if the file is larger than the
	 * maximum write size.
	 */
	file_size = ocifs_cache_get_size(handle);
	if (file_size > OCIFS_WRITE_MAX) {
		ocifs_cache_unlock_entry(handle);
		return -EFBIG;
	}

	/*
	 * Write data to cache only. Data will be written to cloud when
	 * the file is flushed.
	 */
	count = ocifs_cache_write(handle, buf, size, offset);
	if (count < 0) {
		err = errno == ENOSPC ? ENOSPC : EIO;
		ocifs_cache_unlock_entry(handle);
		return -err;
	}

	/*
	 * Cached data are not on the cloud, so the cache is dirty and
	 * will need to be flushed.
	 */
	ocifs_cache_set_dirty(handle);

	ocifs_cache_unlock_entry(handle);

	return count;
}

static int ocifs_fill_range(off_t begin, off_t end, enum range_overlap overlap,
			    void *data)
{
	struct ocifs_cache_handle *handle = data;
	const char *name;
	size_t size;
	int err;
	int fd;

	name = ocifs_cache_get_name(handle);
	fd = ocifs_cache_get_file(handle);

	/*
	 * If the object range overlaps with a range in cache then we
	 * have up-to-date data in cache for this range. Otherwise we
	 * have to read data for that range from the object to the
	 * cache file.
	 */
	if (overlap) {
		OCIFS_DEBUG_CACHE("fill %s [%jd, %jd]: range is defined\n",
				  name, begin, end);
		return RANGE_WALK_CONTINUE;
	}

	OCIFS_DEBUG_CACHE("fill %s [%jd, %jd]: filling from cloud\n",
			  name, begin, end);

	err = ocifs_cache_seek(handle, begin);
	if (err)
		return RANGE_WALK_ERROR;

	size = ocifs_cloud_read_to_file(name, fd, end - begin + 1, begin);
	if (size < 0)
		return RANGE_WALK_ERROR;

	/*
	 * Indicate that a range of the cache has been filled with data.
	 */
	err = ocifs_cache_filled(handle, begin, end - begin + 1);
	if (err)
		return RANGE_WALK_ERROR;

	return RANGE_WALK_CONTINUE;
}

static int ocifs_flush_handle(const char *path, struct ocifs_cache_handle *handle)
{
	size_t size;
	int err;
	int fd;

	ocifs_cache_lock_entry(handle);

	if (!ocifs_cache_is_dirty(handle)) {
		ocifs_cache_unlock_entry(handle);
		return 0;
	}

	/*
	 * If the object has been removed then data shouldn't be copied
	 * to the cloud.
	 */
	if (ocifs_cache_is_removed(handle)) {
		ocifs_cache_unlock_entry(handle);
		return 0;
	}

	size = ocifs_cache_get_size(handle);

	/*
	 * Fastpath if the object is empty.
	 */
	if (!size) {
		err =  ocifs_cloud_add_object(path, NULL, 0);
		if (err) {
			ocifs_cache_unlock_entry(handle);
			return -EIO;
		}

		ocifs_cache_set_clean(handle);

		ocifs_cache_unlock_entry(handle);
		return 0;
	}

	/*
	 * An OCI FS file is flushed by putting the cache file of the
	 * object to the cloud. The cache is filled only for ranges of
	 * data which have been read or written. So, we first need to
	 * fill "holes" in the cache file with data from the cloud
	 * object. Then, we can put the new object on the cloud.
	 */
	err = ocifs_cache_walk_data(handle, 0, size, ocifs_fill_range, handle);
	if (err) {
		ocifs_cache_unlock_entry(handle);
		return -ENXIO;
	}

	fd = ocifs_cache_get_file(handle);

	err = ocifs_cloud_add_object_from_file(path, fd);
	if (err) {
		ocifs_cache_unlock_entry(handle);
		return -EIO;
	}

	ocifs_cache_set_clean(handle);

	ocifs_cache_unlock_entry(handle);

	return 0;
}

int ocifs_flush(const char *path, struct fuse_file_info *fi)
{
	struct ocifs_cache_handle *handle = ocifs_get_fuse_fh(fi);
	bool path_cacheable;
	int rv;

	OCIFS_DEBUG_FOPS("flush %s\n", path);

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	if (!OCIFS_CACHE_USABLE(path_cacheable)) {
		/* we should have nothing to flush when not caching */
		ocifs_release_path(path);
		return 0;
	}

	rv = ocifs_flush_handle(path, handle);

	ocifs_release_path(path);

	return rv;
}

int ocifs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	OCIFS_DEBUG_FOPS("fsync %s\n", path);

	/*
	 * At the moment, ocifs_fsync() and ocifs_flush() are similar:
	 * they synchronize file contents and only flush user data (as
	 * we don't persistently store any metadata).
	 *
	 * In the future, if we have metadata, ocifs_fsync() should
	 * flush metadata only when datasync is 0.
	 */

	return ocifs_flush(path, fi);
}

int ocifs_release(const char *path, struct fuse_file_info *fi)
{
	struct ocifs_cache_handle *handle = ocifs_get_fuse_fh(fi);
	size_t size;
	bool path_cacheable;
	int err;

	OCIFS_DEBUG_FOPS("release %s\n", path);

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	if (!OCIFS_CACHE_USABLE(path_cacheable)) {
		/* data are not cached, just close the handle */
		ocifs_cache_close(handle);
		ocifs_release_path(path);
		return 0;
	}

	if (ocifs_cache_lock_refcount(handle) > 1) {
		/* this is not the last reference */
		goto done_cache_locked;
	}

	/*
	 * We are releasing the last entry reference. Closing this last
	 * handle will:
	 *
	 * - either, (A) schedule the cache entry for purging, and the
	 *   purge will remove the cache file;
	 *
	 * - or, (B) immediately remove the cache entry, but keep the
	 *    cache file.
	 *
	 * We can access entry attributes without locking because
	 * the cache is locked and we are the only one referencing
	 * this entry.
	 */

	/*
	 * If there is a purge delay then the cache file will be
	 * removed (case A) after the purge delay (if the file is
	 * not re-opened in between). The cache entry and cache file
	 * are preserved until the purge.
	 */
	if (ocifs_cache_purge_enabled(ocifs_cache))
		goto done_cache_locked;

	/*
	 * Case B, the cache file is never purged, the cache entry will
	 * be removed, but not the cache file. We need to ensure that
	 * the cache file effectively caches all data from the cloud
	 * object.
	 *
	 * Fill the cache file. To prevent locking the entire cache for
	 * too long, unlock the refcount and just lock the entry. This
	 * unlock/lock sequence opens a window for the file to re-opened,
	 * but this doesn't matter as we are just forcing caching data.
	 */

	ocifs_cache_unlock_refcount(handle);
	ocifs_cache_lock_entry(handle);

	/*
	 * If the object has been removed, or the object is empty then
	 * we are done.
	 */
	if (ocifs_cache_is_removed(handle))
		goto done;

	size = ocifs_cache_get_size(handle);
	if (!size)
		goto done;

	/*
	 * Initially, the cache file is filled only for ranges of data
	 * which have been read or written. Fill "holes" in the cache
	 * file with data from the cloud object.
	 *
	 * If this fails then invalidate this cache entry.
	 */
	err = ocifs_cache_walk_data(handle, 0, size, ocifs_fill_range, handle);
	if (err)
		ocifs_cache_invalidate(ocifs_cache, path);

done:
	ocifs_cache_unlock_entry(handle);
	ocifs_cache_close(handle);
	ocifs_release_path(path);

	return 0;

done_cache_locked:
	ocifs_cache_close_locked(handle);
	ocifs_release_path(path);

	return 0;
}

/*
 * Begin a cache-only operation. Such operation cannot be done if there
 * is no cache or if the path is not compatible with caching.
 */
static const char *ocifs_cache_op_begin(const char *path,
					struct ocifs_cache_ref **refp)
{
	struct stat stat;
	int err;

	*refp = NULL;

	path = ocifs_get_path(path, NULL);
	if (!path)
		return NULL;

	if (OCIFS_CACHE_DISABLED()) {
		ocifs_release_path(path);
		return NULL;
	}

	ocifs_ns_rdlock(path);

	/*
	 * Call getattr() to check the object exists and to get it
	 * into the cache.
	 */
	err = ocifs_getattr_with_cache(path, &stat, refp);
	if (err) {
		ocifs_ns_unlock(path);
		return NULL;
	}

	return path;
}

static void ocifs_cache_op_end(const char *path, struct ocifs_cache_ref *ref)
{
	ocifs_ns_unlock(path);
	ocifs_cache_unref(ref);
	ocifs_release_path(path);
}

int ocifs_chown(const char *path, uid_t owner, gid_t group)
{
	struct ocifs_cache_ref *ref;
	int rv;

	OCIFS_DEBUG_FOPS("chown %s uid=%d gid=%d\n", path, owner, group);

	if (ocifs_uid != 0) {
		/*
		 * chown() is supported only if the filesystem is
		 * mounted by root.
		 */
		return -ENOTSUP;
	}

	path = ocifs_cache_op_begin(path, &ref);
	if (!path)
		return -errno;

	rv = ocifs_cache_chown(ocifs_cache, path, owner, group);

	ocifs_cache_op_end(path, ref);

	if (rv <= 0)
		return -errno;

	/*
	 * For now, we only change the owner/group in the cache but this
	 * change is not committed to cloud. So changes will not persist
	 * if the filesystem in unmounted and then remounted.
	 */

	return 0;
}

int ocifs_chmod(const char *path, mode_t mode)
{
	struct ocifs_cache_ref *ref;
	uid_t caller_uid;
	int rv;

	OCIFS_DEBUG_FOPS("chmod %s mode=%o\n", path, mode);

	caller_uid = fuse_get_context()->uid;

	/*
	 * If the filesystem owner is not root then all filesystem
	 * accesses are done with the filesystem owner credential,
	 * and only the filesystem owner change file permissions.
	 */
	if (ocifs_uid != 0 && caller_uid != ocifs_uid)
		return -EPERM;

	path = ocifs_cache_op_begin(path, &ref);
	if (!path)
		return -errno;

	rv = ocifs_cache_chmod(ocifs_cache, path, mode);

	ocifs_cache_op_end(path, ref);

	if (rv < 0)
		return -ENXIO;
	if (rv == 0)
		return -ENOENT;

	/*
	 * For now, we only change the mode in the cache but this change
	 * is not committed to cloud. So changes will not persist* if the
	 * filesystem in unmounted and then remounted.
	 */

	return 0;
}

int ocifs_utimens(const char *path, const struct timespec times[2])
{
	struct ocifs_cache_ref *ref;
	int rv;

	OCIFS_DEBUG_FOPS("utimens %s\n", path);

	path = ocifs_cache_op_begin(path, &ref);
	if (!path)
		return -errno;

	rv = ocifs_cache_utimens(ocifs_cache, path, times);

	ocifs_cache_op_end(path, ref);

	if (rv < 0)
		return -ENXIO;
	if (rv == 0)
		return -ENOENT;

	/*
	 * For now, we only change the mode in the cache but this change
	 * is not committed to cloud. So changes will not persist* if the
	 * filesystem in unmounted and then remounted.
	 */

	return 0;
}

int ocifs_rename(const char *oldpath, const char *newpath)
{
	struct ocifs_cache_ref *ref_old, *ref_new;
	struct stat stat_old;
	struct stat stat_new;
	bool path_cacheable;
	bool use_cache_new;
	bool use_cache_old;
	int err;
	int rv;

	OCIFS_DEBUG_FOPS("rename %s to %s\n", oldpath, newpath);

	oldpath = ocifs_get_path(oldpath, &path_cacheable);
	if (!oldpath)
		return -errno;

	ref_old = NULL;
	ref_new = NULL;

	ocifs_ns_wrlock(oldpath);

	newpath = ocifs_get_path(newpath, NULL);
	if (!newpath) {
		err = -errno;
		goto error;
	}

	use_cache_old = OCIFS_CACHE_USABLE(path_cacheable);
	use_cache_new = OCIFS_CACHE_ENABLED();

	/*
	 * Call getattr() to check the object exists and to get it
	 * into the cache if possible.
	 */
	rv = ocifs_getattr_locked(oldpath, &stat_old, &ref_old, use_cache_old);
	if (rv) {
		err = rv;
		goto error;
	}

	rv = ocifs_getattr_locked(newpath, &stat_new, &ref_new, use_cache_new);
	if (rv && rv != -ENOENT) {
		err = rv;
		goto error;
	}

	/*
	 * If oldpath is a directory then newpath must either not exist, or
	 * it must specify an empty directory.
	 */
	if (S_ISDIR(stat_old.st_mode)) {
		if (rv == 0) {
			if (!S_ISDIR(stat_new.st_mode)) {
				err = -ENOTSUP;
				goto error;
			}

			/* check that the prefix is effectively not used */
			rv = ocifs_cloud_check_prefix_used(newpath);
			if (rv < 0) {
				err = -EIO;
				goto error;
			}
			if (rv > 1) {
				err = -ENOTEMPTY;
				goto error;
			}
		}
		rv = ocifs_cloud_rename_prefix(oldpath, newpath);
		/*
		 * If there was an error renaming prefix in cloud then
		 * we can end up with a partial remaming in cloud: some
		 * objects with the prefix may have been renamed, while
		 * some have not. In that case, the cache entries will
		 * become inconsistent so clear them.
		 */
		if (rv < 0 && use_cache_old) {
			ocifs_cache_invalidate(ocifs_cache, oldpath);
			ocifs_cache_invalidate(ocifs_cache, newpath);
		}
	} else {
		/*
		 * If newpath exists then remove it. This ensures that
		 * opened files won't deal with the renamed object (i.e.
		 * with oldpath).
		 */
		if (rv == 0) {
			/*
			 * The unlink function expects the file to remove
			 * to exist. So do not drop the cache reference
			 * to the newpath yet.
			 */
			err = ocifs_unlink_locked(newpath, use_cache_new);
			if (err)
				goto error;

			/*
			 * Now that the file is unlinked, drop the cache
			 * reference so that the file gets effectively
			 * removed.
			 */
			ocifs_cache_unref(ref_new);
			ref_new = NULL;
		}

		rv = ocifs_cloud_rename(oldpath, newpath);
		/*
		 * If we fail here then oldpath still exists but if there
		 * was an existing newpath then it has been removed.
		 */
	}

	if (rv == 0) {
		err = -ENOENT;
		goto error;
	}
	if (rv < 0) {
		err = -EIO;
		goto error;
	}

	/*
	 * Rename the cache entry. This is required even if the old name
	 * doesn't have a cache file because it can still have a cache
	 * entry. If cache was used for oldpath then the cache file will
	 * be renamed to newpath. Otherwise, only the cache entry will
	 * be updated and we create a cache file.
	 *
	 * If renaming in cache fails then caching can become inconsistent
	 * and we invalidate the cache entries.
	 */
	rv = ocifs_cache_rename(ocifs_cache, oldpath, newpath);
	if (rv < 0) {
		ocifs_cache_invalidate(ocifs_cache, oldpath);
		ocifs_cache_invalidate(ocifs_cache, newpath);
		err = -errno;
		goto error;
	}

	if (rv == 0 && use_cache_new) {
		/*
		 * There was no cache file to rename so add a cache
		 * file. It doesn't matter if creating the cache file
		 * fails, it will be created later if needed.
		 */
		(void) ocifs_cache_add_object(ocifs_cache, newpath,
					      stat_old.st_size);
	}

	ocifs_ns_unlock(oldpath);
	ocifs_cache_unref(ref_old);
	ocifs_cache_unref(ref_new);
	ocifs_release_path(oldpath);
	return 0;

error:
	ocifs_ns_unlock(oldpath);
	ocifs_cache_unref(ref_old);
	ocifs_cache_unref(ref_new);
	ocifs_release_path(oldpath);
	ocifs_release_path(newpath);
	return err;
}
