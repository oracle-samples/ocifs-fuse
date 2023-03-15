/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "ocifs.h"
#include "ocifs_cache.h"
#include "utils.h"

/*
 * OCI Object Storage object names are limited to 1024 characters.
 */
#define OCI_PATH_MAX	1024

/*
 * Limit OCIFS paths to (OCI_PATH_MAX - 1) characters because an OCIFS
 * directory will have a corresponding OCI object with a trailing slash
 * (/) (e.g. OCIFS directory "foo/bar/buz" will be associated with OCI
 * object "foo/bar/buz/"). So we need to save room for this extra
 * characters.
 */
#define OCIFS_PATH_MAX	(OCI_PATH_MAX - 1)

/*
 * Cache filesystem free space buffer limits and expiration delays. The
 * free space buffer is the difference between the cache filesystem
 * free space and the free space limit (cache->fsfree_limit).
 *
 * OCIFS_CACHE_FSFREEBUF_LIMIT<n> is the free space buffer limit above
 * which the associated delay (OCIFS_CACHE_FSFREEBUF_DELAY<n>) can be
 * used.

 * OCIFS_CACHE_FSFREEBUF_DELAY<n> is the amount of time during which
 * the effective amount of free space on the cache filesystem doesn't
 * need to checked.
 *
 * Current limits values and delays are:
 *
 *               Value   Delay
 *   +---------+-------+-------+
 *   | Limit 1 |  1GB  |   1s  |
 *   +---------+-------+-------+
 *   | Limit 2 |  1TB  |  10s  |
 *   +---------+-------+-------+
 */

#define OCIFS_CACHE_FSFREEBUF_LIMIT1	\
	(1ULL * 1024 * 1024 * 1024) 		/* 1GB */
#define OCIFS_CACHE_FSFREEBUF_LIMIT2	\
	(1ULL * 1024 * 1024 * 1024 * 1024)	/* 1TB */

#define OCIFS_CACHE_FSFREEBUF_DELAY1	1	/* second */
#define OCIFS_CACHE_FSFREEBUF_DELAY2	10	/* seconds */

/*
 * An OCI Object Storage is in cache when it has a corresponding entry
 * in the cache directory (by default ~/.ocifs/<bucket-name>/cache).
 * The entry is either a directory for prefix object or a regular
 * file for regular object.
 *
 *     Cloud              Local Filesystem
 * <cloud object> :::::::   <cache file>
 *
 * When an object/file is opened then it also has a corresponding
 * memory handle (struct ocifs_cache_handle). The handles references
 * a cache entry (struct ocifs_cache_entry) which is shared by all
 * opens.
 *
 *                 +-- ocifs_cache_handle --+
 *                 |                        |
 * <cache file> <--+-- ocifs_cache_handle --+--> ocifs_cache_entry
 *                 |                        |
 *                 +-- ocifs_cache_handle --+
 */

struct ocifs_cache;

struct ocifs_cache_entry {
	struct ocifs_cache *cache;
	pthread_mutex_t lock;	/* protect size, data_ranges, dirty */
	int refcount;		/* reference count */
	bool removed;		/* has entry been removed? */
	const char *name;	/* name of the cached object */
	size_t size;		/* size of the cached object */
	struct range_list data_ranges; /* track data in the cache file */
	bool dirty;		/* is the cache dirty? */
	struct ocifs_cache_entry *purge_next; /* next entry in the purge list */
	struct ocifs_cache_entry *purge_prev; /* prev entry in the purge list */
	time_t purge_time;	/* time when entry should be purged */
};

struct ocifs_cache_handle {
	struct ocifs_cache *cache;
	int fd;
	struct ocifs_cache_entry *entry;
};

struct ocifs_cache {
	char *lockfile;		/* lock bucket cache */
	char *cachepath;	/* path to the actual (subfolder) cache */
	char *dirpath;		/* path to the bucket cache */
	int dirfd;
	unsigned long namemax;	/* filesystem maximum filename length */
	struct stat rootstat;	/* cache root stat */
	pthread_mutex_t lock;	/* protect entry_list and entry->refcount */
	void *entry_list;	/* track opened files/objects */
	size_t fsfree_limit;	/* percent (if <= 100) or size (in bytes) */
	time_t fsfree_expiration;
	pthread_t purge_thread; /* thread that purges old cache file */
	int purge_delay;	/* delay after which to purge files */
	pthread_cond_t purge_cv;
	struct ocifs_cache_entry purge_head; /* purge list head (fake entry) */
	struct ocifs_cache_entry purge_tail; /* purge list tail (fake entry) */
};

enum {
	OCIFS_CACHE_ENTRY_CHECK,
	OCIFS_CACHE_ENTRY_CREATE,
	OCIFS_CACHE_ENTRY_BUILD,
};

static int ocifs_cache_entry_init_ranges(struct ocifs_cache_entry *entry,
					 const char *name);
static void ocifs_cache_entry_destroy(struct ocifs_cache_entry *entry);
static int cache_faccess(struct ocifs_cache *cache, const char *name);
static void *ocifs_cache_purge_thread(void *data);
static void ocifs_cache_purge_enqueue(struct ocifs_cache *cache,
				      struct ocifs_cache_entry *entry);
static void ocifs_cache_purge_rm(struct ocifs_cache *cache,
				 struct ocifs_cache_entry *entry);

static struct ocifs_cache_entry *
ocifs_cache_entry_create(struct ocifs_cache *cache, const char *name,
			 size_t size)
{
	struct ocifs_cache_entry *entry;
	int err;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	entry->name = strdup(name);
	if (!entry->name) {
		free(entry);
		return NULL;
	}

	err = pthread_mutex_init(&entry->lock, NULL);
	if (err) {
		free((char *)entry->name);
		free(entry);
		return NULL;
	}

	entry->cache = cache;
	entry->size = size;
	entry->refcount = 0;
	entry->removed = false;
	entry->dirty = false;

	range_list_init(&entry->data_ranges);

	return entry;
}

static struct ocifs_cache_entry *
ocifs_cache_entry_build(struct ocifs_cache *cache, const char *name)
{
	struct ocifs_cache_entry *entry;
	int err;

	/*
	 * Create an entry with an initial size set to 0. The size will
	 * be updated from the cache file when initializing the entry
	 * ranges.
	 */
	entry = ocifs_cache_entry_create(cache, name, 0);
	if (!entry)
		return NULL;

	err = ocifs_cache_entry_init_ranges(entry, name);
	if (err) {
		ocifs_cache_entry_destroy(entry);
		return NULL;
	}

	return entry;
}

static void ocifs_cache_entry_destroy(struct ocifs_cache_entry *entry)
{
	if (!entry)
		return;

	range_list_fini(&entry->data_ranges);
	(void) pthread_mutex_destroy(&entry->lock);
	free((char *)entry->name);
	free(entry);
}

static int ocifs_cache_entry_cmp(const void *a, const void *b)
{
	const struct ocifs_cache_entry *entry_a, *entry_b;

	entry_a = a;
	entry_b = b;

	return strcmp(entry_a->name, entry_b->name);
}

static int ocifs_cache_add_entry(struct ocifs_cache *cache,
				 struct ocifs_cache_entry *entry)
{
	struct ocifs_cache_entry **entry_p;

	entry_p = tsearch(entry, &cache->entry_list, ocifs_cache_entry_cmp);
	if (*entry_p != entry) {
		/* entry is already in tree */
		return -1;
	}

	return 0;
}

static void ocifs_cache_rm_entry(struct ocifs_cache *cache,
				 struct ocifs_cache_entry *entry)
{
	tdelete(entry, &cache->entry_list, ocifs_cache_entry_cmp);
}

static void ocifs_cache_lock(struct ocifs_cache *cache)
{
	mutex_lock(&cache->lock);
}

static void ocifs_cache_unlock(struct ocifs_cache *cache)
{
	mutex_unlock(&cache->lock);
}

void ocifs_cache_lock_entry(struct ocifs_cache_handle *handle)
{
	mutex_lock(&handle->entry->lock);
}

void ocifs_cache_unlock_entry(struct ocifs_cache_handle *handle)
{
	mutex_unlock(&handle->entry->lock);
}

/*
 * Lookup a cache entry by name. Return the cache entry if found,
 * otherwise return NULL. The refcount is not changed. In particular,
 * the refcount can be zero if the entry was in purge list (the lookup
 * will removed it from the purge list).
 *
 * In all cases, the function returns with the cache locked.
 */
static struct ocifs_cache_entry *
ocifs_cache_lookup_locked(struct ocifs_cache *cache, const char *name)
{
	struct ocifs_cache_entry e, *entry, **entry_p;

	e.name = name;

	entry_p = tfind(&e, &cache->entry_list, ocifs_cache_entry_cmp);
	if (!entry_p)
		return NULL;

	entry = *entry_p;
	if (!entry)
		return NULL;

	if (entry->refcount == 0) {
		/*
		 * If we were able to look up an entry with no refcount
		 * then it comes from the purge list. Remove it from
		 * that list.
		 */
		ocifs_cache_purge_rm(cache, entry);
	}

	if (entry->removed) {
		/*
		 * Removed entry can't be looked up. They will be removed
		 * from the entry list when the handle removing the entry
		 * is closed. There is a short window between when the
		 * entry is marked removed and the handle is closed.
		 */
		return NULL;
	}

	return entry;
}

static struct ocifs_cache_entry *
ocifs_cache_lookup(struct ocifs_cache *cache, const char *name)
{
	ocifs_cache_lock(cache);
	return ocifs_cache_lookup_locked(cache, name);
}

static struct ocifs_cache_entry *
ocifs_cache_get_entry(struct ocifs_cache *cache, const char *name, size_t size,
		      int create_or_build)
{
	struct ocifs_cache_entry *entry;
	int err;

	entry = ocifs_cache_lookup(cache, name);

	if (!entry) {
		/* create and add a new entry */
		switch (create_or_build) {

		case OCIFS_CACHE_ENTRY_CREATE:
			entry = ocifs_cache_entry_create(cache, name, size);
			break;

		case OCIFS_CACHE_ENTRY_BUILD:
			entry = ocifs_cache_entry_build(cache, name);
			break;

		case OCIFS_CACHE_ENTRY_CHECK:
		default:
			break;
		}

		if (!entry) {
			ocifs_cache_unlock(cache);
			return NULL;
		}

		err = ocifs_cache_add_entry(cache, entry);
		if (err) {
			/*
			 * This shouldn't happen because the lookup
			 * didn't return any entry.
			 */
			ocifs_cache_entry_destroy(entry);
			ocifs_cache_unlock(cache);
			return NULL;
		}
	}

	entry->refcount++;
	ocifs_cache_unlock(cache);

	return entry;
}

/*
 * Should be called with the cache locked, return with the cache
 * unlocked.
 */
static void
ocifs_cache_entry_put(struct ocifs_cache_entry *entry)
{
	struct ocifs_cache *cache;

	cache = entry->cache;

	/*
	 * If the entry is removed, delete it from the cache entries
	 * so that it can't be looked up anymore.
	 */
	if (entry->removed)
		ocifs_cache_rm_entry(cache, entry);

	if (--entry->refcount > 0) {
		/* keep the entry, it is still referenced */
		ocifs_cache_unlock(cache);
		return;
	}

	/*
	 * If the entry is removed then it has no more cache file, and
	 * it was already removed from the cache entry so we just need
	 * to destroy the entry.
	 */
	if (entry->removed)
		goto done_no_rm_entry;

	/*
	 * If cache purge is not enabled then cache files are never
	 * purged. So keep the cache file but remove the entry from
	 * the cache.
	 */
	if (!ocifs_cache_purge_enabled(cache))
		goto done;

	/*
	 * If cache purge is enabled, add the entry to the purge queue
	 * so that it gets purged after the purge delay.
	 *
	 * If the entry has no associated cache file then remove the
	 * entry immediately.
	 */
	if (cache_faccess(cache, entry->name) <= 0)
		goto done;

	entry->purge_time = time(NULL) + cache->purge_delay;
	ocifs_cache_purge_enqueue(cache, entry);
	cv_signal(&cache->purge_cv);

	ocifs_cache_unlock(cache);
	return;

done:
	ocifs_cache_rm_entry(cache, entry);
done_no_rm_entry:
	ocifs_cache_unlock(cache);
	ocifs_cache_entry_destroy(entry);
}

static void ocifs_cache_entry_unref(struct ocifs_cache_entry *entry)
{
	if (entry) {
		ocifs_cache_lock(entry->cache);
		ocifs_cache_entry_put(entry);
	}
}

/*
 * Lock the entry refcount, and return the entry refcount value. Locking
 * the refcount guarantees that the refcount won't change. Currently,
 * locking the refcount locks the entire cache.
 */
int ocifs_cache_lock_refcount(struct ocifs_cache_handle *handle)
{
	ocifs_cache_lock(handle->cache);
	return handle->entry->refcount;
}

/*
 * Unlock the entry refcount. Refcount can change after it is unlocked.
 */
void ocifs_cache_unlock_refcount(struct ocifs_cache_handle *handle)
{
	ocifs_cache_unlock(handle->cache);
}

/*
 * Check that a path is valid for OCI and compatible with caching
 * (even if cache is disabled).
 *
 * Return value:
 * -1  -  OCI name is invalid for OCI, error in errno
 *  0  -  OCI name is valid for OCI and for cache
 *  1  -  OCI name is valid for OCI but not for cache
 */
int ocifs_cache_validate_path(struct ocifs_cache *cache, const char *path)
{
	bool cache_valid;
	int name_size;
	int i;

	if (path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	cache_valid = true;
	name_size = 1;

	for (i = 1; path[i] != '\0'; i++) {
		if (i >= OCIFS_PATH_MAX) {
			errno = ENAMETOOLONG;
			return -1;
		}
		if (path[i] == '\n' || path[i] == '\r') {
			errno = EINVAL;
			return -1;
		}

		if (!cache_valid)
			continue;

		if (path[i] == '/') {
			name_size = 0;
			continue;
		}

		if (++name_size > cache->namemax)
			cache_valid = false;
	}

	if (!cache_valid) {
		errno = ENAMETOOLONG;
		return 1;
	}

	return 0;
}

/*
 * A cache entry name shouldn't be empty, and it should not start or end
 * with a '/'.
 *
 * OCI Object Storage object name can have any character except line feed,
 * carriage return and NULL.
 *
 * Note that OCI names start with "/" (e.g. "/abc") or contain multiple
 * consecutive "/" (for example "abc////def"). These names not reported
 * (they are ignored during readdir()).
 */
static int check_entry_name(const char *name)
{
	int len;

	len = strlen(name);

	if (!name || *name == '\0' || *name == '/' || name[len - 1] == '/')
		return -1;

	/*
	 * Name shouldn't be "..", "../<path>", "<path>/.." "<path>/../<path>"
	 */

	if (strcmp(name, "..") == 0)
		return -1;

	if (len < 3)
		return 0;

	if (strstr(name, "/../") ||
	    strncmp(name, "../", 3) == 0 ||
	    strcmp(name + strlen(name) - 3, "/..") == 0)
		return -1;

	return 0;
}

#define CHECK_ENTRY_NAME(name, rv)			\
	do {						\
		if (check_entry_name(name))		\
			return rv;			\
	} while (0)

/*
 * Indicate if a file is entirely sparse.
 *
 * Return:
 *   1 : the file is entirely sparse
 *   0 : the file has data, it is not entirely sparse
 *  -1 : error
 */
static int file_is_sparse(int fd)
{
	off_t offset;

	offset = lseek(fd, 0, SEEK_DATA);
	if (offset != -1) {
		/* data found, the file is not entirely sparse */
		return 0;
	}

	if (errno != ENXIO) {
		/* error */
		return -1;
	}

	/* no data found, the file is entirely sparse */
	return 1;
}

static int cache_fstat(struct ocifs_cache *cache, const char *name,
		       struct stat *stbuf)
{
	int err;

	err = fstatat(cache->dirfd, name, stbuf,
		      AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW);

	if (err) {
		if (errno == ENOENT || errno == ENAMETOOLONG)
			return 0;
		return -1;
	}


	return 1;
}

static int cache_faccess(struct ocifs_cache *cache, const char *name)
{
	int err;

	err = faccessat(cache->dirfd, name, F_OK, AT_SYMLINK_NOFOLLOW);
	if (err) {
		if (errno == ENOENT || errno == ENAMETOOLONG)
			return 0;
		return -1;
	}

	return 1;
}

char *ocifs_cache_get_path(struct ocifs_cache *cache)
{
	if (!cache)
		return NULL;

	return cache->cachepath;
}

/*
 * Create a lock in the cache directory of a specific bucket visible
 * by other ocifs processes.
 */
static int ocifs_lock_cache_dir(const char *lockfile, const char *msg)
{
	int fd;
	int i;

	/*
	 * Try to take the lock. Retry 5 times with a 1s delay.
	 * This should be enough as lock is only taken while
	 * mount/unmounting a filesystem.
	 */
	for (i = 0; i < 5; i++) {
		fd = open(lockfile, O_CREAT | O_EXCL | O_WRONLY, 0644);
		if (fd != -1)
			break;
		if (errno != EEXIST) {
			OCIFS_DEBUG_CACHE("Failed to create lock file %s: %s\n",
					  lockfile, strerror(errno));
			return -1;
		}
		sleep(1);
	}

	if (fd == -1) {
		OCIFS_DEBUG_CACHE("Failed to get lock file %s\n", lockfile);
		errno = EAGAIN;
		return -1;
	}

	if (msg)
		(void) write(fd, msg, strlen(msg));

	(void) close(fd);

	return 0;
}

static void ocifs_unlock_cache_dir(const char *lockfile)
{
	int err;

	err = unlink(lockfile);
	if (err) {
		/*
		 * We can't recover in case of an error. The cache
		 * directory will remain lock until the file is
		 * manually removed.
		 */
		OCIFS_DEBUG_CACHE("Failed to remove lock file %s: %s\n",
				  lockfile, strerror(errno));
	}

	return;

}

static int ocifs_setup_cache_dir(const char *dirpath, char *cachepath,
				 const char *lockfile)
{
	char *msg;
	int err;

	err = mktree_for_file(lockfile, 0755);
	if (err)
		return -1;

	/* debug info, doesn't matter if msg is not created */
	msg = strfmt("PID: %ld\nCACHE: %s\nFUNCTION: %s",
		     getpid(), cachepath, __func__);

	err = ocifs_lock_cache_dir(lockfile, msg);
	free(msg);
	if (err)
		return -1;

	err = mktree(cachepath, 0755);
	ocifs_unlock_cache_dir(lockfile);

	return err;
}

bool ocifs_cache_is_enabled(struct ocifs_cache *cache)
{
	return (cache->dirpath != NULL);
}

static struct ocifs_cache *ocifs_cache_create_common(void)
{
	struct ocifs_cache *cache ;
	int err;

	cache = malloc(sizeof(*cache));
	if (!cache)
		return NULL;

	bzero(cache, sizeof(*cache));

	/*
	 * purge_head and purge_tail are not real entries but just
	 * placeholder to indicate the head and tail of the purge
	 * list.
	 */
	cache->purge_head.name = "__PURGE_HEAD__";
	cache->purge_head.purge_next = &cache->purge_tail;
	cache->purge_tail.name = "__PURGE_TAIL__";
	cache->purge_tail.purge_prev = &cache->purge_head;

	err = pthread_mutex_init(&cache->lock, NULL);
	if (err) {
		free(cache);
		return NULL;
	}

	err = pthread_cond_init(&cache->purge_cv, NULL);
	if (err) {
		(void) pthread_mutex_destroy(&cache->lock);
		free(cache);
		return NULL;
	}

	return cache;
}

/*
 * Create a disabled cache. We need a cache structure even if cache
 * is disabled (i.e. when there is effectively no cache), so that we
 * can check that OCIFS names are valid for caching, and for tracking
 * opened files (with cache entry/handle).
 */
struct ocifs_cache *ocifs_cache_create_disabled(void)
{
	struct ocifs_cache *cache ;
	struct stat *stbuf;
	time_t now;

	cache = ocifs_cache_create_common();
	if (!cache)
		return NULL;

	/*
	 * Set namemax to check OCIFS path names are valid with the
	 * most common name limit (NAME_MAX).
	 */
	cache->namemax = NAME_MAX;
	cache->dirfd = -1;

	stbuf = &cache->rootstat;
	now = time(NULL);
	stbuf->st_mode = S_IFDIR | 0755;
	stbuf->st_nlink = 2;
	stbuf->st_uid = geteuid();
	stbuf->st_gid = getegid();
	stbuf->st_atim.tv_sec = now;
	stbuf->st_mtim.tv_sec = now;
	stbuf->st_ctim.tv_sec = now;

	return cache;
}

struct ocifs_cache *ocifs_cache_create(const char *cache_root,
				       const char *bucket,
				       const char *subfolder,
				       size_t fsfree_limit,
				       int purge_delay)
{
	struct ocifs_cache *cache = NULL;
	struct statvfs stvfs_buf;
	char *cachepath;
	char *lockfile;
	char *dirpath;
	int err;
	int fd;

	if (!bucket)
		return NULL;

	if (!cache_root)
		return ocifs_cache_create_disabled();

	/*
	 * When using a subfolder, all filenames will be prepended with
	 * the subfolder name. So we create a cache for the entire bucket
	 * but files/directories will only be cached in the subfolder.
	 * Note that the bucket cache is shared by all subfolders.
	 */

	dirpath = strfmt("%s/%s/cache", cache_root, bucket);
	if (!dirpath)
		return NULL;

	if (subfolder) {
		cachepath = strfmt("%s/%s", dirpath, subfolder);
		if (!cachepath) {
			free(dirpath);
			return NULL;
		}
	} else {
		cachepath = dirpath;
	}

	lockfile = strfmt("%s/%s/lock", cache_root, bucket);
	if (!lockfile) {
		free(dirpath);
		if (subfolder)
			free(cachepath);
		return NULL;
	}

	err = ocifs_setup_cache_dir(dirpath, cachepath, lockfile);
	if (err)
		goto error;

	err = statvfs(cachepath, &stvfs_buf);
	if (err)
		goto error;

	cache = ocifs_cache_create_common();
	if (!cache)
		goto error;

	fd = open(dirpath, O_RDONLY | O_DIRECTORY | O_PATH);
	if (fd < 0)
		goto error;

	cache->lockfile = lockfile;
	cache->cachepath = cachepath;
	cache->dirpath = dirpath;
	cache->dirfd = fd;
	cache->namemax = stvfs_buf.f_namemax;
	cache->entry_list = NULL;
	cache->fsfree_limit = fsfree_limit;
	cache->purge_delay = purge_delay;

	err = fstat(fd, &cache->rootstat);
	if (err) {
		close(fd);
		goto error;
	}

	return cache;

error:
	if (cachepath != dirpath)
		free(cachepath);
	free(dirpath);
	free(cache);
	return NULL;
}

static int ocifs_cleanup_cache_dir(const char *dirpath, char *cachepath,
				   const char *lockfile)
{
	char *msg;
	char *dir;
	int err;

	/* debug info, doesn't matter if msg is not created */
	msg = strfmt("PID: %ld\nCACHE: %s\nFUNCTION: %s",
		     getpid(), cachepath, __func__);

	err = ocifs_lock_cache_dir(lockfile, msg);
	free(msg);
	if (err)
		return err;

	err = rmtree(cachepath);
	if (err) {
		ocifs_unlock_cache_dir(lockfile);
		return err;
	}

	/*
	 * If there is no subfolder then cachepath is the same as
	 * dirpath, and we are done. Otherwise, cachepath is a subdir
	 * of dirpath, and we need to remove parent directories of
	 * cachepath up to dirpath, unless a parent directory is used
	 * by to cache another subfolder.
	 *
	 * Example:
	 *
	 * - dirpath = /path/to/cache
	 * - bucket = my-bucket
	 * - subfolder = A/B/C
	 *
	 * then cachepath = /path/to/my-bucket/cache/A/B/C
	 *
	 * The previous rmtree() has removed C, then we need to remove
	 * B, A, "cache" (in this order) if these directories are not
	 * caching another subfolder.
	 *
	 * For example, if subfolder A/foo is also mounted then B should
	 * be removed, but not A and "cache".
	 */
	if (cachepath == dirpath) {
		ocifs_unlock_cache_dir(lockfile);
		return 0;
	}

	/*
	 * dirname(3) will modify cachepath, but this doesn't matter because
	 * cache->cachepath will be freed.
	 */
	dir = dirname(cachepath);

	/*
	 * <cachepath> = <dirpath>/<subfolder> so dirname(<cachepath>)
	 * will eventually match <dirpath>
	 */
	while (strcmp(dirpath, dir) != 0) {
		err = rmdir(dir);
		if (err)
			break;
		dir = dirname(dir);
	}

	if (!err)
		err = rmdir(dir);

	/*
	 * If we failed to remove a parent directory with an EEXIST or
	 * ENOTEMPTY error then this means that the directory is used
	 * by another subfolder, and it will be removed when that
	 * subfolder is unmounted.
	 */
	if (err && (errno == EEXIST || errno == ENOTEMPTY))
		err = 0;

	ocifs_unlock_cache_dir(lockfile);

	return 0;
}

/*
 * Destroy cache. Return an error if there was a failure to remove
 * the cache directory. In any case, the cache object is always
 * destroyed.
 */
int ocifs_cache_destroy(struct ocifs_cache *cache, bool keep_cache_dir)
{
	int err;

	if (!cache)
		return 0;

	if (!cache->dirpath) {
		free(cache);
		return 0;
	}

	/* stop the cache purge_thread */
	if (cache->purge_thread) {
		ocifs_cache_lock(cache);
		/* set value to force thread to exit */
		cache->purge_delay = OCIFS_CACHE_PURGE_NEVER;
		cv_signal(&cache->purge_cv);
		ocifs_cache_unlock(cache);

		(void) pthread_join(cache->purge_thread, NULL);
	}

	if (keep_cache_dir)
		err = 0;
	else
		err = ocifs_cleanup_cache_dir(cache->dirpath, cache->cachepath,
					      cache->lockfile);

	free(cache->lockfile);
	if (cache->dirpath != cache->cachepath)
		free(cache->cachepath);
	free(cache->dirpath);
	if (cache->dirfd != -1)
		close(cache->dirfd);
	/*
	 * Destroy entries. Note that entries in the purge list are
	 * also in the entry_list so they will be destroyed when
	 * destroying the entry_list.
	 */
	tdestroy(cache->entry_list,
		 (void (*)(void *))ocifs_cache_entry_destroy);

	(void) pthread_mutex_destroy(&cache->lock);
	(void) pthread_cond_destroy(&cache->purge_cv);

	free(cache);

	return err;
}

static struct ocifs_cache_handle *
ocifs_cache_handle_alloc(struct ocifs_cache *cache,
			 struct ocifs_cache_entry *entry, int fd)
{
	struct ocifs_cache_handle *handle;

	handle = malloc(sizeof(*handle));
	if (!handle) {
		ocifs_cache_entry_unref(entry);
		return NULL;
	}

	handle->entry = entry;
	handle->cache = cache;
	handle->fd = fd;

	return handle;
}

static struct ocifs_cache_handle *
ocifs_cache_handle_build(struct ocifs_cache *cache, int fd, const char *name)
{
	struct ocifs_cache_entry *entry;

	entry = ocifs_cache_get_entry(cache, name, 0, OCIFS_CACHE_ENTRY_BUILD);
	if (!entry)
		return NULL;

	return ocifs_cache_handle_alloc(cache, entry, fd);
}

static struct ocifs_cache_handle *
ocifs_cache_handle_create(struct ocifs_cache *cache, int fd, const char *name,
			  size_t size)
{
	struct ocifs_cache_entry *entry;


	entry = ocifs_cache_get_entry(cache, name, size,
				      OCIFS_CACHE_ENTRY_CREATE);
	if (!entry)
		return NULL;

	return ocifs_cache_handle_alloc(cache, entry, fd);
}

/*
 * Check if a prefix exists in the cache and is used by other entries.
 * Return:
 *   0  if prefix is not in cache
 *   1  if prefix is in cache but not used,
 *  >1  if prefix is in cache and used
 *  -1  if there is an error
 */
int ocifs_cache_check_prefix_used(struct ocifs_cache *cache, const char *name)
{
	struct dirent *dent;
	int save_errno;
	int count;
	DIR *dir;
	char *n;
	int err;
	int fd;

	CHECK_ENTRY_NAME(name, -1);

	/*
	 * There is no opendir_at(dirfd, name) function. So instead, we do
	 * fdopendir(openat(dirfd, name))
	 */
	fd = openat(cache->dirfd, name, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	dir = fdopendir(fd);
	if (!dir) {
		save_errno = errno;
		close(fd);

		if (save_errno == ENOENT)
			return 0;

		return -1;
	}

	/*
	 * Check if the directory has at least one entry (other than
	 * . and ..).
	 */
	count = 0;
	errno = 0;
	while ((dent = readdir(dir)) != NULL) {
		n = dent->d_name;
		/* ignore "." and ".." */
		if (n[0] == '.') {
			if (n[1] == '\0')
				continue;
			if (n[1] == '.'  && n[2] == '\0')
				continue;
		}

		/*
		 * Don't count all entries, we just need to know if
		 * there is at least one entry in the directory. So
		 * break the loop as soon as we find one.
		 */
		count++;
		break;
	}

	save_errno = errno;

	err = closedir(dir);
	if (err)
		close(fd);

	if (save_errno)
		return -1;

	return 1 + count;
}

/*
 * Check if a prefix exists in cache. Return 1 if the prefix exists,
 * 0 if the prefix doesn't exist and -1 if there is an error.
 */
int ocifs_cache_check_prefix(struct ocifs_cache *cache, const char *name)
{
	CHECK_ENTRY_NAME(name, -1);
	// XXX check if dir?
	return cache_faccess(cache, name);
}

int ocifs_cache_check_object(struct ocifs_cache *cache, const char *name)
{
	struct ocifs_cache_entry *entry;

	CHECK_ENTRY_NAME(name, -1);

	/*
	 * If there is a cache entry then the object exists in cache.
	 * If not then check if there is a cache file.
	 */
	entry = ocifs_cache_get_entry(cache, name, 0, OCIFS_CACHE_ENTRY_CHECK);
	if (entry) {
		ocifs_cache_entry_unref(entry);
		return 1;
	}

	// XXX check if file?
	return cache_faccess(cache, name);
}

int ocifs_cache_add_prefix(struct ocifs_cache *cache, const char *name,
			   mode_t mode)
{
	int err;

	err = mktree_at(cache->dirfd, name, mode);
	if (err)
		return -1;

	return 0;
}

int ocifs_cache_rm_prefix(struct ocifs_cache *cache, const char *name)
{
	int err;

	err = unlinkat(cache->dirfd, name, AT_REMOVEDIR);
	if (err)
		return -1;

	return 0;
}

struct ocifs_cache_handle *ocifs_cache_create_handle(struct ocifs_cache *cache,
						     const char *name,
						     size_t size)
{
	struct ocifs_cache_handle *handle;

	handle = ocifs_cache_handle_create(cache, -1, name, size);
	if (!handle)
		return NULL;

	return handle;
}

/*
 * Create a placeholder file for an object.
 *
 * This creates an empty file with the size of the object. The file will
 * eventually be filled with object data.
 */
static int ocifs_cache_create_placeholder(struct ocifs_cache *cache,
					  const char *name,
					  size_t size, mode_t mode)
{
	int flags;
	int err;
	int fd;

	CHECK_ENTRY_NAME(name, -1);

	err = mktree_for_file_at(cache->dirfd, name,
				 OCIFS_CACHE_PERM_DEFAULT_DIR);
	if (err)
		return err;

	flags = O_RDWR | O_LARGEFILE | O_NOFOLLOW | O_CREAT | O_EXCL;
	fd = openat(cache->dirfd, name, flags, mode);
	if (fd < 0)
		return -1;

	if (size) {
		err = ftruncate(fd, size);
		if (err)
			return err;
	}

	return fd;
}

/*
 * Add a cache placeholder file for an object and return an object handle.
 */
struct ocifs_cache_handle *ocifs_cache_create_object(struct ocifs_cache *cache,
						     const char *name,
						     size_t size, mode_t mode)
{
	struct ocifs_cache_handle *handle;
	int fd;

	fd = ocifs_cache_create_placeholder(cache, name, size, mode);
	if (fd < 0)
		return NULL;

	handle = ocifs_cache_handle_create(cache, fd, name, size);
	if (!handle) {
		ocifs_cache_invalidate(cache, name);
		close(fd);
		return NULL;
	}

	return handle;
}

/*
 * Add a cache placeholder file for an object.
 */
int ocifs_cache_add_object(struct ocifs_cache *cache, const char *name,
			   size_t size)
{
	int fd;
	int rv;

	fd = ocifs_cache_create_placeholder(cache, name, size,
					    OCIFS_CACHE_PERM_DEFAULT_FILE);
	if (fd < 0)
		return -1;

	/*
	 * Check that the placeholder is an entirely sparse file. This
	 * will be used when opening the file to indicate that no data
	 * is cached (conversely, if the file has data this will mean
	 * object data are all cached in the file).
	 */
	rv = file_is_sparse(fd);
	if (rv <= 0) {
		/*
		 * The file is not entirely sparse or error, get rid
		 * of it. Otherwise this will confuse open().
		 */
		OCIFS_DEBUG_CACHE("Failed to create entirely sparse file %s "
				  "(size=%zd)\n", name, size);
		ocifs_cache_invalidate(cache, name);
		close(fd);
		return -1;
	}

	/* no data found, the file is entirely sparse */

	close(fd);
	return (0);
}

static int ocifs_cache_entry_init_ranges(struct ocifs_cache_entry *entry,
					 const char *name)
{
	struct stat stbuf;
	int err;
	int fd;
	int rv;

	fd = openat(entry->cache->dirfd, name,
		    O_RDONLY | O_LARGEFILE | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	err = fstat(fd, &stbuf);
	if (err) {
		close(fd);
		return -1;
	}

	entry->size = stbuf.st_size;
	if (entry->size == 0) {
		close(fd);
		return 0;
	}

	/*
	 * Check if the file is entirely sparse. If it is then the file
	 * is just a placeholder for getattr() and it has no data.
	 * Otherwise the file has been creat() or open() and close(),
	 * and it is fully populated (all data are in the cache file).
	 * Note that in the case, the file can be partially sparse if
	 * it was created and partially written to.
	 */

	rv = file_is_sparse(fd);
	close(fd);
	if (rv < 0) {
		/* error */
		return -1;
	}

	if (rv > 0) {
		/*
		 * The file is entirely sparse, it has no cache data
		 * so the entry range list should remain empty.
		 */
		return 0;
	}

	/*
	 * The file has data so it is fully populated with data.
	 * Then the entry range list has a single range covering
	 * the entire file.
	 */
	err = range_list_add(&entry->data_ranges, 0, entry->size);
	if (err)
		return -1;

	return 0;
}

/*
 * Open an existing cache file. Fails if the cache file doesn't exist.
 *
 * The cache file is either a placeholder (i.e. an empty file with the size
 * of the object), or a file fully populated with object data.
 */
struct ocifs_cache_handle *ocifs_cache_open_object(struct ocifs_cache *cache,
						   const char *name)
{
	struct ocifs_cache_handle *handle;
	struct ocifs_cache_entry *entry;
	int fd;

	CHECK_ENTRY_NAME(name, NULL);

	/*
	 * Get a reference to the cache entry (if there is one) to
	 * prevent the cache file from being purged.
	 */
	entry = ocifs_cache_get_entry(cache, name, 0, OCIFS_CACHE_ENTRY_CHECK);

	fd = openat(cache->dirfd, name, O_RDWR | O_LARGEFILE | O_NOFOLLOW);
	if (fd < 0) {
		ocifs_cache_entry_unref(entry);
		return NULL;
	}

	/*
	 * If we already have an entry then wrap it into an handle.
	 * Otherwise build the entry (and the handle) from the cache
	 * file.
	 */
	if (entry)
		handle = ocifs_cache_handle_alloc(cache, entry, fd);
	else
		handle = ocifs_cache_handle_build(cache, fd, name);

	if (!handle) {
		close(fd);
		errno = ENOMEM;
		return NULL;
	}

	return handle;
}

/*
 * Validate a cache handle. A cache handle can have no file descriptor
 * if it was created with a non-cacheable name. The handle validation
 * will create a file descriptor if the name was changed to a cacheable
 * name.
 */
int ocifs_cache_validate_handle(struct ocifs_cache_handle *handle,
				const char *name)
{
	int fd;

	/*
	 * Check if we have a valid file descriptor.
	 */
	if (handle->fd != -1)
		return 0;

	/* the name should match with the entry name */
	if (strcmp(name, handle->entry->name) != 0) {
		OCIFS_DEBUG_CACHE("entry name '%s' doesn't match with '%s'\n",
				  handle->entry->name, name);
		return 0;
	}

	/*
	 * If the file descriptor is not valid, open the cache file.
	 */
	fd = openat(handle->cache->dirfd, name,
		    O_RDWR | O_LARGEFILE | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	handle->fd = fd;

	return 0;
}

static void ocifs_cache_close_common(struct ocifs_cache_handle *handle,
				     bool cache_locked)
{
	if (!handle)
		return;

	if (!cache_locked)
		ocifs_cache_lock(handle->cache);

	/* ocifs_cache_entry_put() will release the cache lock */
	ocifs_cache_entry_put(handle->entry);
	close(handle->fd);
	free(handle);
}

/*
 * Locks: cache shouldn't be locked. If it is then use
 * ocifs_cache_close_locked() instead.
 */
void ocifs_cache_close(struct ocifs_cache_handle *handle)
{
	ocifs_cache_close_common(handle, false);
}

void ocifs_cache_close_locked(struct ocifs_cache_handle *handle)
{
	ocifs_cache_close_common(handle, true);
}

int ocifs_cache_walk_data(struct ocifs_cache_handle *handle,
			  off_t offset, size_t size,
			  range_list_walk_cb callb, void *data)
{
	int err;

	err = range_list_walk_range_safe(&handle->entry->data_ranges,
					 offset, size, callb, data);
	if (err)
		return -1;

	return 0;
}

ssize_t ocifs_cache_read(struct ocifs_cache_handle *handle, char *buf,
			 size_t size, off_t offset)
{
	return pread(handle->fd, buf, size, offset);
}

/*
 * Return true if we can write data to the OCIFS cache. False is
 * returned if we are reaching the cache size limit.
 */
static bool ocifs_cache_can_write(struct ocifs_cache *cache, size_t size)
{
	struct statvfs vfs_stat;
	time_t fs_free_buffer;
	size_t fs_free_limit;
	size_t fs_size;
	size_t fs_free;
	time_t delay;
	time_t now;
	int err;

	if (cache->fsfree_limit == 0) {
		/* no cache limit */
		return true;
	}

	now = time(NULL);
	if (cache->fsfree_expiration != 0 && now < cache->fsfree_expiration) {
		/*
		 * We recently checked that we are below the cache
		 * limit and we estimate that this information is
		 * still valid.
		 */
		return true;
	}

	cache->fsfree_expiration = 0;

	err = statvfs(cache->cachepath, &vfs_stat);
	if (err) {
		/*
		 * If we can't get information about the filesystem
		 * then assume that we can't write.
		 */
		return false;
	}

	fs_size = vfs_stat.f_blocks * vfs_stat.f_frsize;
	fs_free = vfs_stat.f_bfree * vfs_stat.f_bsize;

	/*
	 * If cache->fsfree_limit <= 100 then it is a percentage of
	 * the total size of the cache filesystem, otherwise it is
	 * an absolute value in bytes.
	 */
	if (cache->fsfree_limit <= 100)
		fs_free_limit = (fs_size * cache->fsfree_limit) / 100;
	else
		fs_free_limit = cache->fsfree_limit;

	if (size >= fs_free) {
		/*
		 * Free space is too low for the specified size.
		 */
		return false;
	}

	fs_free -= size;

	if (fs_free <= fs_free_limit) {
		/*
		 * Free space is below the free space limit.
		 */
		return false;
	}

	/*
	 * Set the fsfree expiration time based the remaining space
	 * buffer.
	 */
	fs_free_buffer = fs_free - fs_free_limit;

	if (fs_free_buffer > OCIFS_CACHE_FSFREEBUF_LIMIT2)
		delay = OCIFS_CACHE_FSFREEBUF_DELAY2;
	else if (fs_free_buffer > OCIFS_CACHE_FSFREEBUF_LIMIT1)
		delay = OCIFS_CACHE_FSFREEBUF_DELAY1;
	else
		delay = 0;

	if (now != -1 && delay != 0)
		cache->fsfree_expiration = now + delay;

	return true;
}

ssize_t ocifs_cache_write(struct ocifs_cache_handle *handle, const char *buf,
			  size_t size, off_t offset)
{
	size_t object_size;
	ssize_t count;
	int rv;

	if (!ocifs_cache_can_write(handle->cache, size)) {
		errno = ENOSPC;
		return -1;
	}

	count = pwrite(handle->fd, buf, size, offset);
	if (count < 0)
		return -1;

	/*
	 * If the offset is past the size of the file then we are
	 * defining a range (filled with zero) starting at the end
	 * of the file right and follow by the write range.
	 *
	 * Otherwise, only the write range is defined (but it can also
	 * go past the end of the file).
	 */
	object_size = handle->entry->size;
	if (offset > object_size) {
		rv = range_list_add(&handle->entry->data_ranges, object_size,
				    offset + count - object_size);
	} else {
		rv = range_list_add(&handle->entry->data_ranges, offset, count);
	}
	if (rv != 0)
		return -1;

	if (offset + count > object_size)
		handle->entry->size = offset + count;

	return count;
}

int ocifs_cache_filled(struct ocifs_cache_handle *handle, off_t offset,
		       size_t size)
{
	return range_list_add(&handle->entry->data_ranges, offset, size);
}

void ocifs_cache_unref(struct ocifs_cache_ref *ref)
{
	ocifs_cache_entry_unref((struct ocifs_cache_entry *)ref);
}

/*
 * getattr() for a cache entry. Fill stbuf and return 1 if a cache entry
 * exists. Return 0 if there is no cache entry and -1 if there is an error.
 */
int ocifs_cache_getattr(struct ocifs_cache *cache, const char *name,
			struct stat *stbuf, struct ocifs_cache_ref **refp)
{
	struct ocifs_cache_entry *entry;
	int rv;

	CHECK_ENTRY_NAME(name, -1);

	*refp = NULL;

	/*
	 * If cache purge is not enabled then the cache file is never
	 * removed and we can directly stat() that file.
	 */
	if (!ocifs_cache_purge_enabled(cache))
		return cache_fstat(cache, name, stbuf);

	/*
	 * If cache purge is enabled then get a reference to the cache
	 * entry (if there is one) to prevent the cache file from being
	 * purged.
	 */
	entry = ocifs_cache_get_entry(cache, name, 0, OCIFS_CACHE_ENTRY_CHECK);

	rv = cache_fstat(cache, name, stbuf);
	if (rv <= 0) {
		/* error or no cache file */
		ocifs_cache_entry_unref(entry);
		return rv;
	}

	*refp = (struct ocifs_cache_ref *)entry;

	return rv;
}

int ocifs_cache_getattr_root(struct ocifs_cache *cache, struct stat *stbuf)
{
	bcopy(&cache->rootstat, stbuf, sizeof(*stbuf));
	return 0;
}

bool ocifs_cache_is_dirty(struct ocifs_cache_handle *handle)
{
	if (handle && handle->entry && handle->entry->dirty)
		return true;

	return false;
}

void ocifs_cache_set_dirty(struct ocifs_cache_handle *handle)
{
	handle->entry->dirty = true;
}

void ocifs_cache_set_clean(struct ocifs_cache_handle *handle)
{
	handle->entry->dirty = false;
}

bool ocifs_cache_is_removed(struct ocifs_cache_handle *handle)
{
	if (handle && handle->entry && handle->entry->removed)
		return true;

	return false;
}

void ocifs_cache_set_removed(struct ocifs_cache_handle *handle)
{
	handle->entry->removed = true;
}

const char *ocifs_cache_get_name(struct ocifs_cache_handle *handle)
{
	return handle->entry->name;
}

int ocifs_cache_get_file(struct ocifs_cache_handle *handle)
{
	return handle->fd;
}

size_t ocifs_cache_get_size(struct ocifs_cache_handle *handle)
{
	return handle->entry->size;
}

int ocifs_cache_seek(struct ocifs_cache_handle *handle, off_t offset)
{
	off_t off;

	off = lseek(handle->fd, offset, SEEK_SET);
	if (off < 0)
		return -1;

	return 0;
}

int ocifs_cache_truncate(struct ocifs_cache_handle *handle, off_t length)
{
	size_t old_length;
	int err;

	ocifs_cache_lock_entry(handle);

	old_length = handle->entry->size;
	if (length == old_length) {
		ocifs_cache_unlock_entry(handle);
		return 0;
	}

	err = ftruncate(handle->fd, length);
	if (err)
		goto error;

	/*
	 * If the size is reduced then also reduce the data_ranges.
	 * If the size is increased then add a new data range as this
	 * range is now filled (with zeros).
	 */
	if (length < old_length) {
		range_list_truncate(&handle->entry->data_ranges, length);
	} else {
		err = range_list_add(&handle->entry->data_ranges,
				     old_length, length - old_length);
		if (err) {
			errno = -ENXIO;
			goto error;
		}
	}

	handle->entry->size = length;
	handle->entry->dirty = true;

	ocifs_cache_unlock_entry(handle);

	return 0;

error:
	ocifs_cache_unlock_entry(handle);
	return -1;
}

int ocifs_cache_unlink(struct ocifs_cache *cache, const char *name)
{
	int err;

	err = unlinkat(cache->dirfd, name, 0);
	if (err) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	return 1;
}

int ocifs_cache_chown(struct ocifs_cache *cache, const char *name,
		      uid_t owner, gid_t group)
{
	int err;

	err = fchownat(cache->dirfd, name, owner, group, AT_SYMLINK_NOFOLLOW);
	if (err) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	return 1;
}

int ocifs_cache_chmod(struct ocifs_cache *cache, const char *name, mode_t mode)
{
	int err;

	err = fchmodat(cache->dirfd, name, mode, 0);
	if (err) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	return 1;
}

int ocifs_cache_utimens(struct ocifs_cache *cache, const char *name,
			const struct timespec times[2])
{
	int err;

	err = utimensat(cache->dirfd, name, times, 0);
	if (err) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}

	return 1;
}

/*
 * Rename oldpath cache entry and cache file to newpath. On success,
 * return 1 if the cache file was renamed, and 0 if there was no cache
 * file. On error, return -1.
 */
int ocifs_cache_rename(struct ocifs_cache *cache,
		       const char *oldpath, const char *newpath)
{
	struct ocifs_cache_entry *entry_newpath, *entry_oldpath;
	char *entry_new_name;
	int err;

	/*
	 * We shouldn't have an entry nor a cache file with the newpath
	 * because we are going to create a new entry and cache file
	 * with that name. If such an entry exists, it should be removed
	 * by the caller before invoking this function.
	 */
	if (cache_faccess(cache, newpath) != 0)
		return -1;

	entry_newpath = ocifs_cache_lookup(cache, newpath);
	if (entry_newpath) {
		ocifs_cache_unlock(cache);
		return -1;
	}

	/*
	 * Check if we need to copy the newpath name before effectively
	 * starting the rename so that we don't have a strdup() failure
	 * in the middle of the operation.
	 */
	entry_oldpath = ocifs_cache_lookup_locked(cache, oldpath);
	if (entry_oldpath) {
		entry_new_name = strdup(newpath);
		if (!entry_new_name) {
			ocifs_cache_unlock(cache);
			return -1;
		}
	} else {
		entry_oldpath = NULL;
	}

	/*
	 * The oldpath entry should have its name updated (this requires
	 * to remove and re-add the entry in the cache).
	 */
	if (entry_oldpath) {
		ocifs_cache_rm_entry(cache, entry_oldpath);
		free((char *)entry_oldpath->name);
		entry_oldpath->name = entry_new_name;
		ocifs_cache_add_entry(cache, entry_oldpath);
	}

	ocifs_cache_unlock(cache);

	/*
	 * Check that there is effectively a cache file before trying
	 * to rename it. If there is an error, try to the rename anyway.
	 */
	if (cache_faccess(cache, oldpath) == 0)
		return 0;

	/*
	 * Rename the cache file associated with oldpath if there is
	 * one. We might not have a cache file, for example, if
	 * the oldpath was not compatible with caching.
	 */
	err = renameat(cache->dirfd, oldpath, cache->dirfd, newpath);
	if (err)
		return -1;

	return 1;
}

void ocifs_cache_invalidate(struct ocifs_cache *cache, const char *path)
{
	struct ocifs_cache_entry *entry;
	int err;
	char *p;

	/*
	 * To invalid a cache entry, remove the entry from the cache
	 * and try to remove the cache file.
	 */

	entry = ocifs_cache_lookup(cache, path);
	if (entry) {
		ocifs_cache_rm_entry(cache, entry);
		if (entry->refcount == 0)
			ocifs_cache_entry_destroy(entry);
		/*
		 * If refcount is non-zero then operations are in
		 * progress, they will continue using the corresponding
		 * opened cache file.
		 */
	}

	ocifs_cache_unlock(cache);

	err = unlinkat(cache->dirfd, path, 0);
	if (err && errno == EISDIR) {
		p = strfmt("%s%s", cache->dirpath, path);
		if (!p) {
			errno = ENOMEM;
		} else {
			err = rmtree(p);
			free(p);
		}
	}

	if (!err || errno == ENOENT) {
		/* path is gone, we are done */
		return;
	}

	OCIFS_DEBUG_CACHE("Failed to invalidate cache entry %s\n", path);
}

int ocifs_cache_adjust_ownership(struct ocifs_cache *cache, const char *path)
{
	uid_t caller_uid;
	gid_t caller_gid;
	int rv;

	if (!ocifs_caller_context())
		return 0;

	caller_uid = fuse_get_context()->uid;
	caller_gid = fuse_get_context()->gid;

	rv = ocifs_cache_chown(cache, path, caller_uid, caller_gid);
	if (rv <= 0)
		return -1;

	return 0;
}

/*
 * Cache Purge Functions
 */

bool ocifs_cache_purge_enabled(struct ocifs_cache *cache)
{
	return (cache->purge_delay != OCIFS_CACHE_PURGE_NEVER);
}

void ocifs_cache_purge_init(struct ocifs_cache *cache)
{
	int err;

	if (cache->purge_delay == OCIFS_CACHE_PURGE_NEVER)
		return;

	/*
	 * Create the purge thread. If this fails then disable
	 * purging.
	 */
	err = pthread_create(&cache->purge_thread, NULL,
			     ocifs_cache_purge_thread, cache);
	if (err) {
		OCIFS_DEBUG_CACHE("Failed to create purge thread, "
			"cache purge is disabled\n");
		cache->purge_delay = OCIFS_CACHE_PURGE_NEVER;
		cache->purge_thread = 0;
		return;
	}
}

static void
ocifs_cache_purge_rm(struct ocifs_cache *cache,
		     struct ocifs_cache_entry *entry)
{
	entry->purge_prev->purge_next = entry->purge_next;
	entry->purge_next->purge_prev = entry->purge_prev;
	entry->purge_prev = NULL;
	entry->purge_next = NULL;
}

/*
 * Add entry to the beginning of the purge list.
 */
static void
ocifs_cache_purge_enqueue(struct ocifs_cache *cache,
			  struct ocifs_cache_entry *entry)
{
	struct ocifs_cache_entry *first;

	first = cache->purge_head.purge_next;

	entry->purge_next = first;
	entry->purge_prev = &cache->purge_head;

	cache->purge_head.purge_next = entry;
	first->purge_prev = entry;
}

/*
 * Remove the cache file.
 */
static void ocifs_cache_purge_entry(struct ocifs_cache *cache,
				    struct ocifs_cache_entry *entry)
{
	int err;
	int fd;

	/*
	 * We need to keep the cache lock during the entire purge
	 * because it will temporarily reduce the file size to zero,
	 * and we need the cache file information to remain consistent.
	 */

	/* remove entry from cache */
	ocifs_cache_rm_entry(cache, entry);

	/*
	 * Purge the cache file: truncate the file to a size of 0
	 * and then back to its original size to replace the file
	 * with a sparse file. We preserve the file in order to keep
	 * the file attributes (owner, permissions).
	 */
	fd = openat(cache->dirfd, entry->name,
		    O_RDWR | O_TRUNC | O_LARGEFILE | O_NOFOLLOW);
	if (fd == -1)
		goto error;

	err = ftruncate(fd, entry->size);
	if (err) {
		close(fd);
		goto error;
	}

	(void) close(fd);

	/*
	 * Release the cache lock while destroying the cache entry to
	 * not lock the cache for too long when purging a long list of
	 * entries.
	 */
	ocifs_cache_unlock(cache);
	ocifs_cache_entry_destroy(entry);
	ocifs_cache_lock(cache);
	return;

error:
	ocifs_cache_unlock(cache);
	ocifs_cache_invalidate(cache, entry->name);
	ocifs_cache_entry_destroy(entry);
	ocifs_cache_lock(cache);
	return;
}

/*
 * Return the next entry to purge, and its purge time in *purge_timep.
 * If the purge list is empty then return NULL and set *purge_timep
 * to 0. If the purge list is not empty but there is no entry to purge
 * at the moment then return NULL and set *purge_timep with the purge
 * time of the next entry to purge.
 */
static struct ocifs_cache_entry *
ocifs_cache_purge_getnext(struct ocifs_cache *cache, time_t *purge_timep)
{
	struct ocifs_cache_entry *entry;

	/*
	 * New purge entries are added at the beginning of the purge
	 * list. So the next entry to purge is always at the end of
	 * the purge.
	 */
	entry = cache->purge_tail.purge_prev;

	if (entry == &cache->purge_head) {
		/* list is empty */
		*purge_timep = 0;
		return NULL;
	}

	if (entry->purge_time < time(NULL)) {
		/* purge time not reached */
		*purge_timep = entry->purge_time;
		return NULL;
	}

	/* entry should be purged, remove it from list */
	ocifs_cache_purge_rm(cache, entry);

	return entry;
}

/*
 * This thread erases cache files which are not opened anymore
 * and are present in the cache past the cache purge delay.
 */
static void *ocifs_cache_purge_thread(void *data)
{
	struct ocifs_cache_entry *entry;
	struct ocifs_cache *cache;
	struct timespec ts;
	time_t purge_time;

	cache = data;

	ocifs_cache_lock(cache);

	while (ocifs_cache_purge_enabled(cache)) {

		purge_time = 0;

		for (;;) {
			entry = ocifs_cache_purge_getnext(cache, &purge_time);
			if (!entry)
				break;

			ocifs_cache_purge_entry(cache, entry);
		}

		/*
		 * If there are still entries in the purge list then wait
		 * until we reach the next purge time. Otherwise, wait for
		 * entries to be added to the purge list.
		 */
		if (purge_time) {
			ts.tv_sec = purge_time;
			ts.tv_nsec = 0;
			(void) cv_timedwait(&cache->purge_cv,
					    &cache->lock, &ts);
		} else {
			cv_wait(&cache->purge_cv, &cache->lock);
		}
	}

	ocifs_cache_unlock(cache);

	return NULL;
}
