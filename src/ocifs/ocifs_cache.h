/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#ifndef __OCIFS_CACHE_H__
#define __OCIFS_CACHE_H__

#include <stdbool.h>
#include <sys/stat.h>

#include "utils.h"

#define OCIFS_CACHE_PERM_DEFAULT_DIR		0755
#define OCIFS_CACHE_PERM_DEFAULT_FILE		0644

/*
 * Default amount of space that should remain free on the cache
 * filesystem.
 */
#define OCIFS_CACHE_FSFREE_DEFAULT	5 	/* percent */

/*
 * Default delay before purge cache files.
 */
#define OCIFS_CACHE_PURGE_DEFAULT	OCIFS_CACHE_PURGE_NEVER

/*
 * Value to indicate that the cache should never be purged. Files will
 * remain in cache while OCIFS is running.
 */
#define OCIFS_CACHE_PURGE_NEVER		-1

struct ocifs_cache;
struct ocifs_cache_handle;
struct ocifs_cache_ref;

const char *ocifs_cache_get_name(struct ocifs_cache_handle *handle);
int ocifs_cache_get_file(struct ocifs_cache_handle *handle);
int ocifs_cache_seek(struct ocifs_cache_handle *handle, off_t offset);
size_t ocifs_cache_get_size(struct ocifs_cache_handle *handle);
bool ocifs_cache_is_dirty(struct ocifs_cache_handle *handle);
void ocifs_cache_set_dirty(struct ocifs_cache_handle *handle);
void ocifs_cache_set_clean(struct ocifs_cache_handle *handle);
bool ocifs_cache_is_removed(struct ocifs_cache_handle *handle);
void ocifs_cache_set_removed(struct ocifs_cache_handle *handle);
int ocifs_cache_lock_refcount(struct ocifs_cache_handle *handle);
void ocifs_cache_unlock_refcount(struct ocifs_cache_handle *handle);
void ocifs_cache_lock_entry(struct ocifs_cache_handle *handle);
void ocifs_cache_unlock_entry(struct ocifs_cache_handle *handle);

int ocifs_cache_validate_handle(struct ocifs_cache_handle *handle,
				const char *name);
int ocifs_cache_validate_path(struct ocifs_cache *cache, const char *path);
struct ocifs_cache *ocifs_cache_create(const char *cache_root,
				       const char *bucket,
				       const char *subfolder,
				       size_t fsfree, int purge_delay);
struct ocifs_cache *ocifs_cache_create_disabled(void);
int ocifs_cache_destroy(struct ocifs_cache *cache, bool keep_cache_dir);
bool ocifs_cache_is_enabled(struct ocifs_cache *cache);
char *ocifs_cache_get_path(struct ocifs_cache *cache);
void ocifs_cache_purge_init(struct ocifs_cache *cache);
bool ocifs_cache_purge_enabled(struct ocifs_cache *cache);

int ocifs_cache_check_prefix(struct ocifs_cache *cache, const char *name);
int ocifs_cache_check_prefix_used(struct ocifs_cache *cache, const char *name);
void ocifs_cache_unref(struct ocifs_cache_ref *ref);
int ocifs_cache_add_prefix(struct ocifs_cache *cache, const char *name,
			   mode_t mode);
int ocifs_cache_rm_prefix(struct ocifs_cache *cache, const char *name);
int ocifs_cache_check_object(struct ocifs_cache *cache, const char *name);
int ocifs_cache_add_object(struct ocifs_cache *cache, const char *name,
			   size_t size);
int ocifs_cache_getattr(struct ocifs_cache *cache, const char *name,
			struct stat *stbuf, struct ocifs_cache_ref **refp);
int ocifs_cache_getattr_root(struct ocifs_cache *cache, struct stat *stbuf);
struct ocifs_cache_handle *ocifs_cache_open_object(struct ocifs_cache *cache,
						   const char *name);
struct ocifs_cache_handle *ocifs_cache_create_object(struct ocifs_cache *cache,
						     const char *name,
						     size_t size, mode_t mode);
struct ocifs_cache_handle *ocifs_cache_create_handle(struct ocifs_cache *cache,
						     const char *name,
						     size_t size);
void ocifs_cache_close(struct ocifs_cache_handle *handle);
void ocifs_cache_close_locked(struct ocifs_cache_handle *handle);
ssize_t ocifs_cache_read(struct ocifs_cache_handle *handle, char *buf,
			 size_t size, off_t offset);
ssize_t ocifs_cache_write(struct ocifs_cache_handle *handle, const char *buf,
			  size_t size, off_t offset);
int ocifs_cache_filled(struct ocifs_cache_handle *handle, off_t offset,
		       size_t size);
int ocifs_cache_walk_data(struct ocifs_cache_handle *handle,
			  off_t offset, size_t size,
			  range_list_walk_cb callb, void *data);
int ocifs_cache_truncate(struct ocifs_cache_handle *handle, off_t length);
int ocifs_cache_unlink(struct ocifs_cache *cache, const char *name);
int ocifs_cache_chown(struct ocifs_cache *cache, const char *name,
		      uid_t owner, gid_t group);
int ocifs_cache_chmod(struct ocifs_cache *cache, const char *name, mode_t mode);
int ocifs_cache_utimens(struct ocifs_cache *cache, const char *name,
			const struct timespec times[2]);
int ocifs_cache_rename(struct ocifs_cache *cache,
		       const char *oldpath, const char *newpath);
int ocifs_cache_adjust_ownership(struct ocifs_cache *cache, const char *path);
void ocifs_cache_invalidate(struct ocifs_cache *cache, const char *path);

#endif
