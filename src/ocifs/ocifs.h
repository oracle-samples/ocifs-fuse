/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#ifndef __OCIFS_H__
#define __OCIFS_H__

#include <fuse.h>
#include <stdbool.h>

#include "oci.h"
#include "ocifs_cache.h"
#include "ocifs_cloud.h"
#include "ocifs_namespace.h"
#include "utils.h"


extern struct oci_config *oci_config;
extern uid_t ocifs_uid;
extern gid_t ocifs_gid;

struct ocifs_options {
	int nonopt;
	char *auth;
	char *bucket;
	unsigned int check_bucket;
	char *config;
	unsigned int debug;
	char *region;
	/* cache */
	char *cache;
	unsigned int cache_disable;
	char *cache_fsfree;
	size_t cache_fsfree_value;
	unsigned int cache_keep;
	char *cache_purge;
	int cache_purge_delay;
	unsigned int cache_reuse;
	unsigned int version;
};

extern struct ocifs_options ocifs_options;
extern struct ocifs_cache *ocifs_cache;
extern const char *ocifs_subfolder;

#define OCIFS_DEBUG_LVL_OCI		0x00000001
#define OCIFS_DEBUG_LVL_FOPS		0x00000002
#define OCIFS_DEBUG_LVL_CACHE		0x00000004
#define OCIFS_DEBUG_LVL_OTHER		0x80000000
#define OCIFS_DEBUG_LVL_ALL		0xffffffff

#define OCIFS_DEBUG_LVL(level, type, fmt, ...)				\
	do {								\
		if (ocifs_options.debug & (level))			\
			printf("OCIFS " type ": " fmt, ##__VA_ARGS__);	\
	} while (0)

#define __OCIFS_DEBUG(type, ...)					\
	OCIFS_DEBUG_LVL(OCIFS_DEBUG_LVL_ ## type, #type, __VA_ARGS__)

#define OCIFS_DEBUG_FOPS(...)	__OCIFS_DEBUG(FOPS, __VA_ARGS__)
#define OCIFS_DEBUG_CACHE(...)	__OCIFS_DEBUG(CACHE, __VA_ARGS__)
#define OCIFS_DEBUG(...)	__OCIFS_DEBUG(OTHER, __VA_ARGS__)

#define OCIFS_CACHE_ENABLED()	(ocifs_cache_is_enabled(ocifs_cache))
#define OCIFS_CACHE_DISABLED()	(!ocifs_cache_is_enabled(ocifs_cache))
#define OCIFS_CACHE_USABLE(path_cacheable)	\
	(OCIFS_CACHE_ENABLED() && (path_cacheable))

const char *ocifs_get_path(const char *path, bool *cachep);
void ocifs_release_path(const char *path);
bool ocifs_caller_context(void);

int ocifs_mkdir(const char *path, mode_t mode);
int ocifs_rmdir(const char *path);
int ocifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		  off_t offset, struct fuse_file_info *fi);

int ocifs_chmod(const char *path, mode_t mode);
int ocifs_chown(const char *path, uid_t owner, gid_t group);
int ocifs_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int ocifs_flush(const char *path, struct fuse_file_info *fi);
int ocifs_fsync(const char *path, int datasync, struct fuse_file_info *fi);
int ocifs_getattr(const char *path, struct stat *stbuf);
int ocifs_open(const char *path, struct fuse_file_info *fi);
int ocifs_read(const char *path, char *buf, size_t size, off_t offset,
	       struct fuse_file_info *fi);
int ocifs_release(const char *path, struct fuse_file_info *fi);
int ocifs_rename(const char *oldpath, const char *newpath);
int ocifs_truncate(const char *path, off_t length);
int ocifs_unlink(const char *path);
int ocifs_utimens(const char *path, const struct timespec times[2]);
int ocifs_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi);

#endif
