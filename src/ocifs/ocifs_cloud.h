/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#ifndef __OCIFS_CLOUD_H__
#define __OCIFS_CLOUD_H__

#include <stdbool.h>

int ocifs_cloud_check_prefix(const char *path);
int ocifs_cloud_check_prefix_used(const char *path);
int ocifs_cloud_getattr(const char *path, struct stat *stbuf);
int ocifs_cloud_add_prefix(const char *path);
int ocifs_cloud_rm_prefix(const char *path);
int ocifs_cloud_add_object(const char *path, char *buffer, size_t size);
int ocifs_cloud_add_object_from_file(const char *path, int fd);
int ocifs_cloud_check_object(const char *path);
int ocifs_cloud_list_objects(const char *path,
			     struct oci_os_list_objects *list_objects,
			     char *start);
ssize_t ocifs_cloud_read(const char *path, char *buf, size_t size,
			 off_t offset);
ssize_t ocifs_cloud_read_to_file(const char *path, int fd, size_t size,
				 off_t offset);
ssize_t ocifs_cloud_write(const char *path, char *buf, size_t size,
			  off_t offset);
int ocifs_cloud_unlink(const char *path);
int ocifs_cloud_rename(const char *oldpath, const char *newpath);
int ocifs_cloud_rename_prefix(const char *oldpath, const char *newpath);

#endif
