/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>

#include "ocifs.h"
#include "utils.h"
#include "string.h"

static char *prefix_path(const char *path)
{
	return strfmt("%s/", path);
}

static int get_objects_with_prefix(char *prefix, int limit,
				   struct oci_os_list_objects *list_objects,
				   char *start)
{
	struct oci_os_list_objects_param param = {0};

	param.prefix = prefix;
	param.start = start;
	param.limit = limit;

	return oci_os_list_objects(oci_config, list_objects, &param, NULL);
}

/*
 * Check if a prefix exists in cloud. Return 1 if the prefix exists,
 * 0 if the prefix doesn't exist and -1 if there is an error.
 */
int ocifs_cloud_check_prefix(const char *path)
{
	char *object_name;
	int count;

	/*
	 * To check the prefix exists in cloud, check if there is any object
	 * with a name starting with "<path>/".
	 */

	object_name = prefix_path(path);
	if (!object_name)
		return -1;

	count = get_objects_with_prefix(object_name, 1, NULL, NULL);

	free(object_name);

	if (count < 0)
		return -1;

	return count == 0 ? 0 : 1;
}

int ocifs_cloud_check_object(const char *path)
{
	struct oci_os_object_summary object;
	int count;

	count = oci_os_list_object(oci_config, path, &object, NULL);
	if (count < 0)
		return -1;

	oci_os_object_summary_fini(&object);

	return count > 0 ? 1 : 0;
}

/*
 * Check if a prefix exists in the cloud and is used by other entries.
 * Return:
 *   0  - prefix is not in cloud
 *   1  - prefix is in cloud but not used,
 *  >1  - prefix is in cloud and used
 *  -1  - there is an error
 */
int ocifs_cloud_check_prefix_used(const char *path)
{
	struct oci_os_list_objects list_objects;
	char *object_name;
	int count;
	int rv;

	/*
	 * Check if there are multiple (i.e. at least 2) objects with
	 * a name starting with "<path>/". If that's the case then there
	 * is directory and it is not empty.
	 */

	object_name = prefix_path(path);
	if (!object_name)
		return -1;

	count = get_objects_with_prefix(object_name, 2, &list_objects, NULL);

	if (count < 0) {

		/* error */
		rv = -1;

	} else if (count == 0) {

		/* no entry with prefix */
		rv = 0;

	} else if (count == 1) {
		/*
		 * If there is a single object then check that this
		 * is effectively the prefix object. Otherwise this
		 * means that the prefix is used although there is
		 * no prefix object.
		 */
		if (strcmp(list_objects.objects[0].name, object_name) == 0)
			rv = 1;
		else
			rv = 2;
	} else {
		/*
		 * We have at least two object with the prefix so the
		 * prefix exists and it is used.
		 */
		rv = 2;
	}
	
	oci_os_list_objects_fini(&list_objects);
	free(object_name);

	return rv;
}

static void ocifs_cloud_getattr_common(const char *path, struct stat *stbuf,
				       mode_t mode, int nlink, size_t size)
{
	struct timespec now = {0};

	/*
	 * Ignore errors if we can't get time. In case, all times will
	 * be set to 0.
	 */
	(void) clock_gettime(CLOCK_REALTIME, &now);

	stbuf->st_mode = mode;
	stbuf->st_nlink = nlink;
	stbuf->st_size = size;

	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();

	/*
	 * Set all times to the current time.
	 *
	 * This could be improved by getting some time values from
	 * the object. An object has a timeCreated and a timeModified.
	 * timeCreated can be mapped to statx.stx_btime, and timeModified
	 * to st_mtim. But there is no mapping for st_atim and st_ctim.
	 */

	stbuf->st_atim = now ;	/* last access */
	stbuf->st_mtim = now;	/* last modification */
	stbuf->st_ctim = now;	/* last change */
}

static int ocifs_cloud_getattr_prefix(const char *path, struct stat *stbuf)
{
	char *object_name;
	int count;

	/*
	 * Check if any object has a name starting with "<path>/". If
	 * there is then consider that "<path>" is a directory.
	 */

	object_name = prefix_path(path);
	if (!object_name)
		return -1;
	
	count = get_objects_with_prefix(object_name, 1, NULL, NULL);

	free(object_name);

	if (count < 0)
		return -1;

	if (count == 0)
		return 0;

	ocifs_cloud_getattr_common(path, stbuf, S_IFDIR | 0755, 2, 0);

	return 1;
}

static int ocifs_cloud_getattr_object(const char *path, struct stat *stbuf)
{
	struct oci_os_object_summary object;
	int count;

	/*
	 * Check that an object with the name "<path>" exits. If it does
	 * then consider the object as a regular file.
	 */

	count = oci_os_list_object(oci_config, path, &object, NULL);
	if (count < 0)
		return -1;

	if (count == 0)
		return 0;

	ocifs_cloud_getattr_common(path, stbuf, S_IFREG | 0644, 1, object.size);

	oci_os_object_summary_fini(&object);

	return 1;
}

int ocifs_cloud_getattr(const char *path, struct stat *stbuf)
{
	int rv;

	/*
	 * First, check if a prefix exist. If not, check if an object exists.
	 */

	rv = ocifs_cloud_getattr_prefix(path, stbuf);
	if (rv) {
		/* prefix was found or there was an error */
		return rv;
	}
	
	return ocifs_cloud_getattr_object(path, stbuf);
}

int ocifs_cloud_add_prefix(const char *path)
{
	char *object_name;
	int err;

	object_name = prefix_path(path);
	if (!object_name)
		return -1;

	err = oci_os_put_object(oci_config, object_name, NULL, 0, NULL);
	if (err) {
		free(object_name);
		return -1;
	}

	free(object_name);
	return 0;
}

int ocifs_cloud_rm_prefix(const char *path)
{
	char *object_name;
	int err;

	object_name = prefix_path(path);
	if (!object_name)
		return -1;

	err = oci_os_delete_object(oci_config, object_name, NULL);
	if (err) {
		free(object_name);
		return -1;
	}

	free(object_name);
	return 0;
}

int ocifs_cloud_list_objects(const char *path,
			     struct oci_os_list_objects *list_objects,
			     char *start)
{
	struct oci_os_list_objects_param param = {0};
	int count;

	param.start = start;
	param.delimiter = "/";
	param.fields = "size";
	if (*path != '\0') {
		param.prefix = prefix_path(path);
		if (!param.prefix)
			return -1;
	}

	count = oci_os_list_objects(oci_config, list_objects, &param, NULL);
	free(param.prefix);

	return count;
}

ssize_t ocifs_cloud_read(const char *path, char *buf, size_t size, off_t offset)
{
	struct oci_os_get_object_param param = {0};
	int err;

	param.range_start = offset;
	param.range_size = size;

	err = oci_os_get_object(oci_config, path, &buf, &size, &param, NULL);
	if (err)
		return -1;

	return size;
}

ssize_t ocifs_cloud_read_to_file(const char *path, int fd, size_t size, off_t offset)
{
	struct oci_os_get_object_param param = {0};
	int err;

	param.range_start = offset;
	param.range_size = size;

	err = oci_os_get_object_to_file(oci_config, path, fd, &param, NULL);
	if (err)
		return -1;

	return size;
}

ssize_t ocifs_cloud_write(const char *path, char *buf, size_t size, off_t offset)
{
	errno = ENOTSUP;
	return -1;
}

int ocifs_cloud_add_object(const char *path, char *buffer, size_t size)
{
	return oci_os_put_object(oci_config, path, NULL, 0, NULL);
}

int ocifs_cloud_add_object_from_file(const char *path, int fd)
{
	return oci_os_put_object_from_file(oci_config, path, fd, NULL);
}

/*
 * Delete an OCI Object Storage object.
 *
 * Return value:
 *  0 : object doesn't exist
 *  1 : object exists and was successfully deleted
 * -1 : error
 */
int ocifs_cloud_unlink(const char *path)
{
	struct oci_error error = OCI_ERROR_INIT;
	int http_status;
	int err;

	err = oci_os_delete_object(oci_config, path, NULL);
	if (err) {
		/*
		 * DeleteObject returns HTTP status 404 if the object
		 * doesn't exist.
		 */
		http_status = error.http_status;
		oci_error_fini(&error);
		return http_status == 404 ? 0 : -1;
	}

	return 1;
}

static int ocifs_cloud_rename_objects(struct oci_os_object_summary *objects,
				       int objects_count,
				       char *prefix_old, char *prefix_new,
				       int prefix_old_len,
				       bool *prefix_old_object_p)
{
	char *old, *new;
	int count;
	int rv;
	int i;

	count = 0;

	for (i = 0; i < objects_count; i++) {
		old = objects[i].name;
		if (strcmp(old, prefix_old) == 0) {
			*prefix_old_object_p = true;
			continue;
		}

		/*
		 * Create the new name by adding the new prefix to the
		 * the part of the name after the old prefix.
		 */
		new = strfmt("%s%s", prefix_new, old + prefix_old_len);
		if (!new) {
			OCI_ERROR("Failed to rename %s prefix %s to %s\n",
				  old, prefix_old, prefix_new);
			return -1;
		}

		rv = ocifs_cloud_rename(old, new);
		if (rv < 0) {
			OCI_ERROR("Failed to rename %s to %s\n", old, new);
			break;
		}

		free(new);
		count++;
	}

	return count;
}

int ocifs_cloud_rename_prefix(const char *oldpath, const char *newpath)
{
	struct oci_os_list_objects list_objects = { 0 };
	bool prefix_old_object;
	int prefix_old_len;
	char *prefix_old;
	char *prefix_new;
	char *start;
	int count;
	int err;
	int rv;

	prefix_old = prefix_path(oldpath);
	if (!prefix_old)
		return -1;

	prefix_new = prefix_path(newpath);
	if (!prefix_new) {
		free(prefix_old);
		return -1;
	}

	prefix_old_len = strlen(prefix_old);

	/*
	 * Track if an old prefix object exists to rename it last.
	 */
	prefix_old_object = false;

	/*
	 * Rename all objects which names start with the old prefix.
	 */
	count = 0;
	start = NULL;
	{
		list_objects = (struct oci_os_list_objects) { 0 };

		rv = get_objects_with_prefix(prefix_old, 0,
					     &list_objects, start);
		free(start);
		if (rv < 0)
			goto error;

		rv = ocifs_cloud_rename_objects(list_objects.objects,
						list_objects.objects_count,
						prefix_old, prefix_new,
						prefix_old_len,
						&prefix_old_object);
		if (rv < 0)
			goto error;

		count += rv;

		start = list_objects.next_start_with;
		if (start) {
			start = strdup(start);
			if (!start) {
				oci_os_list_objects_fini(&list_objects);
				goto error;
			}
		}

		oci_os_list_objects_fini(&list_objects);

	} while (start);

	/*
	 * Finally, rename the prefix object.
	 */
	if (prefix_old_object) {
		rv = ocifs_cloud_rename(prefix_old, prefix_new);
	} else {
		/*
		 * Create a new prefix object if no old prefix was
		 * present.
		 */
		err = oci_os_put_object(oci_config, prefix_new, NULL, 0,
					NULL);
		rv = err ? -1 : 1;
	}

	free(prefix_old);
	free(prefix_new);

	/*
	 * If we are able to rename all objects starting with the old
	 * prefix then we consider that the rename was successful even
	 * if we failed to rename the prefix object itself.
	 */
	if (count)
		return 1;

	/*
	 * There was no object containing the prefix we are renaming. So
	 * the success of the rename only rely on the renaming of the
	 * prefix object.
	 */

	return rv;

error:
	free(prefix_old);
	free(prefix_new);
	return -1;
}

/*
 * Rename an OCI Object Storage object.
 *
 * Return value:
 *  0 : object doesn't exist
 *  1 : object exists and was successfully renamed
 * -1 : error
 */
int ocifs_cloud_rename(const char *oldpath, const char *newpath)
{
	struct oci_error error = OCI_ERROR_INIT;
	int http_status;
	int err;

	err = oci_os_rename_object(oci_config, oldpath, newpath, &error);
	if (err) {
		/*
		 * RenameObject returns HTTP status 404 if the object
		 * doesn't exist.
		 */
		http_status = error.http_status;
		oci_error_fini(&error);
		return http_status == 404 ? 0 : -1;
	}

	return 1;
}
