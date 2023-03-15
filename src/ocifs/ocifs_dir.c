/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <errno.h>
#include <string.h>

#include "ocifs.h"
#include "utils.h"

/*
 * Structure to create a singly linked list of objects, actually of
 * oci_os_object_summary so a list of arrays of objects.
 */
struct object_list {
	struct oci_os_object_summary *objects;
	int objects_count;
	struct object_list *next;
};

/*
 * Remove an object_list element from its linked list. The pointer to the
 * element is replaced with a reference to next element.
 */
static void object_list_remove(struct object_list **element_p)
{
	struct oci_os_object_summary *objects;
	struct object_list *current, *next;
	int count;
	int i;

	current = *element_p;
	if (!current)
		return;

	objects = current->objects;
	count = current->objects_count;
	next = current->next;

	for (i = 0; i < count; i++)
		oci_os_object_summary_fini(&objects[i]);

	free(objects);
	free(current);

	*element_p = next;
}

/*
 * Remove all object_list elements starting from the specified element.
 */
static void object_list_remove_all(struct object_list **start_p)
{
	while (*start_p)
		object_list_remove(start_p);
}

/*
 * Insert a new element in the list before the specified element.
 */
static int object_list_insert(struct object_list **element_p,
			      struct oci_os_list_objects *list_objects)
{
	struct object_list *new_element;

	new_element = malloc(sizeof(*new_element));
	if (!new_element)
		return -1;

	new_element->objects = list_objects->objects;
	new_element->objects_count = list_objects->objects_count;
	new_element->next = *element_p;

	*element_p = new_element;

	/*
	 * The list steals the reference to the objects, so unreference
	 * objects in list_objects so that they are not destroyed when
	 * list_objects is dereferenced.
	 */
	list_objects->objects = NULL;
	list_objects->objects_count = 0;

	return 0;
}

static void filler_object(void *buf, fuse_fill_dir_t filler,
			  struct oci_os_object_summary *object,
			  int prefix_len)
{
	struct stat stbuf = { .st_mode = S_IFREG };
	char *name;
	int rv;

	/* skip the "prefix" object */
	name = object->name + prefix_len;
	if (!*name)
		return;

	filler(buf, name, &stbuf, 0);

	if (OCIFS_CACHE_DISABLED())
		return;

	/* get the full name */
	name = object->name;
	rv = ocifs_cache_check_object(ocifs_cache, name);
	if (rv != 0) {
		/* object in cache or error */
		return;
	}

	rv = ocifs_cache_validate_path(ocifs_cache, name);
	if (rv == 0)
		(void) ocifs_cache_add_object(ocifs_cache, name, object->size);
}

static int filler_object_list(void *buf, fuse_fill_dir_t filler,
			      char *start, char *next,
			      struct oci_os_object_summary *objects,
			      int objects_count,
			      char **prefixes,	int prefixes_count,
			      int prefix_len)
{
	int objects_done;
	char *prefix;
	char *name;
	int rv;
	int i;

	objects_done = 0;

	for (i = 0; i < objects_count; i++) {
		name = objects[i].name;
		/* object name is cleared if it was already processed */
		if (!name) {
			objects_done++;
			continue;
		}

		/* build the prefix name corresponding to the object name */
		prefix = strfmt("%s/", name);
		if (!prefix)
			return -1;


		/*
		 * If the prefix is lower than start then it won't match
		 * any prefix. Otherwise we need to compare it with the
		 * current list of prefixes.
		 */
		if (start)
			rv = strcmp(prefix, start);

		if (!start || rv > 0)
			rv = strcmp_array(prefix, prefixes, prefixes_count);

		free(prefix);

		/*
		 * If the prefix is larger than all current prefixes,
		 * and there are more requests to come, then keep the
		 * object to continue checking against other prefixes
		 * from next requests.
		 */
		if (rv >= prefixes_count && next)
			continue;

		/*
		 * If the prefix doesn't match any of the current
		 * prefixes (and can't match any next prefix) then
		 * return the object name as a readdir entry.
		 *
		 * Otherwise, the name exists both as an object and
		 * as a prefix, and it is reported as a readdir entry
		 * while processing prefixes so ignore the name.
		 */
		if (rv < 0 || rv >= prefixes_count) {
			filler_object(buf, filler, &objects[i], prefix_len);
		} else {
			OCIFS_DEBUG_FOPS("Ignoring object %s, match "
					 "with prefix\n", name);
		}

		/*
		 * We are done with this object. Clear its name to
		 * indicate that we don't need to process it anymore.
		 */
		free(objects[i].name);
		objects[i].name = NULL;
		objects_done++;
	}

	return objects_done;
}

/*
 * readdir object filler. If the object name is also used as a prefix
 * name then it is not reported here but it is reported by the readdir
 * prefix filler.
 *
 * There is a bit of complexity because the object and the matching
 * prefix names can be in different requests (because of paging), so
 * we need to save objects which cannot be immediately matched with
 * prefixes, and check matching for objects previously saved.
 */
static int filler_objects(void *buf, fuse_fill_dir_t filler,
			  struct oci_os_list_objects *list_objects,
			  int prefix_len, char *start,
			  struct object_list **objects_saved_p)
{
	struct oci_os_object_summary *objects;
	struct object_list **saved_p;
	struct object_list *saved;
	int prefixes_count;
	int objects_count;
	int objects_done;
	char **prefixes;
	char *next;
	int rv;

	prefixes = list_objects->prefixes;
	prefixes_count = list_objects->prefixes_count;
	next = list_objects->next_start_with;

	/*
	 * Check previously saved objects for which we couldn't
	 * check if there was a matching prefix.
	 */
	saved_p = objects_saved_p;
	while (*saved_p) {
		saved = *saved_p;
		objects = saved->objects;
		objects_count = saved->objects_count;

		objects_done = filler_object_list(buf, filler, start, next,
						  objects, objects_count,
						  prefixes, prefixes_count,
						  prefix_len);
		if (objects_done < 0)
			return -1;

		/*
		 * If all objects are done, remove them from the
		 * saved list.
		 */
		if (objects_done == objects_count)
			object_list_remove(saved_p);
		else
			saved_p = &saved->next;
	}

	/*
	 * Check new objects
	 */
	objects = list_objects->objects;
	objects_count = list_objects->objects_count;

	objects_done = filler_object_list(buf, filler, start, next,
					  objects, objects_count,
					  prefixes, prefixes_count,
					  prefix_len);
	if (objects_done < 0)
		return -1;

	/*
	 * If we couldn't check all object names against prefix
	 * names then save objects to check them against the
	 * next round of prefixes.
	 */
	if (objects_done < objects_count) {
		rv = object_list_insert(objects_saved_p, list_objects);
		if (rv < 0)
			return -1;
	}

	return 0;
}

static void filler_prefixes(void *buf, fuse_fill_dir_t filler,
			    struct oci_os_list_objects *list_objects,
			    int prefix_len)
{
	struct stat stbuf = { .st_mode = S_IFDIR };
	char *name, *str;
	char **prefixes;
	int count;
	int rv;
	int i;

	prefixes = list_objects->prefixes;
	count = list_objects->prefixes_count;

	if (!prefixes)
		return;

	for (i = 0; i < count; i++) {
		name = prefixes[i] + prefix_len;
		if (!*name)
			continue;

		/*
		 * OCI can have objects with name starting with "/" or
		 * containing "//". In that case, the '/' prefix will be
		 * returned. Ignore it.
		 */
		if (strcmp(name, "/") == 0)
			continue;

		/* the prefix ends with the delimiter (/), remove it */
		str = name + strlen(name) - 1;
		if (*str == '/')
			*str = '\0';

		filler(buf, name, &stbuf, 0);

		if (OCIFS_CACHE_DISABLED())
			continue;

		/* get the full name */
		name = prefixes[i];
		rv = ocifs_cache_check_prefix(ocifs_cache, name);
		if (rv != 0) {
			/* object in cache or error */
			continue;
		}

		(void) ocifs_cache_add_prefix(ocifs_cache, name,
					      OCIFS_CACHE_PERM_DEFAULT_DIR);
	}
}

/*
 * Check if a prefix exists in cache or in cloud. If the prefix exists
 * in cloud but not in cache then it is cached (if cache is enabled).
 */
static int ocifs_check_prefix(const char *path)
{
	int rv;

	/*
	 * First, check if the prefix exists in cache; if it exists in
	 * cache then it exists in cloud.
	 */
	if (OCIFS_CACHE_ENABLED()) {
		rv = ocifs_cache_check_prefix(ocifs_cache, path);
		if (rv) {
			/* prefix exists or error */
			return rv;
		}
	}

	/*
	 * Next, check if the prefix exists in cloud. If the prefix exists
	 * in cloud then create a cache entry.
	 */
	rv = ocifs_cloud_check_prefix(path);
	if (rv <= 0) {
		/* prefix doesn't exist or error */
		return rv;
	}

	/*
	 * Prefix exists in cloud but not in cache, create a cache
	 * entry. We do not report an error if we fail to cache the
	 * entry, the prefix will just not be cached at the moment.
	 */
	if (OCIFS_CACHE_ENABLED()) {
		(void) ocifs_cache_add_prefix(ocifs_cache, path,
					      OCIFS_CACHE_PERM_DEFAULT_DIR);
	}

	return 1;
}

int ocifs_mkdir(const char *path, mode_t mode)
{
	int err;
	int rv;

	OCIFS_DEBUG_FOPS("mkdir %s mode=%o\n", path, mode);

	if (strcmp(path, "/") == 0)
		return -EEXIST;

	/* only create a directory which name can be cached */
	path = ocifs_get_path(path, NULL);
	if (!path)
		return -errno;

	ocifs_ns_wrlock(path);

	/*
	 * Check if prefix already exists in cache or cloud.
	 */
	rv = ocifs_check_prefix(path);
	if (rv < 0) {
		err = -EIO;
		goto error;
	}

	if (rv > 0) {
		err = -EEXIST;
		goto error;
	}

	/*
	 * Create an empty object with the name "<path>/" representing
	 * the directory.
	 */
	rv = ocifs_cloud_add_prefix(path);
	if (rv) {
		err = -EIO;
		goto error;
	}

	if (OCIFS_CACHE_DISABLED())
		goto done;

	/*
	 * Create a corresponding cache entry.
	 */
	mode &= ~fuse_get_context()->umask;
	rv = ocifs_cache_add_prefix(ocifs_cache, path, mode);
	if (rv) {
		/*
		 * The cache entry creation failure doesn't matter if we
		 * are not in a specific caller context.
		 */
		if (!ocifs_caller_context())
			goto done;

		err = -ENXIO;
		goto error_cache;
	}

	/*
	 * Make sure the cache entry has the appropriate ownership.
	 */
	rv = ocifs_cache_adjust_ownership(ocifs_cache, path);
	if (rv) {
		err = -errno;
		ocifs_cache_invalidate(ocifs_cache, path);
		goto error_cache;
	}

done:
	ocifs_ns_unlock(path);
	ocifs_release_path(path);
	return 0;

error_cache:
	err = ocifs_cloud_rm_prefix(path);
	if (err)
		OCIFS_DEBUG_FOPS("Failed to invalidate cloud entry %s\n", path);
error:
	ocifs_ns_unlock(path);
	return err;
}

int ocifs_rmdir(const char *path)
{
	bool path_cacheable;
	int err;
	int rv;

	OCIFS_DEBUG_FOPS("rmdir %s\n", path);

	if (strcmp(path, "/") == 0)
		return -EPERM;

	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	ocifs_ns_wrlock(path);

	/*
	 * First, try to remove the directory from the cache. This will
	 * fail if the directory is not empty. Otherwise, this means
	 * that this directory had no cached entry but the prefix is not
	 * necessarily unused. So then, we should check if the prefix is
	 * effectively not used before removing the prefix object.
	 *
	 * Note that we don't check if the cache directory has entries
	 * because the directory might have permissions preventing
	 * access so we just try to remove it. This can unnecessarily
	 * remove the cached directory but this will only happen when
	 * the cached directory is empty.
	 *
	 * Removing the prefix from the cache first prevent the cache
	 * from becoming inconsistent: the prefix can exist in the cloud
	 * and not in the cache, but the prefix shouldn't exist in the
	 * cache if it doesn't exist in the cloud [exception: when a
	 * new object is created, it first exists in the cache before
	 * it is pushed to the cloud on close()].
	 */
	if (OCIFS_CACHE_USABLE(path_cacheable)) {
		rv = ocifs_cache_rm_prefix(ocifs_cache, path);
		if (rv && errno != ENOENT) {
			err = -errno;
			goto error;
		}
	}

	rv = ocifs_cloud_check_prefix_used(path);
	if (rv < 0) {
		err = -EIO;
		goto error;
	}
	if (rv == 0) {
		err = -ENOENT;
		goto error;
	}
	if (rv > 1) {
		err = -ENOTEMPTY;
		goto error;
	}

	rv = ocifs_cloud_rm_prefix(path);
	if (rv) {
		err = -EIO;
		goto error;
	}

	ocifs_ns_unlock(path);
	ocifs_release_path(path);
	return 0;

error:
	ocifs_ns_unlock(path);
	ocifs_release_path(path);
	return err;
}

int ocifs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		  off_t offset, struct fuse_file_info *fi)
{
	struct object_list *object_saved = NULL;
	struct oci_os_list_objects list_objects;
	bool path_cacheable;
	int prefix_len;
	char *start;
	int error;
	int count;
	int rv;

	OCIFS_DEBUG_FOPS("readdir %s\n", path);

	/*
	 * Validate the path. It doesn't matter if the path is not valid
	 * for cache, we will get the list of files but we won't be able
	 * to cache any.
	 */
	path = ocifs_get_path(path, &path_cacheable);
	if (!path)
		return -errno;

	/*
	 * We always get the list of objects from cloud to ensure it is
	 * always acurate. We could get the list from the cache directory
	 * but we would need to track if the directory has been fully
	 * populated and that is effectively up-to-date.
	 */

	if (*path != '\0')
		prefix_len = strlen(path) + 1; /* +1 for trailing '/' */
	else
		prefix_len = 0;

	start = NULL;

	do {
		ocifs_ns_rdlock(path);
		count = ocifs_cloud_list_objects(path, &list_objects, start);
		ocifs_ns_unlock(path);

		if (count < 0) {
			free(start);
			return -EIO;
		}

		/*
		 * filler_objects() must be called before filler_prefixes().
		 *
		 * filler_objects() checks if an object name is also
		 * used as a prefix name. To do so, it relies on the
		 * list of prefixes to be sorted (as returned by the
		 * ListObject OCI API). filler_prefixes() will change
		 * prefix names by removing the leading slash ('/')
		 * and so mess up the sort order.
		 */
		rv = filler_objects(buf, filler, &list_objects, prefix_len,
				    start, &object_saved);
		if (rv < 0) {
			error = errno;
			free(start);
			object_list_remove_all(&object_saved);
			oci_os_list_objects_fini(&list_objects);
			ocifs_release_path(path);
			return -error;
		}
		filler_prefixes(buf, filler, &list_objects, prefix_len);

		free(start);
		start = list_objects.next_start_with;
		list_objects.next_start_with = NULL;

		oci_os_list_objects_fini(&list_objects);

	} while (start);

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	ocifs_release_path(path);

	return 0;
}
