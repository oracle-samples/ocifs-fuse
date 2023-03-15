/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#define FUSE_USE_VERSION 26

#include <dirent.h>
#include <errno.h>
#include <mntent.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <fuse.h>

#include "ocifs.h"
#include "utils.h"

/*
 * The ocifs command is either invoked directly by the user using
 * the following syntax:
 *
 *   ocifs [<options>] <bucket>[/<subfolder>] <mountpoint>
 *
 * or it is invoked by the mount command (through mount.fuse). In
 * that case, it uses the following syntax:
 *
 *   ocifs <bucket>[/<subfolder>] <mountpoint> [-o <mount-options>]
 *
 * <options> and <mount-options> use the same option names, except
 * that long options start with two dashes. Some <options> cannot be
 * used as <mount-options>.
 */

#define OCIFS_CMD_ERROR(...)	printf(__VA_ARGS__)

/*
 * OCIFS mount options. A mount option can be used as a direct option
 * from the ocifs CLI (i.e. --option[=val]) or as a mount command option
 * (i.e. -o option[=val]).
 */
#define OCIFS_MNT_OPT(opt, offset, value)	\
	{ opt, offset, value },			\
	{ "--" opt, offset, value }

uid_t ocifs_uid;
gid_t ocifs_gid;
struct ocifs_options ocifs_options;
struct ocifs_cache *ocifs_cache;
const char *ocifs_subfolder;

#define BUCKETPATH_FMT	"%s%s%s"

#define BUCKETPATH(bucket, subfolder)	\
	(bucket), ((subfolder)? "/" : ""), ((subfolder)? (subfolder) : "")

static const struct fuse_opt ocifs_opts[] = {
	OCIFS_MNT_OPT("auth=%s",   offsetof(struct ocifs_options, auth), 0),
	OCIFS_MNT_OPT("config=%s", offsetof(struct ocifs_options, config), 0),
	OCIFS_MNT_OPT("region=%s", offsetof(struct ocifs_options, region), 0),
	OCIFS_MNT_OPT("cache=%s",  offsetof(struct ocifs_options, cache), 0),
#ifdef DEBUG
	OCIFS_MNT_OPT("cache-disable",
		      offsetof(struct ocifs_options, cache_disable), 1),
#endif
	OCIFS_MNT_OPT("cache-fsfree=%s",
		      offsetof(struct ocifs_options, cache_fsfree), 0),
	OCIFS_MNT_OPT("cache-keep",
		      offsetof(struct ocifs_options, cache_keep), 1),
	OCIFS_MNT_OPT("cache-purge=%s",
		      offsetof(struct ocifs_options, cache_purge), 0),
	OCIFS_MNT_OPT("cache-reuse",
		      offsetof(struct ocifs_options, cache_reuse), 1),
	{ "--check-bucket", offsetof(struct ocifs_options, check_bucket), 1 },
	{ "--version", offsetof(struct ocifs_options, version), 1 },
	FUSE_OPT_END
};

struct ocifs_debug_option {
	const char *name;
	int level;
};

static struct ocifs_debug_option ocifs_debug_options[] = {
	{ "all",	OCIFS_DEBUG_LVL_ALL },
	{ "cache",	OCIFS_DEBUG_LVL_CACHE },
	{ "fops",	OCIFS_DEBUG_LVL_FOPS },
	{ "oci",	OCIFS_DEBUG_LVL_OCI },
	{ "other",	OCIFS_DEBUG_LVL_OTHER },
};

struct oci_config *oci_config;

/*
 * Return true if we have a caller context that should be taken
 * into account.
 */
bool ocifs_caller_context(void)
{
	uid_t caller_uid;
	gid_t caller_gid;

	if (ocifs_uid != 0)
		return false;

	caller_uid = fuse_get_context()->uid;
	caller_gid = fuse_get_context()->gid;

	if (caller_uid == ocifs_uid && caller_gid == ocifs_gid)
		return false;

	return true;
}

static void usage(void)
{
	int i;

	printf("Usage:\n");
	printf("       ocifs [<options>] <bucket>[/<subfolder>] <mountpoint>\n");
	printf("       ocifs [<options>] --check-bucket <bucket>\n");
	printf("\n");
	printf("Options:\n");
	printf("\n");
	printf("  --auth=<auth-method> : Set the authentication method, "
	       "either api_key\n"
	       "      (the default), instance_principal or resource_principal\n");
	printf("  --config=<config-file> : OCI configuration file "
	       "(default: ~/.oci/config)\n");
	printf("  --region=<region-name> : OCI region or domain\n");
	printf("  --cache=<cache-directory> : OCIFS cache directory "
	       "(default: ~/.ocifs)\n");
#ifdef DEBUG
	printf("  --cache-disable: Disable cache\n");
#endif
	printf("  --cache-fsfree=<limit>: Cache filesystem free space limit\n");
	printf("  --cache-keep: "
	       "Do not remove the OCIFS cache directory on exit\n");
	printf("  --cache-purge=never|<value>: "
	       "Delay before purging cache file\n");
	printf("  --cache-reuse: Reuse data from the OCIFS cache directory\n");
	printf("  --debug=<level>[,<level>...] : Debug levels (");
	for (i = 0; i < ARRAY_SIZE(ocifs_debug_options) - 1; i++)
		printf("%s ", ocifs_debug_options[i].name);
	printf("%s)\n", ocifs_debug_options[i].name);
	printf("\n");
}

static void *ocifs_init_fuse(struct fuse_conn_info *conn)
{
	ocifs_cache_purge_init(ocifs_cache);
	return NULL;
}

static const struct fuse_operations ocifs_operations = {
	.chmod		= ocifs_chmod,
	.chown		= ocifs_chown,
	.create		= ocifs_create,
	.flush		= ocifs_flush,
	.fsync		= ocifs_fsync,
	.getattr	= ocifs_getattr,
	.init		= ocifs_init_fuse,
	.mkdir		= ocifs_mkdir,
	.open		= ocifs_open,
	.read		= ocifs_read,
	.readdir	= ocifs_readdir,
	.release	= ocifs_release,
	.rename		= ocifs_rename,
	.rmdir		= ocifs_rmdir,
	.truncate	= ocifs_truncate,
	.unlink		= ocifs_unlink,
	.utimens	= ocifs_utimens,
	.write		= ocifs_write,
};

/*
 * Convert the cache-fsfree option to corresponding values.
 */
static int ocifs_init_fsfree(void)
{
	long long int value;
	size_t fsfree;
	size_t unit;
	char suffix;
	char *str;

	if (ocifs_options.cache_fsfree == NULL) {
		fsfree = OCIFS_CACHE_FSFREE_DEFAULT;
		goto done;
	}

	value = strtoll(ocifs_options.cache_fsfree, &str, 10);
	if (value == LLONG_MIN || value == LLONG_MAX ||
	    str == ocifs_options.cache_fsfree) {
		/* invalid value */
		printf("cache-fsfree: invalid value\n");
		return -1;
	}

	if (value < 0) {
		printf("cache-fsfree: invalid negative value\n");
		return -1;
	}

	fsfree = value;

	/*
	 * If the option just specifies a value then it should be 0
	 * (cache-fsfree=0).
	 */
	if (str[0] == '\0') {
		if (fsfree != 0) {
			printf("cache-fsfree: value should be 0 or have a suffix\n");
			return -1;
		}
		goto done;
	}

	/*
	 * The value should be followed by "%" or "[KMGT]" or "[KMGT]i".
	 */
	if (strcmp(str, "%") == 0) {
		if (fsfree > 100) {
			printf("cache-fsfree: invalid percentage value\n");
			return -1;
		}
		goto done;
	};

	suffix = *str++;

	if (*str == 'i') {
		unit = 1024ULL;
		str++;
	} else {
		unit = 1000ULL;
	}

	if (*str != '\0') {
		printf("cache-fsfree: invalid suffix\n");
		return -1;
	}

	switch (suffix) {

	case 'T':
		fsfree *= unit;
		/* fall through */
	case 'G':
		fsfree *= unit;
		/* fall through */
	case 'M':
		fsfree *= unit;
		/* fall through */
	case 'K':
		fsfree *= unit;
		break;

	default:
		printf("cache-fsfree: invalid unit\n");
		return -1;
	}

done:
	ocifs_options.cache_fsfree_value = fsfree;
	return 0;
}

/*
 * Convert the cache-purge option to corresponding values.
 */
static int ocifs_init_purge(void)
{
	long int value;
	int purge_delay;
	char *str;

	if (ocifs_options.cache_purge == NULL) {
		purge_delay = OCIFS_CACHE_PURGE_DEFAULT;
		goto done;
	}

	if (strcmp(ocifs_options.cache_purge, "never") == 0) {
		purge_delay = OCIFS_CACHE_PURGE_NEVER;
		goto done;
	}

	value = strtol(ocifs_options.cache_purge, &str, 10);
	if (value < 0 || value > INT_MAX || *str != '\0' ||
	    str == ocifs_options.cache_purge) {
		/* invalid value */
		printf("cache-purge: invalid value\n");
		return -1;
	}

	purge_delay = value;

done:
	ocifs_options.cache_purge_delay = purge_delay;
	return 0;
}

static int ocifs_init_options(void)
{
	int err;

	/*
	 * Check bucket should have no non-option argument. Otherwise,
	 * we have a single non-option argument: the mountpoint.
	 */
	if (ocifs_options.check_bucket) {
		if (ocifs_options.nonopt != 0)
			return -1;
		/*
		 * Check bucket needs cache to be configured but it
		 * won't effectively use it. So run even if a cache
		 * exists and don't remove it.
		 */
		ocifs_options.cache_reuse = 1;
		ocifs_options.cache_keep = 1;
	} else if (ocifs_options.nonopt != 1) {
		return -1;
	}

	if (!ocifs_options.bucket)
		return -1;

	err =  ocifs_init_fsfree();
	if (err)
		return err;

	err = ocifs_init_purge();
	if (err)
		return err;

	return 0;
}

static void ocifs_fini_options(void)
{
	free(ocifs_options.bucket);
	free(ocifs_options.config);
}

static int ocifs_init_config(void)
{
	const char *user_agent;
	const char *region;
	char *auth;
	int debug;

	region = ocifs_options.region;
	debug = ocifs_options.debug & OCIFS_DEBUG_LVL_OCI ? 1 : 0;
	user_agent = strfmt("OCIFS/%s", OCIFS_VERSION);
	if (!user_agent) {
		OCIFS_CMD_ERROR("Failed to create user-agent string\n");
		return -1;
	}

	auth = ocifs_options.auth;
	if (auth == NULL || strcmp(auth, "api_key") == 0) {
		oci_config = oci_config_create_from_file(ocifs_options.config,
							 region, user_agent,
							 debug);
	} else if (strcmp(auth, "instance_principal") == 0) {
		oci_config = oci_config_instance_principal(region, user_agent,
							   debug);
	} else if (strcmp(auth, "resource_principal") == 0) {
		oci_config = oci_config_resource_principal(region, user_agent,
							   debug);
	} else {
		OCIFS_CMD_ERROR("Unknown authentication method '%s'\n", auth);
		free((char *)user_agent);
		return -2;
	}

	free((char *)user_agent);

	if (!oci_config) {
		OCIFS_CMD_ERROR("Failed to create OCI config\n");
		return -1;
	}

	return 0;
}

static void ocifs_fini_config(void)
{
	if (!oci_config)
		return;

	oci_config_destroy(oci_config);
}

enum {
	OCIFS_NAME_NOT_VISIBLE = 0x01,
	OCIFS_NAME_NOT_CACHEABLE = 0x02,
	OCIFS_NAME_OBJECT_AND_PREFIX = 0x04,
	OCIFS_NAME_CHECK_ERROR = 0x08,
};

static int ocifs_check_object_name(char *name)
{
	int status;
	int rv;

	status = 0;

	if (name[0] == '/' || strstr(name, "//")) {
		printf("  %s: NOT_VISIBLE\n", name);
		status |= OCIFS_NAME_NOT_VISIBLE;
	}

	rv = ocifs_cache_validate_path(ocifs_cache, name);
	if (rv == 1) {
		printf("  %s: NOT_CACHEABLE\n", name);
		status |= OCIFS_NAME_NOT_CACHEABLE;
	}

	if (name[strlen(name) - 1] == '/')
		return status;

	/*
	 * If we have an object then check if there is a prefix
	 * using the same name.
	 */

	rv = ocifs_cloud_check_prefix(name);
	if (rv < 0) {
		printf("  %s: CHECK_ERROR\n", name);
		status |= OCIFS_NAME_CHECK_ERROR;
	} else if (rv) {
		printf("  %s: OBJECT_AND_PREFIX\n", name);
		status |= OCIFS_NAME_OBJECT_AND_PREFIX;
	}

	return status;
}

static void ocifs_check_bucket(void)
{
	struct oci_os_list_objects_param param = { 0 };
	struct oci_os_list_objects list_objects;
	struct oci_os_object_summary *objects;
	char *next;
	int error;
	int count;
	int i;

	printf("\n");
	printf("BUCKET: %s\n", oci_config->os_bucket);
	printf("\n");
	printf("PROBLEMS:\n");
	printf("\n");

	error = 0;
	while (1) {
		count = oci_os_list_objects(oci_config, &list_objects,
					    &param, NULL);
		free(param.start);
		if (count < 0) {
			printf("Failed to list objects\n");
			return;
		}

		objects = list_objects.objects;
		for (i = 0; i < count; i++)
			error |= ocifs_check_object_name(objects[i].name);

		next = list_objects.next_start_with;
		if (!next) {
			oci_os_list_objects_fini(&list_objects);
			break;
		}

		param.start = strdup(next);
		oci_os_list_objects_fini(&list_objects);
	};

	if (!error) {
		printf("No problem found.\n");
		printf("\n");
		return;
	}

	printf("\n");
	printf("DESCRIPTION:\n");
	printf("\n");

	if (error & OCIFS_NAME_NOT_VISIBLE) {
		printf("  NOT_VISIBLE: The object name is incompatible "
		       "with the filesystem naming.\n"
		       "  The object will not be visible nor accessible "
		       "from the filesystem.\n");
		printf("\n");
	}

	if (error & OCIFS_NAME_NOT_CACHEABLE) {
		printf("  NOT_CACHEABLE: The name is compatible with the "
		       "filesystem naming, but it\n"
		       "  is too long for caching. The object will be "
		       "visible from the filesystem\n"
		       "  but it will accessible only for reading.\n");
		printf("\n");
	}

	if (error & OCIFS_NAME_OBJECT_AND_PREFIX) {
		printf("  OBJECT_AND_PREFIX: The same name is used for an "
		       "object and as a prefix.\n");
		printf("\n");
	}

	if (error & OCIFS_NAME_CHECK_ERROR) {
		printf("  OCIFS_NAME_CHECK_ERROR: Internal error while "
		       "checking object name.\n");
		printf("\n");
	}

	printf("SOLUTION:\n");
	printf("\n");
	if (error & (OCIFS_NAME_NOT_VISIBLE | OCIFS_NAME_NOT_VISIBLE)) {
		printf("  NOT_VISIBLE, NOT_CACHEABLE:\n");
		printf("\n");
		printf("    To fix these issues, rename the objects with names "
		       "compatible with the\n"
		       "    filesystem and with caching.\n");
		printf("\n");
		printf("    To be compatible with the filesystem and with "
		       "caching, the object name must:\n"
		       "    - not start with a slash (\"/\")\n"
		       "    - not contain two consecutive slashes (\"//\")\n"
		       "    - if the name has no slash then it must be shorter "
		       "than 256 characters\n"
		       "    - if the name has slashes then names before or "
		       "after each slash should be\n"
		       "      shorter than 256 characters\n");
		printf("\n");
	}

	if (error & OCIFS_NAME_OBJECT_AND_PREFIX) {
		printf("  OBJECT_AND_PREFIX:\n");
		printf("\n");
		printf("    To fix these issues, rename the objects with names "
		       "different from any\n");
		printf("    prefix names.\n");
		printf("\n");
	}

	if (error & OCIFS_NAME_CHECK_ERROR) {
		printf("  OCIFS_NAME_CHECK_ERROR:\n");
		printf("\n");
		printf("    Retry the command. Internal error can be due to "
		       "memory allocation\n");
		printf("    errors or network errors.\n");
		printf("\n");
	}
}

/*
 * Report if an OCIFS fsname is already used by the specified mounted
 * fsname (fsname_mnt).
 *
 * Return true if the fsname is used, false otherwise.
 */
static bool ocifs_fsname_is_used_by(const char *fsname, const char *fsname_mnt)
{
	char *prefix = NULL;
	int fsname_mnt_len;
	int fsname_len;
	int rv;

	fsname_len = strlen(fsname);
	fsname_mnt_len = strlen(fsname_mnt);

	if (fsname_len < fsname_mnt_len) {
		rv = strncmp(fsname, fsname_mnt, fsname_len);
		if (rv == 0 && fsname_mnt[fsname_len] == '/')
			prefix = "Subpath";
	} else if (fsname_len > fsname_mnt_len) {
		rv = strncmp(fsname, fsname_mnt, fsname_mnt_len);
		if (rv == 0 && fsname[fsname_mnt_len] == '/')
			prefix = "Parent path";
	} else {
		rv = strcmp(fsname, fsname_mnt);
		if (rv == 0)
			prefix = "Path";
	}

	if (prefix) {
		OCIFS_CMD_ERROR("%s %s is already mounted\n",
				prefix, fsname_mnt);
		return true;
	}

	return false;
}

/*
 * Report if a bucket path (<bucket>/<subfolder>) is already used by
 * OCIFS i.e. if a part of the path or if an underneath path is already
 * mounted with OCIFS.
 *
 * Return > 0 if the path is already used, 0 if the path is not used,
 * and -1 if there is an error.
 */
static int ocifs_bucket_path_is_busy(const char *bucket, const char *subfolder)
{
	struct mntent *mntent;
	const char *fsname;
	FILE *mtab;
	int used;

	if (subfolder)
		fsname = strfmt("%s/%s", bucket, subfolder);
	else
		fsname = bucket;

	if (!fsname)
		return -1;

	mtab = setmntent("/etc/mtab", "r");
	if (!mtab) {
		OCIFS_CMD_ERROR("Failed to open /etc/mtab\n");
		goto error;
	}

	used = 0;

	while ((mntent = getmntent(mtab)) != NULL) {
		if (strcmp(mntent->mnt_type, "fuse.ocifs") != 0)
			continue;
		if (ocifs_fsname_is_used_by(fsname, mntent->mnt_fsname))
			used++;
	}

	endmntent(mtab);

	return used;

error:
	if (subfolder)
		free((char *)fsname);

	return -1;
}

static int ocifs_init_bucket(void)
{
	char *subfolder;
	char *bucket;
	int err;
	int rv;

	bucket = ocifs_options.bucket;

	if (bucket[0] == '/') {
		OCIFS_CMD_ERROR("Invalid bucket name '%s'\n", bucket);
		return -1;
	}

	subfolder = strchr(bucket, '/');
	if (subfolder && subfolder[1] != '\0') {
		*(subfolder++) = '\0';
		OCIFS_DEBUG("bucket: %s\n", bucket);
		OCIFS_DEBUG("subfolder: %s\n", subfolder);
	} else {
		OCIFS_DEBUG("bucket: %s\n", bucket);
	}

	err = oci_config_init_object_storage(oci_config, bucket);
	if (err) {
		OCIFS_CMD_ERROR("Failed to init storage connect\n");
		return -1;
	}

	if (!subfolder)
		return 0;

	/*
	 * Define a subfolder. When a subfolder is set then all object
	 * names will be relative to the subfolder, otherwise object
	 * names are relative to the bucket root.
	 */

	/* check that the subfolder exist in the cloud */
	rv = ocifs_cloud_check_prefix(subfolder);
	if (rv < 0) {
		OCIFS_CMD_ERROR("Failed to check subfolder %s\n", subfolder);
		return -1;
	}
	if (rv == 0) {
		OCIFS_CMD_ERROR("Subfolder %s not found\n", subfolder);
		return -1;
	}

	ocifs_subfolder = strdup(subfolder);
	if (!ocifs_subfolder) {
		OCIFS_CMD_ERROR("Failed to init subfolder\n");
		return -1;
	}

	return 0;
}

static int ocifs_init_cache_check_empty(const char *cache_name);

static int ocifs_init_cache(void)
{
	char *cache_name;
	char *cache_root;

	if (ocifs_options.cache_disable) {
		ocifs_cache = ocifs_cache_create_disabled();
		if (!ocifs_cache) {
			OCIFS_CMD_ERROR("Failed to initialize cache disabling\n");
			return -1;
		}
		return 0;
	}

	if (!ocifs_options.cache)
		cache_root = expand_path("~/.ocifs");
	else
		cache_root = expand_path(ocifs_options.cache);

	if (!cache_root) {
		OCIFS_CMD_ERROR("Failed to expand ~/.ocifs path\n");
		return -1;
	}

	ocifs_cache = ocifs_cache_create(cache_root, oci_config->os_bucket,
					 ocifs_subfolder,
					 ocifs_options.cache_fsfree_value,
					 ocifs_options.cache_purge_delay);
	if (!ocifs_cache) {
		OCIFS_CMD_ERROR("Failed to create OCIFS cache for bucket path '"
				BUCKETPATH_FMT "' in %s\n",
				BUCKETPATH(oci_config->os_bucket, ocifs_subfolder),
				cache_root);
		free(cache_root);
		return -1;
	}
	free(cache_root);

	cache_name = ocifs_cache_get_path(ocifs_cache);

	/*
	 * If the user is root then explicitly allow root to rmtree()
	 * the cache directory.
	 */
	if (geteuid() == 0)
		rmtree_set_root_prefix(cache_name);

	return ocifs_init_cache_check_empty(cache_name);
}

static int ocifs_init_cache_check_empty(const char *cache_name)
{
	struct dirent *dent;
	DIR *dir;
	char *n;

	/*
	 * Check if the cache is empty i.e. if the directory has at
	 * least one entry (other than . and ..).
	 */

	dir = opendir(cache_name);
	if (!dir) {
		OCIFS_CMD_ERROR("Failed to open cache directory %s\n",
				cache_name);
		return -1;
	}

	while ((dent = readdir(dir)) != NULL) {
		n = dent->d_name;
		/* ignore "." and ".." */
		if (n[0] == '.') {
			if (n[1] == '\0')
				continue;
			if (n[1] == '.'  && n[2] == '\0')
				continue;
		}

		/* directory is not empty */
		OCIFS_CMD_ERROR("Cache directory %s is not empty\n",
				cache_name);

		if (ocifs_options.cache_reuse)
			break;

		closedir(dir);
		return -1;
	}

	closedir(dir);

	return 0;
}

static void ocifs_fini_cache(void)
{
	char *cache_name = NULL;
	int err;

	if (!ocifs_cache)
		return;

	if (OCIFS_CACHE_ENABLED()) {
		/*
		 * Keep a copy of the cache name so that we can print it
		 * if there was an error.
		 */
		cache_name = strdup(ocifs_cache_get_path(ocifs_cache));
	}
	err = ocifs_cache_destroy(ocifs_cache, ocifs_options.cache_keep);
	if (err)
		OCIFS_CMD_ERROR("Failed to remove cache directory %s\n",
				cache_name);
	free(cache_name);
}

static int ocifs_opt_add(struct fuse_args *args, char *option)
{
	int err;

	err = fuse_opt_add_arg(args, "-o");
	if (err)
		return -1;

	err = fuse_opt_add_arg(args, option);
	if (err)
		return -1;

	return 0;
}

static int ocifs_opt_parse_debug(struct ocifs_options *options, const char *arg)
{
	char *value;
	char *v;
	int i;

	if (strncmp(arg, "debug=", STRLEN("debug=")) == 0)
		arg += STRLEN("debug=");
	else if (strncmp(arg, "--debug=", STRLEN("--debug=")) == 0)
		arg += STRLEN("--debug=");
	else
		return 1;

	value = strdup(arg);
	if (!value)
		return -1;

	v = strtok(value, ",");
	do {
		for (i = 0; i < ARRAY_SIZE(ocifs_debug_options); i++) {
			if (strcmp(v, ocifs_debug_options[i].name) == 0) {
				options->debug |= ocifs_debug_options[i].level;
				break;
			}
		}

		if (i >= ARRAY_SIZE(ocifs_debug_options))
			printf("Ignoring unknown debug option '%s'\n", v);

		v = strtok(NULL, ",");
	} while (v);

	free(value);
	return 0;
}

static int ocifs_opt_proc(void *data, const char *arg, int key,
			  struct fuse_args *outargs)
{
	struct ocifs_options *options = data;

	if (key != FUSE_OPT_KEY_NONOPT)
		return ocifs_opt_parse_debug(options, arg);

	/*
	 * The first non-option argument is the bucket, we store it
	 * and we don't add it to the output argument vector. Other
	 * non-option arguments (i.e. the mount point) are preserved.
	 */
	if (!options->bucket) {
		options->bucket = strdup(arg);
		return 0;
	}

	options->nonopt++;

	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	char *fsname = NULL;
	int ret = -1;
	int err;

	err = fuse_opt_parse(&args, &ocifs_options, ocifs_opts, ocifs_opt_proc);
	if (err)
		return 1;

	if (ocifs_options.version) {
		printf("%s\n", OCIFS_VERSION);
		fuse_opt_free_args(&args);
		return 0;
	}

	err = ocifs_init_options();
	if (err) {
		ret = 1;
		goto error;
	}

	err = ocifs_init_config();
	if (err) {
		if (err == -2)
			ret = 1;
		goto error;
	}

	err = ocifs_init_bucket();
	if (err)
		goto error;

	/*
	 * Check if bucket path is busy before cache init.
	 */
	if (!ocifs_options.check_bucket &&
	    ocifs_bucket_path_is_busy(oci_config->os_bucket,
				      ocifs_subfolder))
		goto error;

	err = ocifs_init_cache();
	if (err)
		goto error;

	if (ocifs_options.check_bucket) {
		ocifs_check_bucket();
		ret = 0;
		goto error;
	}

	ocifs_uid = getuid();
	ocifs_gid = getgid();
	umask(0);

	/*
	 * If the filesystem is mounted by root then force the
	 * default_permissions option to have the kernel performs
	 * permission check.
	 */
	if (ocifs_uid == 0) {
		err = ocifs_opt_add(&args, "default_permissions");
		if (err)
			goto error;
	}

	/*
	 * Set the filesystem source with the bucket name. Also specify
	 * the subtype as just setting fsname would otherwise reset the
	 * fs type to "fuse" (instead of "fuse.ocifs").
	 */
	fsname = strfmt("fsname=" BUCKETPATH_FMT ",subtype=ocifs",
			BUCKETPATH(oci_config->os_bucket, ocifs_subfolder));
	if (!fsname) {
		OCIFS_CMD_ERROR("Failed to create fsname option\n");
		goto error;
	}

	err = ocifs_opt_add(&args, fsname);
	if (err)
		goto error;

	ret = fuse_main(args.argc, args.argv, &ocifs_operations, NULL);

error:
	free(fsname);
	ocifs_fini_cache();
	ocifs_fini_config();
	ocifs_fini_options();

	fuse_opt_free_args(&args);

	if (ret == 1) {
		usage();
		return 2;
	}

	return ret ? 1 : 0;
}
