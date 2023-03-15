/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <curl/curl.h>
#include <stddef.h>
#include <string.h>

#include "oci.h"
#include "utils.h"

#define MEMBER(m)	offsetof(MAPPING, m)
#define MEMBER_END	0, NULL, 0


#define MAPPING struct oci_os_object_summary

struct json_mapping oci_os_object_summary_mapping[] = {
	{ MEMBER(name),	"name", TYPE_STRING },
	{ MEMBER(size), "size", TYPE_NUMBER },
	{ MEMBER(etag),	"etag", TYPE_STRING },
	{ MEMBER(created), "timeCreated", TYPE_DATE },
	{ MEMBER(modified), "timeModified", TYPE_DATE },
	{ MEMBER_END }
};

#undef MAPPING

#define MAPPING struct oci_os_rename_object_details

struct json_mapping oci_os_rename_object_details_mapping[] = {
	{ MEMBER(new_name), "newName", TYPE_STRING },
	{ MEMBER(new_obj_if_match_etag), "newObjIfMatchETag", TYPE_STRING },
	{ MEMBER(new_obj_if_none_match_etag),
	  "newObjIfNoneMatchETag", TYPE_STRING },
	{ MEMBER(source_name), "sourceName", TYPE_STRING },
	{ MEMBER(src_obj_if_match_etag), "srcObjIfMatchETag", TYPE_STRING },
	{ MEMBER_END }
};

#undef MAPPING

/*
 * URL paths for the Object Storage API: /n/<namespace>/b/<bucket>/o/<object>
 */

#define OCI_OS_ROOT_NAMESPACE		"/n"
#define OCI_OS_PATH_NAMESPACE		OCI_OS_ROOT_NAMESPACE "/%s"
#define OCI_OS_ROOT_BUCKET		OCI_OS_PATH_NAMESPACE "/b"
#define OCI_OS_PATH_BUCKET		OCI_OS_ROOT_BUCKET "/%s"
#define OCI_OS_ROOT_OBJECT		OCI_OS_PATH_BUCKET "/o"
#define OCI_OS_PATH_OBJECT		OCI_OS_ROOT_OBJECT "/%s"
#define OCI_OS_ROOT_ACTIONS 		OCI_OS_PATH_BUCKET "/actions"
#define OCI_OS_PATH_ACTIONS 		OCI_OS_ROOT_ACTIONS "/%s"

#define OCI_OS_ACTION_RENAME_OBJECT	"renameObject"

/*
 * Macros to specify an OCI request parameter.
 *
 * PARAM_FMT is the format specifier for printf() like commands. The
 * format is make of three parts ("%s%s%s" = "<name>=" "<value>" "&")
 * so that it can be set to an empty string if the parameter is not
 * set (i.e. "%s%s%s" = "" "" "").
 *
 * PARAM() provides arguments for the PARAM_FMT specifier.
 *
 * Format specifier for an OCI request parameter:
 */
#define PARAM_FMT	"%s%s%s"

#define PARAM(cond, name, value)	\
	(cond) ? name "=" : "",	\
	(cond) ? (value) : "",		\
	(cond) ? "&" : ""

#define PATH_NAMESPACE(config)				\
	(config)->os_namespace

#define PATH_BUCKET(config)				\
	PATH_NAMESPACE(config), (config)->os_bucket

static char *oci_os_path_bucket(struct oci_config *config,
				const char *bucket_name)
{
	return strfmt(OCI_OS_PATH_BUCKET, PATH_NAMESPACE(config), bucket_name);
}

static char *oci_os_path_object(struct oci_config *config,
				const char *object_name)
{
	char *escaped_name;
	char *path;

	escaped_name = escape_path(object_name);
	path = strfmt(OCI_OS_PATH_OBJECT, PATH_BUCKET(config), escaped_name);
	if (escaped_name != object_name)
		free(escaped_name);

	return path;
}

int oci_os_head_bucket(struct oci_config *config, const char *bucket_name,
		       struct oci_os_bucket_head *bucket,
		       struct oci_error *error)
{
	struct oci_header response_header = { "ETag", NULL };
	char *path;
	int err;

	path = oci_os_path_bucket(config, bucket_name);
	if (!path) {
		oci_error(error, "Failed to create bucket path");
		return -1;
	}

	err = oci_request_head(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
			       1, &response_header, error);
	free(path);
	if (err)
		return err;

	if (!response_header.value)
		return -1;

	bucket->name = (char *)bucket_name;
	bucket->etag = response_header.value;

	return 0;
}

void oci_os_bucket_head_fini(struct oci_os_bucket_head *bucket)
{
	if (!bucket)
		return;

	free(bucket->etag);
}

int oci_os_head_object(struct oci_config *config,
		       const char *object_name,
		       struct oci_os_object_head *object,
		       struct oci_error *error)
{
	struct oci_header response_header[] = { { "ETag", NULL },
						{ "content-length", NULL },
						{ "last-modified", NULL } };
	char *content_length;
	char *last_modified;
	int rv = -1;
	char *etag;
	char *path;
	char *s;
	int err;

	path = oci_os_path_object(config, object_name);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	err = oci_request_head(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
			       ARRAY_SIZE(response_header), response_header,
			       error);
	free(path);
	if (err)
		return err;

	etag = response_header[0].value;
	content_length = response_header[1].value;
	last_modified = response_header[2].value;

	if (!etag || !content_length || !last_modified)
		goto done;

	object->content_length = strtol(content_length, &s, 10);
	if (*s != '\0')
		goto done;

	s = strptime(last_modified, "%a, %d %b %Y %T %Z",
		     &object->last_modified);
	if (*s != '\0')
		goto done;

	object->name = (char *)object_name;
	object->etag = etag;

	/* etag reference is borrowed by object->etag, do not free it */
	etag = NULL;
	rv = 0;

done:
	free(etag);
	free(content_length);
	free(last_modified);

	return rv;
}

void oci_os_object_head_fini(struct oci_os_object_head *object)
{
	if (!object)
		return;

	free(object->etag);
}

int oci_os_list_object(struct oci_config *config,
		       const char *object_name,
		       struct oci_os_object_summary *object,
		       struct oci_error *error)
{
	struct oci_os_list_objects_param param = {0};
	struct oci_os_list_objects list_objects;
	int count;

	/*
	 * There is no parameter to directly query a single object. But
	 * the 'start' parameter queries object with a name >= start,
	 * and 'end' queries object with a name < end.
	 *
	 * So to get a specific object, we use start=<name> and
	 * end=<name> + '\1'.
	 */

	param.fields = "size";
	param.start = (char *)object_name;
	param.end = strfmt("%s\1", object_name);
	if (!param.end)
		return -1;

	count = oci_os_list_objects(config, &list_objects, &param, error);
	free(param.end);

	if (count < 0) {
		/* error */
		return -1;
	}

	if (count == 0) {
		/* object doesn't exist */
		*object = (struct oci_os_object_summary) { 0 };
		return 0;
	}

	if (count > 1) {
		/* unexpected! we shouldn't get multiple objects */
		oci_os_list_objects_fini(&list_objects);
		return -1;
	}

	*object = list_objects.objects[0];

	/*
	 * We will return the single object we got. So, before clearing
	 * list_objects, set 'objects_count' to 0 (so that the object
	 * content is not clear), but do not clear 'objects' so it gets
	 * freed.
	 */
	list_objects.objects_count = 0;
	oci_os_list_objects_fini(&list_objects);

	return 1;
}

void oci_os_object_summary_fini(struct oci_os_object_summary *object)
{
	if (!object)
		return;

	free(object->name);
	free(object->etag);
}

void oci_os_list_objects_fini(struct oci_os_list_objects *list_objects)
{
	struct oci_os_object_summary *objects;
	char **prefixes;
	int i;

	if (!list_objects)
		return;

	free(list_objects->next_start_with);

	objects = list_objects->objects;
	for (i = 0; i < list_objects->objects_count; i++)
		oci_os_object_summary_fini(&objects[i]);

	prefixes = list_objects->prefixes;
	for (i = 0; i < list_objects->prefixes_count; i++)
		free(prefixes[i]);

	free(objects);
	free(prefixes);
}

static int oci_parse_prefixes(json_t *result,
			      struct oci_os_list_objects *list_objects)
{
	json_t *json_prefix_list;
	char ***prefixes;
	int count;

	json_prefix_list = json_object_get(result, "prefixes");
	if (!json_prefix_list) {
		if (list_objects) {
			list_objects->prefixes = NULL;
			list_objects->prefixes_count = 0;
		}
		return 0;
	}

	prefixes = list_objects ? &list_objects->prefixes : NULL;

	count = json_array_to_str_array(json_prefix_list, prefixes);
	if (count < 0)
		return -1;

	if (list_objects)
		list_objects->prefixes_count = count;

	return count;
}

static int oci_parse_objects(json_t *result,
			     struct oci_os_list_objects *list_objects)
{
	json_t *json_obj_list;
	void **objects;
	int count;

	json_obj_list = json_object_get(result, "objects");
	if (!json_obj_list)
		return -1;

	objects = list_objects ? (void **)&list_objects->objects : NULL;

	count = json_array_to_struct_array(json_obj_list, objects,
					   sizeof(struct oci_os_object_summary),
					   oci_os_object_summary_mapping);
	if (count < 0)
		return -1;

	if (list_objects)
		list_objects->objects_count = count;

	return count;
}

static int oci_parse_next_start_with(json_t *result,
				     struct oci_os_list_objects *list_objects,
				     char **nextp)
{
	json_t *json_str;
	char *next;

	if (!list_objects && !nextp)
		return 0;

	json_str = json_object_get(result, "nextStartWith");
	if (!json_str) {
		next = NULL;
		goto done;
	}

	next = strdup(json_string_value(json_str));
	if (!next)
		return -1;

done:
	if (list_objects)
		list_objects->next_start_with = next;
	if (nextp)
		*nextp = next;

	return 0;
}

static char *param_int(int param, int *error_p)
{
	char *value;

	if (!param)
		return NULL;

	value = strfmt("%d", param);
	if (!value) {
		*error_p = *error_p + 1;
		return NULL;
	}

	return value;
}

static char *param_str(char *param, int *error_p)
{
	char *value;

	if (!param)
		return NULL;

	value = curl_easy_escape(NULL, param, 0);
	if (!value) {
		*error_p = *error_p + 1;
		return NULL;
	}

	return value;
}

static char *oci_os_path_list_objects(struct oci_config *config,
				      struct oci_os_list_objects_param *param)
{
	char *prefix, *start, *end, *delimiter, *fields, *limit;
	char *path;
	int error;
	int len;

	if (!param)
		return strfmt(OCI_OS_ROOT_OBJECT, PATH_BUCKET(config));

	error = 0;

	prefix = param_str(param->prefix, &error);
	start = param_str(param->start, &error);
	end = param_str(param->end, &error);
	delimiter = param_str(param->delimiter, &error);
	fields = param_str(param->fields, &error);
	limit = param_int(param->limit, &error);

	if (error) {
		path = NULL;
		goto done;
	}

	len = asprintf(&path, OCI_OS_ROOT_OBJECT "?"
		       PARAM_FMT  /* prefix */
		       PARAM_FMT  /* start */
		       PARAM_FMT  /* end */
		       PARAM_FMT  /* delimiter */
		       PARAM_FMT  /* fields */
		       PARAM_FMT, /* limit */
		       PATH_BUCKET(config),
		       PARAM(param->prefix, "prefix", prefix),
		       PARAM(param->start, "start", start),
		       PARAM(param->end, "end", end),
		       PARAM(param->delimiter, "delimiter", delimiter),
		       PARAM(param->fields, "fields", fields),
		       PARAM(param->limit, "limit", limit));

	if (len != -1) {
		/*
		 * Remove the trailing character trailing character,
		 * either '?' if no parameter was added, or '&' added
		 * by PARAM() for the last parameter.
		 */
		path[len - 1] = '\0';
	} else {
		path = NULL;
	}

done:
	free(prefix);
	free(start);
	free(end);
	free(delimiter);
	free(fields);
	free(limit);

	return path;
}

static int oci_os_list_objects_page(struct oci_config *config,
				    struct oci_os_list_objects *list_objects,
				    struct oci_os_list_objects_param *param,
				    char **nextp, struct oci_error *error)
{
	json_t *result;
	char *path;
	int count;
	int err;

	path = oci_os_path_list_objects(config, param);
	if (!path) {
		oci_error(error, "Failed create list objects path");
		return -1;
	}

	result = oci_request_get_json(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
				      error);
	free(path);
	if (!result)
		return -1;

	if (list_objects)
		*list_objects = (struct oci_os_list_objects){ 0 };

	/*
	 * Parse prefixes if they were requested.
	 */
	if (param && param->delimiter) {
		count = oci_parse_prefixes(result, list_objects);
		if (count < 0) {
			oci_error(error, "Failed to parse OCI prefixes");
			json_decref(result);
			return -1;
		}
	}

	/*
	 * Parse NextStartWith.
	 */
	err = oci_parse_next_start_with(result, list_objects, nextp);
	if (err) {
		oci_error(error, "Failed to parse OCI NextStartWith");
		json_decref(result);
		/* clear list_objects to free prefixes */
		oci_os_list_objects_fini(list_objects);
		return -1;
	}

	/*
	 * Parse objects.
	 */
	count = oci_parse_objects(result, list_objects);
	if (count < 0) {
		oci_error(error, "Failed to parse list objects");
		json_decref(result);
		/* clear list_objects to free prefixes */
		oci_os_list_objects_fini(list_objects);
		return -1;
	}

	json_decref(result);

	return count;
}

/*
 * List objects.
 *
 * If list_objects is not NULL then return objects for the parameters
 * specified in 'param'. Because of paging and the 'limit' attribute,
 * the list can be incomplete. In that case, the 'next_start_with'
 * attribute will be set in 'param', and the function returns the number
 * of objects returned in 'list_objects'.
 *
 * If list_objects is NULL then the function returns the total number of
 * objects for the parameters specified in 'param'.
 */
int oci_os_list_objects(struct oci_config *config,
			struct oci_os_list_objects *list_objects,
			struct oci_os_list_objects_param *param,
			struct oci_error *error)
{
	struct oci_os_list_objects_param _param = { 0 };
	char *next = NULL;
	char *start;
	int limit;
	int count;
	int c;

	c = oci_os_list_objects_page(config, list_objects, param, &next,
				     error);
	if (c < 0)
		return c;

	if (list_objects) {
		/*
		 * Do not free 'next' because it is also referenced
		 * in list_objects.
		 */
		return c;
	}

	/*
	 * If list_objects is NULL then count the total number of
	 * objects and return that value.
	 */

	if (!param)
		param = &_param;

	start = param->start;
	limit = param->limit;
	count = c;

	while (next && (!limit || count < limit)) {
		param->start = next;
		c = oci_os_list_objects_page(config, NULL, param, &next,
					     error);
		free(param->start);
		if (c < 0) {
			count = c;
			break;
		}
		count += c;
	}

	free(next);
	param->start = start;

	return count;
}

static int get_object_headers(struct oci_os_get_object_param *param,
			      char **header_p, int *header_count_p)

{
	off_t range_begin, range_end;
	int header_count;
	char *header;

	if (!param) {
		*header_p = NULL;
		*header_count_p = 0;
		return 0;
	}

	if (param->range_start < 0 || param->range_size < 0)
		return -1;

	range_begin = param->range_start;
	range_end = range_begin + param->range_size - 1;

	header = strfmt("range: bytes=%zu-%zu", range_begin, range_end);
	if (!header)
		return -1;

	header_count = 1;

	*header_p = header;
	*header_count_p = header_count;

	return 0;
}

int oci_os_get_object(struct oci_config *config, const char *object_name,
		      char **bufp, size_t *sizep,
		      struct oci_os_get_object_param *param,
		      struct oci_error *error)
{
	int header_count, err;
	char *path, *header;

	path = oci_os_path_object(config, object_name);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	err = get_object_headers(param, &header, &header_count);
	if (err) {
		oci_error(error, "Failed to get object headers");
		free(path);
		return -1;
	}

	err = oci_request_get(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
			      bufp, sizep, &header, header_count,
			      error);

	free(header);
	free(path);

	return err;
}

int oci_os_get_object_to_file(struct oci_config *config,
			      const char *object_name, int fd,
			      struct oci_os_get_object_param *param,
			      struct oci_error *error)
{
	int header_count, err;
	char *path, *header;

	path = oci_os_path_object(config, object_name);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	err = get_object_headers(param, &header, &header_count);
	if (err) {
		oci_error(error, "Failed to get object headers");
		free(path);
		return -1;
	}

	err = oci_request_get_to_file(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
				      fd, &header, header_count,
				      error);

	free(header);
	free(path);

	return err;
}

int oci_os_put_object(struct oci_config *config, const char *object_name,
		      char *buffer, size_t size, struct oci_error *error)
{
	char *path;
	int err;

	path = oci_os_path_object(config, object_name);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	err = oci_request_put(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
			      buffer, size, NULL, 0, error);

	free(path);

	return err;
}

int oci_os_put_object_from_file(struct oci_config *config,
				const char *object_name, int fd,
				struct oci_error *error)
{
	char *path;
	int err;

	path = oci_os_path_object(config, object_name);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	err = oci_request_put_from_file(config,
					OCI_ENDPOINT_OBJECT_STORAGE, path,
					fd, NULL, 0, error);

	free(path);

	return err;
}

int oci_os_delete_object(struct oci_config *config, const char *object_name,
			 struct oci_error *error)
{
	char *path;
	int err;

	path = oci_os_path_object(config, object_name);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	err = oci_request_delete(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
				 error);

	free(path);

	return err;
}

int oci_os_rename_object(struct oci_config *config, const char *old_name,
			 const char *new_name, struct oci_error *error)
{
	struct oci_os_rename_object_details rename = { 0 };
	json_t *object;
	char *body;
	char *path;
	int err;

	path = strfmt(OCI_OS_PATH_ACTIONS, PATH_BUCKET(config),
		      OCI_OS_ACTION_RENAME_OBJECT);
	if (!path) {
		oci_error(error, "Failed to create object path");
		return -1;
	}

	rename.source_name = old_name;
	rename.new_name = new_name;

	object = json_struct_to_object(&rename,
				       oci_os_rename_object_details_mapping);
	if (!object) {
		oci_error(error, "Failed to create JSON request");
		free(path);
		return -1;
	}

	body = json_dumps(object, 0);
	if (!body) {
		oci_error(error, "Failed to create request body");
		free(path);
		json_decref(object);
		return -1;
	}

	err = oci_request_post(config, OCI_ENDPOINT_OBJECT_STORAGE, path,
			       body, strlen(body), NULL, 0,
			       error);

	free(body);
	json_decref(object);
	free(path);

	return err;
}

char *oci_os_get_namespace(struct oci_config *config, struct oci_error *error)
{
	char *namespace = NULL;
	json_t *result;

	result = oci_request_get_json(config,
				      OCI_ENDPOINT_OBJECT_STORAGE,
				      OCI_OS_ROOT_NAMESPACE,
				      error);
	if (!result)
		return NULL;

	if (!json_is_string(result)) {
		oci_error(error, "Response is not a JSON string");
		goto done;
	}

	namespace = (char *)json_string_value(result);
	if (!namespace)
		goto done;

	namespace = strdup(namespace);

done:
	json_decref(result);
	return namespace;
}

/*
 * Do an IMDS request and return the result as a NUL ('\0') terminated
 * string.
 */
char *oci_imds_get_str(struct oci_config *config, char *path,
		       struct oci_error *error)
{
	char *buf = NULL;
	size_t size;
	int err;

	err = oci_request_imds_get(config, path, &buf, &size, error);
	if (err)
		return NULL;
	buf[size] = '\0';

	return buf;
}
