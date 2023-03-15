/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#ifndef __OCI_H__
#define __OCI_H__

#include <jansson.h>
#include <openssl/rsa.h>

#include "utils.h"

#define OCI_DEBUG(config, ...)					\
	do {							\
		if ((config)->debug)				\
			printf(__VA_ARGS__);			\
	} while (0)

#define OCI_ERROR(...)		printf(__VA_ARGS__)

/*
 * Jitter (in seconds) for security token expiration time.
 */
#define OCI_CONFIG_EXPIRATION_JITTER	60	/* seconds */

/*
 * The OCI configuration structure.
 */

enum oci_config_auth {
	OCI_CONFIG_AUTH_NONE,
	OCI_CONFIG_AUTH_API_KEY,
	OCI_CONFIG_AUTH_INSTANCE_PRINCIPAL,
	OCI_CONFIG_AUTH_RESOURCE_PRINCIPAL,
};

struct oci_config;

typedef int (*oci_config_token_refresh_f)(struct oci_config *);

struct oci_config {

	enum oci_config_auth auth;
	const char *domain;
	const char *user_agent;
	int debug;

	/*
	 * Attributes for authentication. All attributes are not
	 * necessarily used, this depends on the authentication
	 * method.
	 */
	const char *user;
	const char *fingerprint;
	const char *keyfile;
	const char *tenancy;
	RSA *private_key;

	/*
	 * Additional attributes for token-based authentication (instance
	 * principal and resource principal).
	 */
	pthread_rwlock_t rwlock;
	struct jwt *security_token;
	oci_config_token_refresh_f security_token_refresh;

	/*
	 * Additional attributes for instance principal authentication.
	 */
	RSA *tenant_key;
	char *cert_pem;
	time_t cert_expiration;
	char *intermediate_pem;

	/*
	 * Object Storage attributes.
	 */
	char *os_namespace;
	char *os_bucket;
};

struct oci_header {
	char *name;
	char *value;
};

const char *oci_region_to_domain(const char *region);

/*
 * OCI Error reporting.
 *
 * The error reporting depend on the error level:
 *
 * Level 0 (basic): report request_status and http_status
 * Level 1 (verbose): also report the OCI error code and message
 * Level 2 (debug): add the raw OCI error message
 */

struct oci_error {
	const char *description;
	int level;
	int request_status;	/* 0 (CURLE_OK) or CURL error */
	int http_status;
	/* verbose */
	char *code;
	char *message;
	/* debug */
	char *buffer;
};

#define OCI_ERROR_INIT_LEVEL(l)	       		\
	((struct oci_error) { 			\
		.level = (l),			\
		.request_status = 0,		\
		.http_status = 0,		\
		.code = NULL,			\
		.message = NULL,		\
		.buffer = NULL,			\
	 })

#define OCI_ERROR_INIT		OCI_ERROR_INIT_LEVEL(0)
#define OCI_ERROR_INIT_VERBOSE	OCI_ERROR_INIT_LEVEL(1)
#define OCI_ERROR_INIT_DEBUG	OCI_ERROR_INIT_LEVEL(2)

void oci_error(struct oci_error *error, const char *error_str);
void oci_error_request_set(struct oci_error *error,
			   int request_status, int http_status);
void oci_error_request_set_verbose(struct oci_error *error,
				   int request_status, int http_status,
				   const char *error_code,
				   const char *error_msg);
void oci_error_request_set_debug(struct oci_error *error,
				 int request_status, int http_status,
				 const char *error_code, const char *error_msg,
				 char *error_buf, int error_buflen);
void oci_error_fini(struct oci_error *error);
void oci_error_print(struct oci_error *error);

/*
 * OCI API Endpoint
 *
 * The list is not exhaustive but limited to endpoints we are using.
 */

#define OCI_ENDPOINT_AUTH "auth"
#define OCI_ENDPOINT_OBJECT_STORAGE "objectstorage"


/*
 * OCI API - Object Storage
 */


/*
 * The maximum object size allowed by PutObject is 50GiB.
 */
#define OCI_PUT_OBJECT_SIZE_MAX	(50UL * 1024 * 1024 * 1024)

struct oci_os_bucket_head {
	char *name;
	char *etag;
};

struct oci_os_object_head {
	char *name;
	char *etag;
	size_t content_length;
	struct tm last_modified;
};

struct oci_os_object_summary {
	char *name;
	size_t size;
	char *etag;
	struct tm created;
	struct tm modified;
};

struct oci_os_list_objects {
	char *next_start_with;
	struct oci_os_object_summary *objects;
	int objects_count;
	char **prefixes;
	int prefixes_count;
};

struct oci_os_rename_object_details {
	const char *new_name;
	const char *new_obj_if_match_etag;
	const char *new_obj_if_none_match_etag;
	const char *source_name;
	const char *src_obj_if_match_etag;
};

struct oci_os_list_objects_param {
	char *prefix;
	char *start;
	char *end;
	int limit;
	char *delimiter;
	char *fields;
};

struct oci_os_get_object_param {
	off_t range_start;
	size_t range_size;
};

struct oci_config *oci_config_create_empty(int debug);
struct oci_config *oci_config_create_common(enum oci_config_auth auth,
					    const char *region,
					    const char *user_agent,
					    oci_config_token_refresh_f
					    token_refresh,
					    int debug);
struct oci_config *oci_config_create_from_file(const char *filename,
					       const char *region,
					       const char *user_agent,
					       int debug);
int oci_config_init_object_storage(struct oci_config *config,
				   const char *bucket);
void oci_config_destroy(struct oci_config *config);
struct oci_config *oci_config_instance_principal(const char *region,
						 const char *user_agent,
						 int debug);
struct oci_config *oci_config_resource_principal(const char *region,
						 const char *user_agent,
						 int debug);
bool oci_config_has_security_token(struct oci_config *config);
char *oci_config_get_security_token(struct oci_config *config);
void oci_config_put_security_token(struct oci_config *config);
bool oci_config_refresh(struct oci_config *config);

char *oci_auth_header(struct oci_config *config, char *date,
		      enum http_method method, const char *endpoint, char *path,
		      size_t clen, const char *content_type,
		      char *content_sha256);
char *oci_auth_get_security_token(struct oci_config *config,
				  char *cert_pem, char *intermediate_pem,
				  RSA *session_key);

int oci_request_post(struct oci_config *config,
		     const char *endpoint, char *path,
		     char *buf, size_t size,
		     char **headers, int headers_count,
		     struct oci_error *error);
json_t *oci_request_post_json(struct oci_config *config,
			      const char *endpoint, char *path,
			      char *buf, size_t size,
			      char **headers, int headers_count,
			      struct oci_error *error);
int oci_request_get(struct oci_config *config,
		    const char *endpoint, char *path,
		    char **bufp, size_t *sizep,
		    char **headers, int headers_count,
		    struct oci_error *error);
int oci_request_get_to_file(struct oci_config *config,
			    const char *endpoint, char *path, int fd,
			    char **headers, int headers_count,
			    struct oci_error *error);
json_t *oci_request_get_json(struct oci_config *config,
			     const char *endpoint, char *path,
			     struct oci_error *error);
int oci_request_put(struct oci_config *config,
		    const char *endpoint, char *path,
		    char *buf, size_t size,
		    char **headers, int headers_count,
		    struct oci_error *error);
int oci_request_put_from_file(struct oci_config *config,
			      const char *endpoint, char *path, int fd,
			      char **headers, int headers_count,
			      struct oci_error *error);
int oci_request_delete(struct oci_config *config,
		       const char *endpoint, char *path,
		       struct oci_error *error);
int oci_request_head(struct oci_config *config,
		     const char *endpoint, char *path,
		     int response_hcount, struct oci_header *response_headers,
		     struct oci_error *error);

int oci_request_imds_get(struct oci_config *config, char *path,
			 char **bufp, size_t *sizep,
			 struct oci_error *error);

int oci_os_head_bucket(struct oci_config *config, const char *bucket_name,
		       struct oci_os_bucket_head *bucket,
		       struct oci_error *error);
void oci_os_bucket_head_fini(struct oci_os_bucket_head *bucket);

int oci_os_head_object(struct oci_config *config,
		       const char *object_name,
		       struct oci_os_object_head *object,
		       struct oci_error *error);
void oci_os_object_head_fini(struct oci_os_object_head *object);

void oci_os_object_summary_fini(struct oci_os_object_summary *object);
void oci_os_list_objects_fini(struct oci_os_list_objects *list_objects);

char *oci_os_get_namespace(struct oci_config *config,
			   struct oci_error *error);
int oci_os_list_object(struct oci_config *config,
		       const char *object_name,
		       struct oci_os_object_summary *object,
		       struct oci_error *error);
int oci_os_list_objects(struct oci_config *config,
			struct oci_os_list_objects *list_objects,
			struct oci_os_list_objects_param *param,
			struct oci_error *error);
int oci_os_get_object(struct oci_config *config, const char *object_name,
		      char **bufp, size_t *sizep,
		      struct oci_os_get_object_param *param,
		      struct oci_error *error);
int oci_os_get_object_to_file(struct oci_config *config,
			      const char *object_name, int fd,
			      struct oci_os_get_object_param *param,
			      struct oci_error *error);
int oci_os_put_object(struct oci_config *config, const char *object_name,
		      char *buffer, size_t size,
		      struct oci_error *error);
int oci_os_put_object_from_file(struct oci_config *config,
				const char *object_name, int fd,
				struct oci_error *error);
int oci_os_delete_object(struct oci_config *config, const char *object_name,
			 struct oci_error *error);
int oci_os_rename_object(struct oci_config *config, const char *old_name,
			 const char *new_name, struct oci_error *error);

char *oci_imds_get_str(struct oci_config *config, char *path,
		       struct oci_error *error);

#endif	/* __OCI_H__ */
