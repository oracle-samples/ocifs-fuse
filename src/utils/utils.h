/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <jansson.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

/*
 * Macro for alignment and roundup with a power of 2 alignment.
 */

#define P2ALIGN(value, align)		((value) & -(align))
#define P2ROUNDUP(value, align)		(-(-(value) & -(align)))

struct range_list;

enum http_method {
	HTTP_METHOD_DELETE,
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
};

enum http_status {
	HTTP_STATUS_UNAUTHORIZED = 401,
};

extern const char *http_method_names[];

ssize_t getrandom (void *buffer, size_t length, unsigned int flags);

#define STRLEN(s) ((__builtin_constant_p(s))? (sizeof(s) - 1) : strlen(s))
char *strfmt(const char *fmt, ...);
int strtotm(const char *internet_date, struct tm *tm);
int strcmp_array(char *str, char **strings, int count);

#define HTTP_DATE_FMT_SIZE 				\
	3 /* day */      + 2 /* comma + space */ +	\
	2 /* day */      + 1 /* space */ +		\
	3 /* month */    + 1 /* space */ +		\
	4 /* year */     + 1 /* space */ +		\
	2 /* hour */     + 1 /* colon */ +		\
	2 /* minute */   + 1 /* colon */ +		\
	2 /* second */   + 1 /* space */ +		\
	3 /* timezone */ + 1 /* \0 */

int http_gmtime(char *date, int date_len);
char *base64_encode(unsigned char *buf, int buf_size);
int base64url_decode(char *str, unsigned char **bufp);
int base64url_decodeb(char *str, int len, unsigned char **bufp);
RSA *load_private_key(const char *filename, char *passphrase);
RSA *read_private_key(const char *key_pem, char *passphrase);
char *file_read(char *filename, size_t *sizep);
int seek_data(int fd, struct range_list *range_list);
int rmtree(char *pathname);
void rmtree_set_root_prefix(char *prefix);
int mktree(const char *dirname, mode_t mode);
int mktree_at(int dirfd, const char *dirname, mode_t mode);
int mktree_for_file(const char *filename, mode_t mode);
int mktree_for_file_at(int dirfd, const char *filename, mode_t mode);
char *expand_path(const char *pathname);
char *escape_path(const char *path);

#define RANGE_LIST_INIT { 0 }

struct range_list {
	struct range *range;
};

struct range {
	struct range *next;
	off_t begin;
	off_t end;
};

enum range_walk_status {
	RANGE_WALK_ERROR = -1,
	RANGE_WALK_CONTINUE = 0,
	RANGE_WALK_DONE = 1,
};

enum range_overlap {
	RANGE_OVERLAP_FALSE = 0,
	RANGE_OVERLAP_TRUE = 1,
};

#define RANGE_LIST_FOREACH(r, range_list)	\
	for (r = (range_list)->range; r; r = r->next)

typedef int (*range_list_walk_cb)(off_t begin, off_t end,
				  enum range_overlap overlap,
				  void *data);

void range_list_init(struct range_list *range_list);
void range_list_fini(struct range_list *range_list);
struct range_list *range_list_create(void);
void range_list_destroy(struct range_list *range_list);
void range_list_clear(struct range_list *range_list);
int range_list_add(struct range_list *range_list, off_t offset, size_t size);
int range_list_walk_range(struct range_list *range_list,
			  off_t offset, size_t size,
			  range_list_walk_cb callb, void *data);
int range_list_walk_range_safe(struct range_list *range_list,
			       off_t offset, size_t size,
			       range_list_walk_cb callb, void *data);
void range_list_truncate(struct range_list *range_list, off_t offset);


enum dstore_type {
	DSTORE_TYPE_NONE,
	DSTORE_TYPE_BUFFER_DYNAMIC,
	DSTORE_TYPE_BUFFER_STATIC,
	DSTORE_TYPE_FD,
};

struct dstore {
	enum dstore_type type;
	union {
		struct {
			int fd;
		} file;
		struct {
			char *addr;
			/*
			 * size_alloc is the allocated size of the buffer.
			 * size_used is the amount of space used in
			 * the buffer.
			 * For a static buffer, size_used == size_alloc.
			 * For a dynamic buffer, size_used <= size_alloc.
			 */
			size_t size_alloc;
			size_t size_used;
			off_t offset;
			size_t size_increment;
		} buffer;
	};
};

void dstore_wrap_fd(struct dstore *dstore, int fd);
int dstore_wrap_buffer(struct dstore *dstore, char *buffer, size_t buffer_size);
void dstore_init(struct dstore *dstore);
void dstore_clear(struct dstore *dstore);
char *dstore_buffer(struct dstore *dstore);
char *dstore_fetch_buffer(struct dstore *dstore);
ssize_t dstore_read(struct dstore *dstore, void *buf, size_t count);
ssize_t dstore_write(struct dstore *dstore, void *buf, size_t count);
ssize_t dstore_size(struct dstore *dstore);
int dstore_sha256(struct dstore *dstore, unsigned char *digest);


enum mapping_type {
	TYPE_NUMBER,
	TYPE_DATE,
	TYPE_STRING,
};

struct json_mapping {
	size_t offset;
	char *json_member;
	enum mapping_type type;
};

json_t *json_struct_to_object(void *c_struct, struct json_mapping *mapping);
int json_object_to_struct(json_t *object, void *c_struct,
			  struct json_mapping *mapping);
int json_array_to_str_array(json_t *object, char ***c_array_p);
int json_array_to_struct_array(json_t *json_obj_list, void **objects_p,
			       size_t c_obj_size, struct json_mapping *mapping);

struct jwt {
	char *raw;
	json_t *header;
	json_t *payload;
	time_t expiration;
	char *signature;
};

struct jwt *jwt_decode(char *token_str);
void jwt_destroy(struct jwt *token);
bool jwt_has_expired(struct jwt *token, int jitter);
char *jwt_claim_str(struct jwt *token, char *claim);

void mutex_lock(pthread_mutex_t *mutex);
void mutex_unlock(pthread_mutex_t *mutex);
void rw_rdlock(pthread_rwlock_t *rwlock);
void rw_wrlock(pthread_rwlock_t *rwlock);
void rw_unlock(pthread_rwlock_t *rwlock);
void cv_wait(pthread_cond_t *cv, pthread_mutex_t *mutex);
int cv_timedwait(pthread_cond_t *cv, pthread_mutex_t *mutex,
		 struct timespec *abstime);
void cv_signal(pthread_cond_t *cv);

X509 *pem_decode_cert(char *cert_pem);
RSA *pem_decode_rsa_private(char *key_pem);
char *pem_encode_rsa_public(RSA *key);
char *pem_strip(char *pem_str);
char *cert_fingerprint(X509 *cert);
time_t cert_expiration(X509 *cert);
RSA *rsa_generate_key(int key_size);
const char *cert_subject_search_prefix(X509 *cert, const char *prefix);

#endif	/* __UTILS_H__ */
