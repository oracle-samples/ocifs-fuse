/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "oci.h"
#include "utils.h"

#define OCI_REQUEST_IMDS_URL	"http://169.254.169.254/opc/v2/%s"

#define OCI_REQUEST_BUFSIZE 4096

struct oci_request {
	struct oci_config *config;
	CURL *curl;

	int flags;
	size_t content_length;
	const char *content_type;
	char *content_sha256;
	size_t recv_len;

	struct dstore body_request;	    /* request body */
	struct dstore body_response;	    /* response body */

	int request_headers_count;
	char **request_headers;
	int response_hcount;			/* response header count */
	struct oci_header *response_headers;	/* response headers */
};

struct oci_body_cfg {
	char	*buffer;
	ssize_t	buffer_size;
	int	fd;
};

#define OCI_BODY_CFG(buf, size, fd)	((struct oci_body_cfg){buf, size, fd})
#define OCI_BODY_NONE			OCI_BODY_CFG(NULL, -1, -1)
#define OCI_BODY_FD(fd)			OCI_BODY_CFG(NULL, 0, fd)
#define OCI_BODY_BUFFER(buf, size)	OCI_BODY_CFG(buf, size, -1)
#define OCI_BODY_BUFFER_DYNAMIC		OCI_BODY_BUFFER(NULL, 1024)

#define OCI_REQUEST_SHA256		0x01
#define OCI_REQUEST_IMDS		0x02

static int oci_configure_body(struct dstore *body, struct oci_body_cfg body_cfg)
{
	int err;

	if (body_cfg.fd == -1 && body_cfg.buffer_size == -1) {
		dstore_init(body);
		return 0;
	}

	if (body_cfg.fd >= 0) {
		dstore_wrap_fd(body, body_cfg.fd);
		return 0;
	}

	err = dstore_wrap_buffer(body, body_cfg.buffer, body_cfg.buffer_size);
	if (err) {
		return -1;
	}

	return 0;
}

static int oci_request_prepare(struct oci_request *request,
			       struct oci_config *config,
			       struct oci_body_cfg request_body_cfg,
			       struct oci_body_cfg response_body_cfg)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	CURL *curl;
	int err;

	curl = curl_easy_init();
	if (!curl)
		return -1;

	request->config = config;
	request->curl = curl;
	request->content_sha256 = NULL;

	err = oci_configure_body(&request->body_request, request_body_cfg);
	if (err)
		goto error;

	err = oci_configure_body(&request->body_response, response_body_cfg);
	if (err)
		goto error;

	if (request->flags & OCI_REQUEST_SHA256) {
		err = dstore_sha256(&request->body_request, digest);
		if (err)
			goto error;
		request->content_sha256 = base64_encode(digest,
							SHA256_DIGEST_LENGTH);
		if (!request->content_sha256)
			goto error;
	}

	request->content_length = dstore_size(&request->body_request);
	request->recv_len = 0;

	return 0;

error:
	dstore_clear(&request->body_request);
	dstore_clear(&request->body_response);
	curl_easy_cleanup(curl);
	free(request->content_sha256);
	return -1;
}

static void oci_request_set_flags(struct oci_request *request, int flags)
{
	request->flags = flags;
}

static void oci_request_set_content_type(struct oci_request *request,
					 const char *content_type)
{
	request->content_type = content_type;
}

static void oci_request_set_request_headers(struct oci_request *request,
					    int request_headers_count,
					    char **request_headers)
{
	request->request_headers_count = request_headers_count;
	request->request_headers = request_headers;

}

static void oci_request_set_response_headers(struct oci_request *request,
					     int response_hcount,
					     struct oci_header *response_headers)
{
	int i;

	if (response_headers && response_hcount > 0) {
		for (i = 0; i < response_hcount; i++)
			response_headers[i].value = NULL;
		request->response_hcount = response_hcount;
		request->response_headers = response_headers;
	} else {
		request->response_hcount = 0;
		request->response_headers = NULL;
	}
}


static void oci_request_fini(struct oci_request *request)
{
	if (!request)
		return;

	dstore_clear(&request->body_request);
	dstore_clear(&request->body_response);
	curl_easy_cleanup(request->curl);
	free(request->content_sha256);
}

static size_t oci_request_read_cb(char *ptr, size_t size, size_t nmemb, void *data)
{
	struct oci_request *request = data;
	ssize_t send_len;
	size_t len;

	OCI_DEBUG(request->config,
		  "READ CALLBACK: %zd*%zd bytes\n", size, nmemb);

	len = size * nmemb;

	send_len = dstore_read(&request->body_request, ptr, len);
	if (send_len < 0)
		return CURL_READFUNC_ABORT;

	return send_len;
}

static size_t oci_request_write_cb(char *ptr, size_t size, size_t nmemb, void *data)
{
	struct oci_request *request = data;
	size_t recv_len, len;

	OCI_DEBUG(request->config,
		  "WRITE CALLBACK: %zd*%zd bytes\n", size, nmemb);

	len = size * nmemb;
	recv_len = request->recv_len;

	recv_len = dstore_write(&request->body_response, ptr, len);
	if (recv_len < 0)
		return 0;

	request->recv_len += recv_len;

	return recv_len;
}

static size_t oci_request_header_cb(char *buffer, size_t size, size_t nmemb,
				    void *data)
{
	struct oci_request *request = data;
	char *old_value, *new_value;
	struct oci_header *header;
	char *name;
	size_t len;
	int i,j;

	len = size * nmemb;

	OCI_DEBUG(request->config, "HEADER CALLBACK: %zd*%zd bytes: %.*s\n",
		  size, nmemb, (int)len, buffer);

	for (i = 0; i < request->response_hcount; i++) {
		header = &request->response_headers[i];
		name = header->name;
		j = strlen(name);
		if (j + 1 >= len) {
			/*
			 * The header we are looking for has a name
			 * (+ the colon ':' separator) which is too
			 * long for this buffer.
			 */
			continue;
		}
		if (buffer[j] != ':')
			continue;

		if (strncasecmp(buffer, name, j) != 0)
			continue;

		/*
		 * The header name matches, get its value (we ignore
		 * whitespaces before and after the value).
		 */
		for (j++; j < len; j++) {
			if (!isspace(buffer[j]))
				break;
		}

		while (len > j && isspace(buffer[len - 1]))
			len--;

		old_value = header->value;
		if (old_value)
			new_value = strfmt("%s,%.*s", old_value,
					   ((int)len) - j, buffer + j);
		else
			new_value = strndup(buffer + j, len - j);

		if (!new_value)
			return 0;

		free(old_value);
		header->value = new_value;
		break;
	}

	return size * nmemb;
}

/*
 * Add an header and return the new CURL header list. The header is
 * not added if it is NULL. If there is an error then the header
 * list is freed.
 */
static int add_header_const(struct curl_slist **curl_headersp, char *header)
{
	struct curl_slist *slist = *curl_headersp;
	struct curl_slist *temp;

	if (!header)
		return 0;

	temp = curl_slist_append(slist, header);
	if (!temp) {
		curl_slist_free_all(slist);
		return -1;
	}

	*curl_headersp = temp;
	return 0;
}

/*
 * Add a dynamically allocated header and return the new CURL header
 * list. Return an error if the header is NULL or if adding the header
 * fails. If there is an error then the header list is freed. In all
 * cases, the header is freed.
 */
static int add_header(struct curl_slist **curl_headersp, char *header)
{
	struct curl_slist *slist = *curl_headersp;
	struct curl_slist *temp;

	if (!header) {
		curl_slist_free_all(slist);
		return -1;
	}

	temp = curl_slist_append(slist, header);
	free(header);
	if (!temp) {
		curl_slist_free_all(slist);
		return -1;
	}

	*curl_headersp = temp;
	return 0;
}

static struct curl_slist *oci_request_init_headers(struct oci_request *request,
						   enum http_method method,
						   const char *endpoint,
						   char *path,
						   char **headers,
						   int headers_count)
{
	struct curl_slist *curl_headers = NULL;
	char date[HTTP_DATE_FMT_SIZE];
	char *header;
	int err;
	int i;

	if (http_gmtime(date, sizeof(date)) != 0)
		return NULL;

	err = add_header(&curl_headers, strfmt("Date: %s", date));
	if (err)
		return NULL;

	if (request->config->user_agent) {
		err = add_header(&curl_headers,
				 strfmt("User-Agent: %s",
					request->config->user_agent));
		if (err)
			return NULL;
	}

	if (request->flags & OCI_REQUEST_IMDS) {
		err = add_header_const(&curl_headers,
				       "Authorization: Bearer Oracle");
	} else {
		header = oci_auth_header(request->config, date,
					 method, endpoint, path,
					 request->content_length,
					 request->content_type,
					 request->content_sha256);
		err = add_header(&curl_headers, header);
	}

	if (err)
		return NULL;

	if (request->content_type) {
		err = add_header(&curl_headers, strfmt("Content-Type: %s",
						       request->content_type));
		if (err)
			return NULL;
	}

	if (request->content_sha256) {
		err = add_header(&curl_headers, strfmt("X-Content-Sha256: %s",
						       request->content_sha256));
		if (err)
			return NULL;
	}

	if (headers) {
		for (i = 0; i < headers_count; i++) {
			err = add_header_const(&curl_headers, headers[i]);
			if (err)
				return NULL;
		}
	}

	return curl_headers;
}

/*
 * Return a non-zero value if the request had an error. Return -1 if the
 * request has failed and we got no HTTP status. Return 0 if the HTTP*
 * status code was 2xx, otherwise return the HTTP status.
 */
static int oci_request_error(struct oci_request *request,
			      struct oci_error *error)
{
	const char *error_code, *error_msg;
	json_t *obj_error;
	json_error_t json_error;
	size_t error_buflen;
	int http_status;
	CURLcode status;
	char *error_buf;

	status = curl_easy_getinfo(request->curl, CURLINFO_RESPONSE_CODE,
				   &http_status);

	if (status != CURLE_OK) {
		oci_error(error, "Failed to get HTTP status");
		return -1;
	}

	/*
	 * HTTP status code 2xx report success. We consider that any
	 * other code is an error.
	 */
	if (http_status >= 200 && http_status < 300) {
		/*
		 * Although there is no error, report the http_status in
		 * the error structure.
		 */
		oci_error_request_set(error, status, http_status);
		return 0;
	}

	error_buf = dstore_buffer(&request->body_response);
	error_buflen = request->recv_len;

	if (!error_buf || error_buflen <= 0) {
		oci_error_request_set_verbose(error, status, http_status,
					      "UnspecifiedError",
					      "The response has no body");
		return http_status;
	}

	/*
	 * On error, the OCI API usually returns a JSON Error object
	 * in the request body.
	 */

	obj_error = json_loadb(error_buf, error_buflen,
				  JSON_DECODE_ANY, &json_error);
	if (!obj_error)
		goto unknown_error;

	error_code = json_string_value(json_object_get(obj_error, "code"));
	error_msg = json_string_value(json_object_get(obj_error, "message"));

	if (!error_code) {
		if (!error_msg) {
			json_decref(obj_error);
			goto unknown_error;
		}
		error_code = "UnspecifiedErrorCode";
	}

	oci_error_request_set_debug(error, status, http_status, error_code,
				    error_msg, error_buf, error_buflen);

	json_decref(obj_error);

	return http_status;

unknown_error:
	oci_error_request_set_debug(error, status, http_status, "UnknownError",
				    "Fail to decode the response body as an Error resource",
				    error_buf, error_buflen);

	return http_status;
}

static int oci_request_perform(struct oci_request *request,
			       enum http_method method,
			       const char *endpoint, char *path,
			       char **headers, int headers_count,
			       struct oci_error *error)
{
	struct curl_slist *curl_headers = NULL;
	char *cert_bundle;
	char *url = NULL;
	CURLcode status;
	CURL *curl;
	bool body;
	int retry;
	int err;
	int rv = -1;

	if (request->flags & OCI_REQUEST_IMDS) {
		url = strfmt(OCI_REQUEST_IMDS_URL, path);
	} else {
		url = strfmt("https://%s.%s%s", endpoint,
			     request->config->domain, path);
	}

	if (!url) {
		oci_error(error, "Failed to build request URL");
		goto error;
	}

	/*
	 * Note that the Content-Length header is automatically added
	 * by CURL.
	 */
	curl_headers = oci_request_init_headers(request, method, endpoint, path,
						headers, headers_count);
	if (!curl_headers) {
		oci_error(error, "Failed to init headers");
		goto error;
	}

	curl = request->curl;

	/*
	 * The response to the request doesn't doesn't necessarily have
	 * a body, but it will in case of an error. So we always set the
	 * write function to collect any response.
	 */
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oci_request_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, request);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* extra certificates to verify the peer with */
	cert_bundle = getenv("REQUESTS_CA_BUNDLE");
	if (cert_bundle)
		curl_easy_setopt(curl, CURLOPT_CAINFO, cert_bundle);

	switch (method) {

	case HTTP_METHOD_DELETE:
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
		body = false;
		break;

	case HTTP_METHOD_GET:
		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
		body = false;
		break;

	case HTTP_METHOD_HEAD:
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
		body = false;
		break;

	case HTTP_METHOD_POST:
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
				 request->content_length);
		body = true;
		break;

	case HTTP_METHOD_PUT:
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		body = true;
		break;

	default:
		oci_error(error, "Unknown HTTP method");
		goto error;
	}

	if (body) {
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
				 (curl_off_t)request->content_length);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION,
				 oci_request_read_cb);
		curl_easy_setopt(curl, CURLOPT_READDATA, request);
	}

	if (request->response_headers && request->response_hcount > 0) {
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,
				 oci_request_header_cb);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, request);
	}

	if (request->config->debug)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	/*
	 * Perform the request. If the request fails with an authorization
	 * error then retry the request once after having refreshed the
	 * configuration. This is to handle the case where a token/cert
	 * expires while the request is being submitted.
	 */
	for (retry = 0; retry < 2; retry++) {

		status = curl_easy_perform(curl);
		if (status != CURLE_OK) {
			oci_error(error, "Failed to perform request");
			goto error;
		};

		err = oci_request_error(request, error);
		if (!err)
			break;

		if (err != HTTP_STATUS_UNAUTHORIZED)
			goto error;

		/*
		 * Force a refresh of the configuration to hopefully
		 * have updated authorization to connect. If nothing
		 * was refreshed there's no need to retry.
		 */
		if (!oci_config_refresh(request->config))
			goto error;
	}

	rv = 0;

error:
	curl_slist_free_all(curl_headers);
	free(url);

	return rv;
}

static int oci_request_execute(struct oci_request *request,
			       struct oci_config *config,
			       enum http_method method,
			       const char *endpoint, char *path,
			       struct oci_body_cfg request_body_cfg,
			       struct oci_body_cfg response_body_cfg,
			       struct oci_error *error)
{
	int err;

	err = oci_request_prepare(request, config,
				  request_body_cfg, response_body_cfg);
	if (err) {
		oci_error(error, "Failed to init request");
		return -1;
	}

	return oci_request_perform(request, method, endpoint, path,
				   request->request_headers,
				   request->request_headers_count,
				   error);
}

/*
 * Send a 'get' request. The body of the response is stored in the
 * provided (*bufp). If no buffer is provided (*bufp == NULL) then
 * a buffer is dynamically allocated and return to the caller. The
 * caller is then responsible for freeing that buffer.
 */
int oci_request_get(struct oci_config *config,
		    const char *endpoint, char *path,
		    char **bufp, size_t *sizep,
		    char **headers, int headers_count,
		    struct oci_error *error)
{
	struct oci_request request = { 0 };
	int err;

	if (!bufp || !sizep)
		return -1;

	oci_request_set_request_headers(&request, headers_count, headers);

	/*
	 * The 'get' request has no body and we use a memory buffer
	 * for the response body.
	 */
	err = oci_request_execute(&request, config,
				  HTTP_METHOD_GET, endpoint, path,
				  OCI_BODY_NONE, OCI_BODY_BUFFER(*bufp, *sizep),
				  error);
	if (err) {
		oci_request_fini(&request);
		return -1;
	}

	/*
	 * If no buffer was provided then return the buffer which was
	 * allocated.
	 */
	if (!*bufp)
		*bufp = dstore_fetch_buffer(&request.body_response);

	/*
	 * Return the number of bytes stored in the buffer.
	 */
	*sizep = request.recv_len;

	oci_request_fini(&request);

	return 0;
}

/*
 * Send a 'get' request. The body of the response is stored in the
 * file associated with the provided file descriptor (fd).
 */
int oci_request_get_to_file(struct oci_config *config,
			    const char *endpoint, char *path, int fd,
			    char **headers, int headers_count,
			    struct oci_error *error)
{
	struct oci_request request = { 0 };
	int err;

	if (fd < 0)
		return -1;

	oci_request_set_request_headers(&request, headers_count, headers);

	/*
	 * The 'get' request has no body and we store the response
	 * body in the file associated with the provided file
	 * descriptor.
	 */
	err = oci_request_execute(&request, config,
				  HTTP_METHOD_GET, endpoint, path,
				  OCI_BODY_NONE, OCI_BODY_FD(fd), error);

	oci_request_fini(&request);

	return err ? -1 : 0;
}

static int oci_request_post_common(struct oci_config *config,
				   const char *endpoint, char *path,
				   char *buf, size_t size,
				   char **headers, int headers_count,
				   char **responsep, size_t *response_sizep,
				   struct oci_error *error)
{
	struct oci_request request = { 0 };
	int err;

	oci_request_set_flags(&request, OCI_REQUEST_SHA256);
	oci_request_set_content_type(&request, "application/json");
	oci_request_set_request_headers(&request, headers_count, headers);

	err = oci_request_execute(&request, config,
				  HTTP_METHOD_POST, endpoint, path,
				  OCI_BODY_BUFFER(buf, size),
				  OCI_BODY_BUFFER_DYNAMIC, error);

	if (responsep)
		*responsep = dstore_fetch_buffer(&request.body_response);
	if (response_sizep)
		*response_sizep = request.recv_len;

	oci_request_fini(&request);

	return err;
}

int oci_request_post(struct oci_config *config,
		     const char *endpoint, char *path,
		     char *buf, size_t size,
		     char **headers, int headers_count,
		     struct oci_error *error)
{
	return oci_request_post_common(config, endpoint, path, buf, size,
				       headers, headers_count,
				       NULL, NULL, error);
}

json_t *oci_request_post_json(struct oci_config *config,
			      const char *endpoint, char *path,
			      char *buf, size_t size,
			      char **headers, int headers_count,
			      struct oci_error *error)
{
	json_error_t json_error;
	size_t response_size;
	json_t *result;
	char *response;
	int err;

	err = oci_request_post_common(config, endpoint, path, buf, size,
				      headers, headers_count,
				      &response, &response_size, error);
	if (err)
		return NULL;

	OCI_DEBUG(config, "REQUEST RECV:\n%.*s\n\n",
		  (int)response_size, response);

	result = json_loadb(response, response_size, JSON_DECODE_ANY,
			    &json_error);

	free(response);

	return result;
}

int oci_request_put(struct oci_config *config,
		    const char *endpoint, char *path,
		    char *buf, size_t size,
		    char **headers, int headers_count,
		    struct oci_error *error)
{
	struct oci_request request = { 0 };
	int err;

	oci_request_set_request_headers(&request, headers_count, headers);

	err = oci_request_execute(&request, config,
				  HTTP_METHOD_PUT, endpoint, path,
				  OCI_BODY_BUFFER(buf, size),
				  OCI_BODY_BUFFER_DYNAMIC, error);

	oci_request_fini(&request);

	return err ? -1 : 0;
}

/*
 * Send a 'put' request. The body of the request is retrieved from
 * the provided file descriptor.
 */
int oci_request_put_from_file(struct oci_config *config,
			      const char *endpoint, char *path, int fd,
			      char **headers, int headers_count,
			      struct oci_error *error)
{
	struct oci_request request = { 0 };
	off_t offset;
	int err;

	/*
	 * Put the content of the entire file. So we make sure we are
	 * at the beginning of the file.
	 */

	offset = lseek(fd, 0, SEEK_SET);
	if (offset == -1)
		return -1;

	oci_request_set_request_headers(&request, headers_count, headers);

	/*
	 * The body of the 'put' request is made by reading the file
	 * with the specified fd. And we use a dynamic memory buffer
	 * to store the response body.
	 */
	err = oci_request_execute(&request, config,
				  HTTP_METHOD_PUT, endpoint, path,
				  OCI_BODY_FD(fd), OCI_BODY_BUFFER_DYNAMIC,
				  error);

	oci_request_fini(&request);

	return err ? -1 : 0;
}

json_t *oci_request_get_json(struct oci_config *config,
			     const char *endpoint, char *path,
			     struct oci_error *error)
{
	json_error_t json_error;
	char *buf = NULL;
	size_t size = 0;
	json_t *result;
	int err;

	err = oci_request_get(config, endpoint, path, &buf, &size, NULL, 0,
			      error);
	if (err)
		return NULL;

	OCI_DEBUG(config, "REQUEST RECV:\n%.*s\n\n", (int)size, buf);

	result = json_loadb(buf, size, JSON_DECODE_ANY, &json_error);

	free(buf);

	return result;
}

int oci_request_delete(struct oci_config *config,
		       const char *endpoint, char *path,
		       struct oci_error *error)
{
	struct oci_request request = { 0 };
	int err;

	/*
	 * The 'delete' request has no body and we use a dynamic memory
	 * buffer to store the response body.
	 */
	err = oci_request_execute(&request, config,
				  HTTP_METHOD_DELETE, endpoint, path,
				  OCI_BODY_NONE, OCI_BODY_BUFFER_DYNAMIC,
				  error);

	oci_request_fini(&request);

	return err ? -1 : 0;
}

int oci_request_head(struct oci_config *config,
		     const char *endpoint, char *path,
		     int response_hcount, struct oci_header *response_headers,
		     struct oci_error *error)
{
	struct oci_request request = { 0 };
	int err;

	oci_request_set_response_headers(&request,
					 response_hcount, response_headers);

	/*
	 * The 'head' request has no body and we use a dynamic memory
	 * buffer to store the response body.
	 */
	err = oci_request_execute(&request, config,
				  HTTP_METHOD_HEAD, endpoint, path,
				  OCI_BODY_NONE, OCI_BODY_BUFFER_DYNAMIC,
				  error);

	oci_request_fini(&request);

	return err ? -1 : 0;
}

/*
 * The instance metadata service periodically experiences short periods
 * of downtime for maintenance. Therefore, when you try to access IMDS
 * endpoints, they might be unavailable. As a best practice, implement
 * retry logic when accessing IMDS endpoints. The following strategy is
 * recommended: retry up to three times with a 30 second timeout if you
 * receive a 404, 429, or 5xx response.
 */

int oci_request_imds_get(struct oci_config *config, char *path,
			 char **bufp, size_t *sizep,
			 struct oci_error *error)

{
	struct oci_request request = { 0 };
	int err;

	/*
	 * IMDS requests can be done without an OCI config, but we need
	 * one for processing (to check the debug level) so create an
	 * empty one if none was specified.
	 */
	if (!config)
		config = &((struct oci_config){ 0 });

	oci_request_set_flags(&request, OCI_REQUEST_IMDS);

	/*
	 * The request has no body and we use a dynamic memory buffer
	 * to store the response body.
	 */
	err = oci_request_execute(&request, config,
				  HTTP_METHOD_GET, NULL, path,
				  OCI_BODY_NONE, OCI_BODY_BUFFER_DYNAMIC,
				  error);
	if (err) {
		oci_request_fini(&request);
		return -1;
	}

	/*
	 * If no buffer was provided then return the buffer which was
	 * allocated.
	 */
	if (!*bufp)
		*bufp = dstore_fetch_buffer(&request.body_response);

	/*
	 * Return the number of bytes stored in the buffer.
	 */
	*sizep = request.recv_len;

	oci_request_fini(&request);

	return 0;
}
