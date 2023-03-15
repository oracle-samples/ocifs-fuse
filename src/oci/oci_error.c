/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <string.h>

#include "oci.h"

static char *error_copy_code = "Failed to copy error code";
static char *error_copy_msg = "Failed to copy error message";
static char *error_copy_buffer = "Failed to copy error buffer";

void oci_error(struct oci_error *error, const char *error_str)
{
	if (error)
		error->description = error_str;
}

void oci_error_print(struct oci_error *error)
{
	if (!error || !error->description)
		return;

	printf("Error: %s\n", error->description);
	if (error->request_status || error->http_status) {
		printf("  Request Status: %d\n", error->request_status);
		printf("  HTTP Status: %d\n", error->http_status);
	}

	if (error->level <= 0)
		return;

	printf("  OCI Error Code: %s\n", error->code);
	printf("  OCI Error Mesg: %s\n", error->message);

	if (error->level <= 1)
		return;

	printf("  OCI Error Buffer: %s\n", error->buffer);
}

void oci_error_request_set_debug(struct oci_error *error,
				 int request_status, int http_status,
				 const char *error_code, const char *error_msg,
				 char *error_buf, int error_buflen)
{
	if (!error_buf || error_buflen < 0)
		error_buflen = 0;

	if (!error)
		return;

	/* basic information */

	oci_error(error, "HTTP request failed");
	error->request_status = request_status;
	error->http_status = http_status;

	if (error->level <= 0)
		return;

	/* verbose information */

	if (error_code) {
		error->code = strdup(error_code);
		if (!error->code)
			error->code = error_copy_code;
	} else {
		error->code = NULL;
	}

	if (error_msg) {
		error->message = strdup(error_msg);
		if (!error->message)
			error->message = error_copy_msg;
	} else {
		error->message = NULL;
	}

	if (error->level <= 1)
		return;

	/* debug information */

	if (error_buf) {
		error->buffer = strndup(error_buf, error_buflen);
		if (!error->buffer)
			error->buffer = error_copy_buffer;
	} else {
		error->buffer = NULL;
	}
}

void oci_error_request_set_verbose(struct oci_error *error,
				   int request_status, int http_status,
				   const char *error_code,
				   const char *error_msg)
{
	return oci_error_request_set_debug(error, request_status, http_status,
					   error_code, error_msg, NULL, 0);
}

void oci_error_request_set(struct oci_error *error,
				  int request_status, int http_status)
{
	return oci_error_request_set_verbose(error, request_status, http_status,
					     NULL, NULL);
}

void oci_error_fini(struct oci_error *error)
{
	if (!error || error->level <= 0)
		return;

	if (error->code != error_copy_code)
		free(error->code);
	if (error->message != error_copy_msg)
		free(error->message);
	if (error->buffer != error_copy_buffer)
		free(error->buffer);
}
