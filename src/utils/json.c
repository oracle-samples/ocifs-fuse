/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <string.h>
#include <time.h>

#include <jansson.h>

#include "utils.h"

static int json_integer_to_longlong(json_t *value, long long *ptr)
{
	if (!json_is_integer(value))
		return -1;

	*((long long *)ptr) = json_integer_value(value);

	return 0;
}

static int json_string_to_str(json_t *value, char **ptr)
{
	char *str;

	str = (char *)json_string_value(value);
	if (!str)
		return -1;

	str = strdup(json_string_value(value));
	if (!str)
		return -1;

	*ptr = str;

	return 0;
}

/*
 * Convert a JSON string representing a date and time in the Internet
 * format (RFC 3339) to a struct tm.
 */
static int json_string_to_time(json_t *value, struct tm *tm)
{
	char *date;

	date = (char *)json_string_value(value);
	if (!date)
		return -1;

	return strtotm(date, tm);
}

/*
 * Fill a C struct with values from a JSON object.
 */
int json_object_to_struct(json_t *object, void *c_struct,
			  struct json_mapping *mapping)
{
	struct json_mapping *m;
	struct json_t *value;
	void *c_member;
	int err;

	if (!json_is_object(object))
		return -1;

	for (m = mapping; m->json_member; m++)
	{
		value = json_object_get(object, m->json_member);
		if (!value)
			continue;

		c_member = (void *)(((unsigned long)c_struct) + m->offset);

		switch (m->type) {

		case TYPE_NUMBER:
			err = json_integer_to_longlong(value,
						       (long long *)c_member);
			break;

		case TYPE_STRING:
			err = json_string_to_str(value, (char **)c_member);
			break;

		case TYPE_DATE:
			err = json_string_to_time(value, (struct tm *)c_member);
			break;

		default:
			/* ignore if the mapping type wasn't processed above */
			err = 0;
			break;
		}

		if (err)
			return -1;
	}

	return 0;
}

/*
 * Create a JSON object from a C struct
 */
json_t *json_struct_to_object(void *c_struct, struct json_mapping *mapping)
{
	struct json_mapping *m;
	struct json_t *object;
	struct json_t *value;
	void *c_member;
	struct tm tm;
	char date[32];
	char *str;
	int len;
	int err;

	if (!c_struct || !mapping)
		return NULL;

	object = json_object();
	if (!object)
		return NULL;

	for (m = mapping; m->json_member; m++)
	{
		c_member = (void *)(((unsigned long)c_struct) + m->offset);
		value = 0;

		switch (m->type) {

		case TYPE_NUMBER:
			value = json_integer(*((long long *)c_member));
			break;

		case TYPE_STRING:
			str = *(char **)c_member;
			if (!str)
				continue;
			value = json_string(str);
			break;

		case TYPE_DATE:
			tm = *(struct tm *)c_member;
			/*
			 * Convert a struct tm to a date and time string
			 * for the Internet (RFC 3339). Use strftime()
			 * to do the conversion. However strftime() does
			 * not provide the RFC 3339 timezone format
			 * (+/-hh:mm). So we use the %z timezone field
			 * (+/-hhmm) and then adjust it to (+/-hh:mm).
			 */
			len = strftime(date, sizeof(date), "%FT%T%z", &tm);
			if (len == 0) {
				json_decref(object);
				return NULL;
			}
			date[len + 1] = '\0';
			date[len] = date[len - 1];
			date[len - 1] = date[len -2];
			date[len - 2] = ':';
			value = json_string(date);
			break;
		}

		if (!value) {
			json_decref(object);
			return NULL;
		}

		err = json_object_set_new(object, m->json_member, value);
		if (err) {
			json_decref(value);
			json_decref(object);
			return NULL;
		}
	}

	return object;
}

int json_array_to_str_array(json_t *object, char ***c_array_p)
{
	int c_array_len, json_array_len, i;
	char **c_array, *str;
	json_t *obj;

	if (!json_is_array(object))
		return -1;

	json_array_len = json_array_size(object);
	if (!json_array_len) {
		if (c_array_p)
			*c_array_p = NULL;
		return 0;
	}

	if (c_array_p) {
		c_array = malloc((json_array_len + 1) * sizeof(char *));
		if (!c_array)
			return -1;
	} else {
		c_array = NULL;
	}

	c_array_len = 0;
	json_array_foreach(object, i, obj) {
		str = (char *)json_string_value(obj);
		if (!str)
			continue;

		if (!c_array_p) {
			c_array_len++;
			continue;
		}

		str = strdup(str);
		if (!str) {
			free(c_array);
			return -1;
		}

		c_array[c_array_len++] = str;
	}

	if (!c_array_len) {
		free(c_array);
		return 0;
	}

	if (c_array_p) {
		c_array[c_array_len] = NULL;
		*c_array_p = c_array;
	}

	return c_array_len;
}

/*
 * objects_p can be NULL in which case we just count the number
 * of objects.
 */
int json_array_to_struct_array(json_t *json_obj_list, void **objects_p,
			       size_t c_obj_size, struct json_mapping *mapping)
{
	int i, err, json_obj_count, c_obj_count;
	void *c_obj_list, *c_obj;
	json_t *json_obj;

	if (!json_is_array(json_obj_list))
		return -1;

	json_obj_count = json_array_size(json_obj_list);
	if (!json_obj_count) {
		/*
		 * Request was successful but result is empty.
		 */
		if (objects_p)
			*objects_p = NULL;
		return 0;
	}

	/*
	 * Allocated space for the maximum number of objects we can
	 * have. The final number of objects can smaller if some
	 * JSON objects don't convert to C struct.
	 */
	if (objects_p) {
		c_obj_list = calloc(json_obj_count, c_obj_size);
		if (!c_obj_list)
			return -1;
		c_obj = c_obj_list;
	} else {
		c_obj_list = NULL;
		c_obj = NULL;
	}

	c_obj_count = 0;

	json_array_foreach(json_obj_list, i, json_obj) {

		c_obj_count++;
		if (!objects_p)
			continue;

		err = json_object_to_struct(json_obj, c_obj, mapping);
		if (err)
			continue;

		c_obj = (void *)((unsigned long)c_obj + c_obj_size);
	}

	if (!c_obj_count) {
		free(c_obj_list);
		if (objects_p)
			*objects_p = NULL;
		return 0;
	}

	if (objects_p)
		*objects_p = c_obj_list;

	return c_obj_count;
}

static json_t *jwt_decode_segment_json(char *str, char **nextp)
{
	json_error_t error;
	json_t *object;
	char *next;
	int len;

	next = strchr(str, '.');
	if (!next || *(next + 1) == '\0')
		return NULL;

	len = base64url_decodeb(str, next - str, (unsigned char **)&str);
	if (len < 0)
		return NULL;

	object = json_loadb(str, len, 0, &error);
	free(str);
	if (!object)
		return NULL;

	*nextp = next + 1;

	return object;
}

/*
 * Return a pointer to the string value of the specified claim in a JWT
 * token. Return NULL in case of an error, or if the claim doesn't exist
 * or if the claim value is not a string.
 */
char *jwt_claim_str(struct jwt *token, char *claim)
{
	json_t *obj;
	char *ptr;
	int err;

	obj = json_object_get(token->payload, claim);
	if (!obj)
		return NULL;

	err = json_string_to_str(obj, &ptr);
	if (err)
		return NULL;

	return ptr;
}

struct jwt *jwt_decode(char *token_str)
{
	struct jwt *token;
	char *str, *next;
	json_t *obj;

	if (!token_str || *token_str == '\0')
		return NULL;

	token = malloc(sizeof(*token));
	if (!token)
		return NULL;

	bzero(token, sizeof(*token));

	/*
	 * Look for a JSON Web Signature (JWS) (RFC 7515). A JWS has
	 * three segments separated by two period ('.') characters:
	 * <header>.<payload>.<signature>
	 *
	 * We don't support other structures such as JSON Web
	 * Encryption (JWE).
	 */

	token->header = jwt_decode_segment_json(token_str, &next);
	if (!token->header) {
		jwt_destroy(token);
		return NULL;
	}

	token->payload = jwt_decode_segment_json(next, &next);
	if (!token->payload) {
		jwt_destroy(token);
		return NULL;
	}

	/* get the expiration time from the payload object */
	obj = json_object_get(token->payload, "exp");
	if (obj)
		token->expiration = json_integer_value(obj);
	else
		token->expiration = 0;

	/*
	 * A JWS has exactly two period characters ('.'), the last
	 * segment is the signature.
	 */

	str = strchr(next, '.');
	if (str) {
		jwt_destroy(token);
		return NULL;
	}

	token->signature = strdup(next);
	if (!token->signature) {
		jwt_destroy(token);
		return NULL;
	}

	token->raw = strdup(token_str);
	if (!token->raw) {
		jwt_destroy(token);
		return NULL;
	}

	return token;
}

void jwt_destroy(struct jwt *token)
{
	if (!token)
		return;

	json_decref(token->header);
	json_decref(token->payload);
	free(token->signature);
	free(token->raw);
	free(token);
}

bool jwt_has_expired(struct jwt *token, int jitter)
{
	if (token->expiration == 0)
		return false;

	return time(NULL) + jitter > token->expiration;
}
