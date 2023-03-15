/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

/*
 * Test JSON functions provided by libutils.
 */

#include <ctype.h>
#include <errno.h>
#include <malloc.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include "utils.h"

struct object {
	long long	number;
	char		*string;
	struct tm	date;
};

struct json_mapping object_mapping[] = {
	{ offsetof(struct object, number), "number", TYPE_NUMBER },
	{ offsetof(struct object, string), "string", TYPE_STRING },
	{ offsetof(struct object, date), "date", TYPE_DATE },
	{ 0, NULL, 0 }
};

/*
 * Date and time (Wed, 24-11-2021 11:18:31) for testing, represented
 * in different formats.
 */
#define DATE_TM { .tm_mday = 24, .tm_mon = 10, .tm_year = 121, 	\
		  .tm_hour = 11, .tm_min = 18, .tm_sec = 31,	\
		  .tm_wday = 3, .tm_yday = 327 }

#define DATE_INTERNET		"2021-11-24T11:18:31"
#define DATE_INTERNET_GMT	DATE_INTERNET "Z"
#define DATE_INTERNET_TZ	DATE_INTERNET "+00:00"
#define DATE_INTERNET_MSEC	DATE_INTERNET ".123"
#define DATE_INTERNET_MSEC_GMT	DATE_INTERNET_MSEC "Z"
#define DATE_INTERNET_MSEC_TZ	DATE_INTERNET_MSEC "+00:00"


json_t *json_create_object(int number, char *string, char *date)
{
	json_t *json_obj;
	int rv;

	json_obj = json_object();
	assert_non_null(json_obj);

	rv = json_object_set_new(json_obj, "number", json_integer(number));
	assert_int_equal(rv, 0);

	rv = json_object_set_new(json_obj, "string", json_string(string));
	assert_int_equal(rv, 0);

	rv = json_object_set_new(json_obj, "date", json_string(date));
	assert_int_equal(rv, 0);

	return json_obj;
}

static void assert_tm_equal(struct tm *tm1, struct tm *tm2)
{
	assert_int_equal(tm1->tm_sec, tm2->tm_sec);
	assert_int_equal(tm1->tm_min, tm2->tm_min);
	assert_int_equal(tm1->tm_hour, tm2->tm_hour);
	assert_int_equal(tm1->tm_mday, tm2->tm_mday);
	assert_int_equal(tm1->tm_mon, tm2->tm_mon);
	assert_int_equal(tm1->tm_year, tm2->tm_year);
	assert_int_equal(tm1->tm_wday, tm2->tm_wday);
	assert_int_equal(tm1->tm_yday, tm2->tm_yday);
}

static void object_to_struct(int number, char *string, char *date)
{
	struct tm date_tm = DATE_TM;
	struct object c_obj;
	json_t *json_obj;
	int rv;

	/*
	 * Create a JSON object and convert that object to a struct.
	 */
	json_obj = json_create_object(number, string, date);
	rv = json_object_to_struct(json_obj, &c_obj, object_mapping);
	assert_int_equal(rv, 0);

	assert_int_equal(c_obj.number, number);
	assert_string_equal(c_obj.string, string);
	assert_tm_equal(&c_obj.date, &date_tm);

	free(c_obj.string);
	json_decref(json_obj);
}

static void test_json_object_to_struct(void **state)
{
	object_to_struct(1234, "abc", DATE_INTERNET_GMT);
	object_to_struct(12345678, "abcdef", DATE_INTERNET_TZ);
	object_to_struct(0, "", DATE_INTERNET_MSEC_GMT);
	object_to_struct(-1234, "\"", DATE_INTERNET_MSEC_TZ);
}

static void struct_to_object(int number, char *string)
{
	struct object c_obj;
	json_t *json_obj;
	const char *s, *d;
	int n;

	/*
	 * Create a struct and convert that struct to a JSON object.
	 */
	c_obj.number = number;
	c_obj.string = string;
	c_obj.date = (struct tm)DATE_TM;

	json_obj = json_struct_to_object(&c_obj, object_mapping);
	assert_non_null(json_obj);

	n = json_integer_value(json_object_get(json_obj, "number"));
	assert_int_equal(n, number);

	s = json_string_value(json_object_get(json_obj, "string"));
	assert_string_equal(s, string);

	d = json_string_value(json_object_get(json_obj, "date"));
	assert_string_equal(d, DATE_INTERNET_TZ);

	json_decref(json_obj);
}

static void test_json_struct_to_object(void **state)
{
	struct_to_object(1234, "abc");
	struct_to_object(12345678, "abcdef");
	struct_to_object(0, "");
	struct_to_object(-1234, "\"");
}

static void array_to_str_array(char *first, ...)
{
	json_t *json_arr;
	char **array;
	va_list args;
	int size, s;
	char *str;
	int rv, i;

	/*
	 * Create a JSON array of string and convert that array to
	 * a C array of char *.
	 */
	json_arr = json_array();
	assert_non_null(json_arr);

	size = 0;
	str = first;
	va_start(args, first);
	while (str) {
		rv = json_array_append_new(json_arr, json_string(str));
		assert_int_equal(rv, 0);
		size++;
		str = va_arg(args, char *);
	}
	va_end(args);

	s = json_array_to_str_array(json_arr, &array);
	assert_int_equal(s, size);
	if (size == 0)
		assert_null(array);
	else
		assert_non_null(array);

	va_start(args, first);
	str = first;
	for (i = 0; i < size; i++) {
		assert_string_equal(array[i], str);
		free(array[i]);
		str = va_arg(args, char *);
	}
	va_end(args);

	free(array);
	json_decref(json_arr);
}

static void test_json_array_to_str_array(void **state)
{
	array_to_str_array(NULL);

	array_to_str_array("abc", NULL);
	array_to_str_array("abc", "def", NULL);
	array_to_str_array("abc", "def", "ghi", NULL);

	array_to_str_array("", NULL);
	array_to_str_array("", "abc", NULL);
	array_to_str_array("", "abc", "", NULL);
	array_to_str_array("", "abc", "", "def", NULL);
	array_to_str_array("", "abc", "", "def", "", NULL);
}

static void array_to_struct_array(int size)
{
	struct tm date_tm = DATE_TM;
	struct object *objects;
	json_t *json_obj_list;
	json_t *json_obj;
	char *string;
	int number;
	int i, s;

	/*
	 * Create a JSON array of object and convert that array to
	 * a C array of struct object *.
	 */
	json_obj_list = json_array();
	assert_non_null(json_obj_list);

	number = 1234;
	string = strdup("A-abcdef");
	for (i = 0; i < size; i++) {
		json_obj = json_create_object(number, string,
					      DATE_INTERNET_GMT);
		json_array_append_new(json_obj_list, json_obj);
		number++;
		string[0]++;
	}

	s = json_array_to_struct_array(json_obj_list, (void **)&objects,
				       sizeof(struct object),
				       object_mapping);
	json_decref(json_obj_list);
	assert_int_equal(s, size);
	if (size == 0)
		assert_null(objects);
	else
		assert_non_null(objects);

	number -= size;
	string[0] -= size;
	for (i = 0; i < size; i++) {
		assert_int_equal(objects[i].number, number);
		assert_string_equal(objects[i].string, string);
		assert_tm_equal(&objects[i].date, &date_tm);
		free(objects[i].string);
		number++;
		string[0]++;
	}

	free(objects);
	free(string);
}

static void test_json_array_to_struct_array(void **state)
{
	array_to_struct_array(0);
	array_to_struct_array(1);
	array_to_struct_array(2);
	array_to_struct_array(5);
	array_to_struct_array(10);
}

static void test_jwt(void **state)
{
	struct jwt *token;

	/*
	 * This is a JWT token example for testing that the JWT decoding
	 * function works correctly. This a stale token that has expired
	 * a long time ago (it expired after 20 minutes). JWK data are
	 * also stale as they are ephemeral and associated with a now
	 * terminated VM.
	 */
	char *token_str = "eyJraWQiOiJhc3dfcmVnaW9uMV9rNm93IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJvY2lkMS5pbnN0YW5jZS5yZWdpb24xLnNlYS5hbnp3a2xqcnFzNWs3b3ljNW93MmZqa2hlY2ltbXZmNGx1Mmh5YjRibXJ1eXpjMzM1YnQ0NDQyNG1mZWEiLCJvcGMtY2VydHR5cGUiOiJpbnN0YW5jZSIsImlzcyI6ImF1dGhTZXJ2aWNlLm9yYWNsZS5jb20iLCJmcHJpbnQiOiJCQjozNzpFMTowNDpERjo0OTo3Nzo0QzoxMjo4MDpBRjozNDpEMTpDRjpENToyOTo1RDpDMTpFQjoyOCIsInB0eXBlIjoiaW5zdGFuY2UiLCJhdWQiOiJvY2kiLCJvcGMtdGFnIjoiVjMsb2NpZDEudGVuYW5jeS5yZWdpb24xLi5hYWFhYWFhYTRjMzR6bmN5MzRjMzQ1dXk2a3ZzZ21kZ3p3b3U2Ymc0aHV6dGVxaWhsdHpoNjd0ZDJiaGEsQUFBQUFRQUFBQUJcL2YzOVwvQUFBQWp3PT0sQUFBQUFRQUFBQUFBQUFDQiIsInR0eXBlIjoieDUwOSIsIm9wYy1pbnN0YW5jZSI6Im9jaWQxLmluc3RhbmNlLnJlZ2lvbjEuc2VhLmFuendrbGpycXM1azdveWM1b3cyZmpraGVjaW1tdmY0bHUyaHliNGJtcnV5emMzMzVidDQ0NDI0bWZlYSIsImV4cCI6MTY0MzcxMjkzMiwib3BjLWNvbXBhcnRtZW50Ijoib2NpZDEudGVuYW5jeS5yZWdpb24xLi5hYWFhYWFhYTRjMzR6bmN5MzRjMzQ1dXk2a3ZzZ21kZ3p3b3U2Ymc0aHV6dGVxaWhsdHpoNjd0ZDJiaGEiLCJpYXQiOjE2NDM3MTE3MzIsImp0aSI6IjI4NjYzNGUwLWE5NTMtNDhlNS04OTFkLWY4MGM2ZWVkOGQ3ZCIsInRlbmFudCI6Im9jaWQxLnRlbmFuY3kucmVnaW9uMS4uYWFhYWFhYWE0YzM0em5jeTM0YzM0NXV5Nmt2c2dtZGd6d291NmJnNGh1enRlcWlobHR6aDY3dGQyYmhhIiwiandrIjoie1wia2lkXCI6XCJCQjozNzpFMTowNDpERjo0OTo3Nzo0QzoxMjo4MDpBRjozNDpEMTpDRjpENToyOTo1RDpDMTpFQjoyOFwiLFwiblwiOlwiM1VFWTB0U1c2VjNtVmM3bWxlYnpkTE0xcklKWVBwbzNMVXIzREVVd0xEY3FrdjA1QkpONWNPMEVzbll3NVMxb1RUNGI0dEo3SmsxSTlVYW1zdXpCVWY2Mi1TX0NtOVdKUFR3emdiQk5BZHpYRG1meHdjM0Jjd1lEMHUxSVZaRDBEdktrN3d5YThBbFgzM040NDhlc0M4VFMya1VHTWJ1dWNzb25SMmxrU2RJcWZqdHVBM3pPYnR5TVY2Si1FZjNHc3ZvQ0Jhd2MwMmpTRUU4MU9ucXpFdlJXX3ROZUxkZ2xwNW1XU2NfN2QzejRmTUE0eXRqY1VDbi1tdGJzUXduX0RHdHVJbVhkNTBLT0pGbjNkNTlZS2FCVFpSam8ybGJ1bl9PRW4teHI3QnJEaXowdXUwTlhxbExfa2l6VzYzV012UGZsRFBWMV9GS3lDVjNGRWNWTEZ3XCIsXCJlXCI6XCJBUUFCXCIsXCJrdHlcIjpcIlJTQVwiLFwiYWxnXCI6XCJSUzI1NlwiLFwidXNlXCI6XCJzaWdcIn0iLCJvcGMtdGVuYW50Ijoib2NpZDEudGVuYW5jeS5yZWdpb24xLi5hYWFhYWFhYTRjMzR6bmN5MzRjMzQ1dXk2a3ZzZ21kZ3p3b3U2Ymc0aHV6dGVxaWhsdHpoNjd0ZDJiaGEifQ.C6hgC_0MIi60CBjhIxOxWpc5aJqwpTsjsAD4jcHLx7TEnArGj0Z0ZbSgN8cjS65kjZLo2Xxuj9e8lf90fmJfJ-WM43lmwNYusPfS29Gq9DMNiCRNvtPaAXE2kpikDuYPAiNq7eMCuuuvIKXRiriTQwZGtMDraSi43-Iw4jCzi0oGzvECzdxmRWzQht_lbHa2DZ08nDUbaQS3roCp_b_023uTbD-9PcJza7hBjSnYLWXgXfCKIcBm7z6X9iwC-RLJok_d2cM8MnbsC2KTEOAs8zJa1wz-2cZwk8x32L9Hm543vSmQLGIP1bFtQNapabMlVWld36Nf_HGPUev9G0Zdqg";
	char *header = "{ \"kid\" : \"asw_region1_k6ow\", \"alg\" : \"RS256\" }";
	char *payload =  "{"
		" \"sub\" : \"ocid1.instance.region1.sea.anzwkljrqs5k7oyc5ow2fjkhecimmvf4lu2hyb4bmruyzc335bt44424mfea\","
		" \"opc-certtype\" : \"instance\","
		" \"iss\" : \"authService.oracle.com\","
		" \"fprint\" : \"BB:37:E1:04:DF:49:77:4C:12:80:AF:34:D1:CF:D5:29:5D:C1:EB:28\","
		" \"ptype\" : \"instance\","
		" \"aud\" : \"oci\", "
		" \"opc-tag\" : \"V3,ocid1.tenancy.region1..aaaaaaaa4c34zncy34c345uy6kvsgmdgzwou6bg4huzteqihltzh67td2bha,AAAAAQAAAAB\\/f39\\/AAAAjw==,AAAAAQAAAAAAAACB\","
		" \"ttype\":\"x509\", "
		" \"opc-instance\" : \"ocid1.instance.region1.sea.anzwkljrqs5k7oyc5ow2fjkhecimmvf4lu2hyb4bmruyzc335bt44424mfea\","
		" \"exp\" : 1643712932,"
		" \"opc-compartment\" : \"ocid1.tenancy.region1..aaaaaaaa4c34zncy34c345uy6kvsgmdgzwou6bg4huzteqihltzh67td2bha\","
		" \"iat\" : 1643711732,"
		" \"jti\" : \"286634e0-a953-48e5-891d-f80c6eed8d7d\","
		" \"tenant\" : \"ocid1.tenancy.region1..aaaaaaaa4c34zncy34c345uy6kvsgmdgzwou6bg4huzteqihltzh67td2bha\","
		" \"jwk\" : \"{\\\"kid\\\":\\\"BB:37:E1:04:DF:49:77:4C:12:80:AF:34:D1:CF:D5:29:5D:C1:EB:28\\\",\\\"n\\\":\\\"3UEY0tSW6V3mVc7mlebzdLM1rIJYPpo3LUr3DEUwLDcqkv05BJN5cO0EsnYw5S1oTT4b4tJ7Jk1I9UamsuzBUf62-S_Cm9WJPTwzgbBNAdzXDmfxwc3BcwYD0u1IVZD0DvKk7wya8AlX33N448esC8TS2kUGMbuucsonR2lkSdIqfjtuA3zObtyMV6J-Ef3GsvoCBawc02jSEE81OnqzEvRW_tNeLdglp5mWSc_7d3z4fMA4ytjcUCn-mtbsQwn_DGtuImXd50KOJFn3d59YKaBTZRjo2lbun_OEn-xr7BrDiz0uu0NXqlL_kizW63WMvPflDPV1_FKyCV3FEcVLFw\\\",\\\"e\\\":\\\"AQAB\\\",\\\"kty\\\":\\\"RSA\\\",\\\"alg\\\":\\\"RS256\\\",\\\"use\\\":\\\"sig\\\"}\","
		" \"opc-tenant\" : \"ocid1.tenancy.region1..aaaaaaaa4c34zncy34c345uy6kvsgmdgzwou6bg4huzteqihltzh67td2bha\""
		"}";
	char *signature = "C6hgC_0MIi60CBjhIxOxWpc5aJqwpTsjsAD4jcHLx7TEnArGj0Z0ZbSgN8cjS65kjZLo2Xxuj9e8lf90fmJfJ-WM43lmwNYusPfS29Gq9DMNiCRNvtPaAXE2kpikDuYPAiNq7eMCuuuvIKXRiriTQwZGtMDraSi43-Iw4jCzi0oGzvECzdxmRWzQht_lbHa2DZ08nDUbaQS3roCp_b_023uTbD-9PcJza7hBjSnYLWXgXfCKIcBm7z6X9iwC-RLJok_d2cM8MnbsC2KTEOAs8zJa1wz-2cZwk8x32L9Hm543vSmQLGIP1bFtQNapabMlVWld36Nf_HGPUev9G0Zdqg";
	char *sub = "ocid1.instance.region1.sea.anzwkljrqs5k7oyc5ow2fjkhecimmvf4lu2hyb4bmruyzc335bt44424mfea";
	char *tenant = "ocid1.tenancy.region1..aaaaaaaa4c34zncy34c345uy6kvsgmdgzwou6bg4huzteqihltzh67td2bha";

	json_t *obj;
	char *str;
	int rv;

	token = jwt_decode(token_str);
	assert_non_null(token);
	assert_string_equal(token->raw, token_str);
	assert_string_equal(token->signature, signature);

	obj = json_loads(header, 0, NULL);
	assert_non_null(obj);
	rv = json_equal(token->header, obj);
	assert_int_equal(rv, 1);
	json_decref(obj);

	obj = json_loads(payload, 0, NULL);
	assert_non_null(obj);
	rv = json_equal(token->payload, obj);
	assert_int_equal(rv, 1);
	json_decref(obj);

	assert_int_equal(token->expiration, 1643712932);

	str = jwt_claim_str(token, "sub");
	assert_non_null(str);
	assert_string_equal(str, sub);
	free(str);

	str = jwt_claim_str(token, "tenant");
	assert_non_null(str);
	assert_string_equal(str, tenant);
	free(str);

	str = jwt_claim_str(token, "exp");
	assert_null(str);

	jwt_destroy(token);
}

static const struct CMUnitTest tests[] =
{
	cmocka_unit_test(test_json_struct_to_object),
	cmocka_unit_test(test_json_object_to_struct),
	cmocka_unit_test(test_json_array_to_str_array),
	cmocka_unit_test(test_json_array_to_struct_array),
	cmocka_unit_test(test_jwt),
};

int main(void)
{
	return cmocka_run_group_tests(tests, NULL, NULL);
}
