/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <stdbool.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "oci.h"

/*
 * OCI Request Signatures:
 * https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
 */

#define OCI_AUTH_VERSION	"Signature version=\"1\""
#define OCI_AUTH_ALGO		"algorithm=\"rsa-sha256\""
#define OCI_AUTH_KEYID_FMT	"keyId=\"%s/%s/%s\""
#define OCI_AUTH_KEYID_ST_FMT	"keyId=\"ST$%s\""
#define OCI_AUTH_HEADERS_FMT	"headers=\"%s\""
#define OCI_AUTH_SIGNATURE_FMT	"signature=\"%s\""

#define PARAM_KEYID(config)		\
	(config)->tenancy, (config)->user, (config)->fingerprint

#define OCI_AUTH_HEADER		"Authorization: "	\
				OCI_AUTH_VERSION ","	\
				OCI_AUTH_ALGO ","	\
				OCI_AUTH_KEYID_FMT ","	\
				OCI_AUTH_HEADERS_FMT "," \
				OCI_AUTH_SIGNATURE_FMT

#define OCI_AUTH_ST_HEADER	"Authorization: "	\
				OCI_AUTH_VERSION ","	\
				OCI_AUTH_ALGO ","	\
				OCI_AUTH_KEYID_ST_FMT ","	\
				OCI_AUTH_HEADERS_FMT "," \
				OCI_AUTH_SIGNATURE_FMT

#define OCI_AUTH_HEADERS_BASE	"date (request-target) host"
#define OCI_AUTH_HEADERS_PUT	\
	OCI_AUTH_HEADERS_BASE	" content-length"
#define OCI_AUTH_HEADERS_POST	\
	OCI_AUTH_HEADERS_PUT	" content-type x-content-sha256"

#define OCI_AUTH_STR_DATE_FMT	"date: %s"
#define OCI_AUTH_STR_TARGET_FMT	"(request-target): %s %s"
#define OCI_AUTH_STR_HOST_FMT	"host: %s.%s" 	/* <endpoint>.<domain> */
#define OCI_AUTH_STR_CLENGTH_FMT "content-length: %zd"
#define OCI_AUTH_STR_CTYPE_FMT	"content-type: %s"
#define OCI_AUTH_STR_CSHA256_FMT "x-content-sha256: %s"

#define OCI_AUTH_STR_BASE_FMT		\
	OCI_AUTH_STR_DATE_FMT "\n"	\
	OCI_AUTH_STR_TARGET_FMT "\n"	\
	OCI_AUTH_STR_HOST_FMT

#define OCI_AUTH_STR_PUT_FMT		\
	OCI_AUTH_STR_BASE_FMT "\n"	\
	OCI_AUTH_STR_CLENGTH_FMT

#define OCI_AUTH_STR_POST_FMT		\
	OCI_AUTH_STR_PUT_FMT "\n"	\
	OCI_AUTH_STR_CTYPE_FMT "\n"	\
	OCI_AUTH_STR_CSHA256_FMT

static const char *oci_auth_methods[] = {
	[HTTP_METHOD_DELETE] = "delete",
	[HTTP_METHOD_GET] = "get",
	[HTTP_METHOD_HEAD] = "head",
	[HTTP_METHOD_POST] = "post",
	[HTTP_METHOD_PUT] = "put",
};

static char *oci_sign(char *str, RSA *pkey)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned int sig_len;
	SHA256_CTX sha_ctx;
	unsigned char *sig;
	char *sig64;
	int rv;

	/* create a SHA-256 message digest */

	rv = SHA256_Init(&sha_ctx);
	if (rv != 1)
		return NULL;

	rv = SHA256_Update(&sha_ctx, str, strlen(str));
	if (rv != 1)
		return NULL;

	rv = SHA256_Final(digest, &sha_ctx);
	if (rv != 1)
		return NULL;

	/* sign the SHA-256 message digest with the provided private key */

	sig = malloc(RSA_size(pkey));
	if (!sig)
		return NULL;

	rv = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH,
		      sig, &sig_len, pkey);
	if (rv != 1) {
		free(sig);
		return NULL;
	}

	/* encode signature with base64 */

	sig64 = base64_encode(sig, sig_len);
	if (!sig64) {
		free(sig);
		return NULL;
	}

	free(sig);

	return sig64;
}

static char *oci_signature(struct oci_config *config, char *date,
			   enum http_method method, const char *endpoint,
			   char *path, size_t clen, const char *content_type,
			   char *content_sha256)
{
	char *sig_str, *sig64;

	switch (method) {

	case HTTP_METHOD_DELETE:
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		sig_str = strfmt(OCI_AUTH_STR_BASE_FMT, date,
				 oci_auth_methods[method], path,
				 endpoint, config->domain);
		break;

	case HTTP_METHOD_PUT:
		sig_str = strfmt(OCI_AUTH_STR_PUT_FMT, date,
				 oci_auth_methods[method], path,
				 endpoint, config->domain, clen);
		break;

	case HTTP_METHOD_POST:
		if (!content_type || !content_sha256)
			return NULL;
		sig_str = strfmt(OCI_AUTH_STR_POST_FMT, date,
				 oci_auth_methods[method], path,
				 endpoint, config->domain, clen,
				 content_type, content_sha256);
		break;

	default:
		return NULL;
	}

	/* building the signature string */

	OCI_DEBUG(config, "SIGNATURE STRING:\n%s\n\n", sig_str);

	/* sign the signature string */

	sig64 = oci_sign(sig_str, config->private_key);

	free(sig_str);

	return sig64;
}

char *oci_auth_header(struct oci_config *config, char *date,
		      enum http_method method, const char *endpoint, char *path,
		      size_t clen, const char *content_type,
		      char *content_sha256)
{
	char *auth, *signature, *headers;
	char *token;

	switch (method) {

	case HTTP_METHOD_DELETE:
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		headers = OCI_AUTH_HEADERS_BASE;
		break;

	case HTTP_METHOD_POST:
		headers = OCI_AUTH_HEADERS_POST;
		break;

	case HTTP_METHOD_PUT:
		headers = OCI_AUTH_HEADERS_PUT;
		break;

	default:
		return NULL;
	}

	signature = oci_signature(config, date, method, endpoint, path,
				  clen, content_type, content_sha256);
	if (!signature)
		return NULL;

	/*
	 * If the OCI configuration has a security token then use it.
	 * Security token is used by resource principal and instance
	 * principal authentication.
	 */
	if (oci_config_has_security_token(config)) {
		/*
		 * Currently oci_config_get_security_token() doesn't
		 * change the session key. If the session key was
		 * changed then signature would need to be rebuilt as
		 * the key is used to sign it.
		 */
		token = oci_config_get_security_token(config);
		if (!token) {
			free(signature);
			return NULL;
		}
		auth = strfmt(OCI_AUTH_ST_HEADER, token, headers, signature);
		oci_config_put_security_token(config);
	} else {
		auth = strfmt(OCI_AUTH_HEADER, PARAM_KEYID(config),
			      headers, signature);
	}

	free(signature);

	return auth;
}

/*
 * Return a security token from the Oracle Cloud auth endpoint.
 */
char *oci_auth_get_security_token(struct oci_config *config,
				  char *cert_pem, char *intermediate_pem,
				  RSA *session_key)
{
	char *session_key_pub_str;
	char *session_key_pub_pem;
	char *intermediate_str;
	struct oci_error error;
	json_t *token_json;
	json_t *result;
	char *cert_str;
	char *token;
	char *body;

	token = NULL;
	cert_str = NULL;
	intermediate_str = NULL;
	session_key_pub_str = NULL;

	/*
	 * The payload to get a security token needs the certificates
	 * and key values in PEM format without the encapsulation
	 * boundaries and without any space/newline.
	 */
	cert_str = pem_strip(cert_pem);
	if (!cert_str)
		return NULL;

	intermediate_str = pem_strip(intermediate_pem);
	if (!intermediate_str)
		goto error;

	session_key_pub_pem = pem_encode_rsa_public(session_key);
	if (!session_key_pub_pem)
		goto error;

	session_key_pub_str = pem_strip(session_key_pub_pem);
	free(session_key_pub_pem);
	if (!session_key_pub_str)
		goto error;

	/* request payload to get a security token */
	body = strfmt(
		"{\n"
		"\t\"certificate\": \"%s\",\n"
		"\t\"intermediateCertificates\": [\"%s\"],\n"
		"\t\"publicKey\": \"%s\"\n"
		"}", cert_str, intermediate_str, session_key_pub_str);

	if (!body)
		goto error;

	/* post the request to the auth endpoint */
	result = oci_request_post_json(config, OCI_ENDPOINT_AUTH, "/v1/x509",
				       body, strlen(body), NULL, 0, &error);

	free(cert_str);
	free(intermediate_str);
	free(session_key_pub_str);
	free(body);

	if (!result)
		return NULL;

	/*
	 * The request returns a JSON object with "token" entry that
	 * contents the security token.
	 */

	token_json = json_object_get(result, "token");
	if (!token_json)
		goto done;

	token = (char *)json_string_value(token_json);
	if (!token)
		goto done;

	token = strdup(token);

done:
	json_decref(result);
	return token;

error:
	free(cert_str);
	free(intermediate_str);
	free(session_key_pub_str);

	return NULL;
}
