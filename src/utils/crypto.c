/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <string.h>

#include "utils.h"

#define PEM_DASHES	"-----"
#define PEM_BEGIN	PEM_DASHES "BEGIN "
#define PEM_END		PEM_DASHES "END "

/*
 * Handle differences between OpenSSL 1.1.1 and previous versions.
 */
#if OPENSSL_VERSION_NUMBER >= 0x010101000L

#define asn1_string_get_data	ASN1_STRING_get0_data
#define x509_get_notAfter	X509_get0_notAfter
#define asn1_time_to_tm		ASN1_TIME_to_tm

#else

#define asn1_string_get_data	ASN1_STRING_data
#define x509_get_notAfter	X509_get_notAfter

/*
 * OpenSSL before 1.1.1 doesn't have a function to directly convert
 * an ASN1 time to tm. So instead, use ASN1_TIME_print() to convert
 * the ASN1 time to a string, and then strptime() to convert that
 * string to tm.
 *
 * Returns 1 if the time is successfully parsed and 0 if an error
 * occurred.
 */

#define ASN1_TIME_LENGTH	STRLEN("MMM DD HH:MM:SS YYYY GMT")

static int asn1_time_to_tm(const ASN1_TIME *s, struct tm *tm)
{
	char buf[ASN1_TIME_LENGTH + 1];
	char *str;
	int count;
	BIO *bio;
	int rv;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return 0;

	rv = ASN1_TIME_print(bio, s);
	if (rv != 1)
		goto error;

	count = BIO_read(bio, buf, ASN1_TIME_LENGTH);
	if (count <= 0)
		goto error;

	buf[count] = '\0';

	/*
	 * ANS1_TIME_print() always use GMT but doesn't always include
	 * it in the string, so do not parse the optional timezone at
	 * end of the string.
	 */
	str = strptime(buf, "%b %d %H:%M:%S %Y%n", tm);
	if (!str)
		goto error;

	/*
	 * The parsing should reach either the end of the string, or the
	 * timezone ("GMT").
	 */
	if (str[0] != '\0' && strcmp(str, "GMT") != 0)
		goto error;

	BIO_free_all(bio);

	return 1;
error:
	BIO_free_all(bio);
	return 0;
}

#endif

/*
 * Decode a certificate in PEM format into a X509 structure.
 */
X509 *pem_decode_cert(char *cert_pem)
{
	X509 *cert;
	int count;
	BIO *bio;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;

	count = BIO_puts(bio, cert_pem);
	if (count <= 0) {
		BIO_free_all(bio);
		return NULL;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

	BIO_free_all(bio);

	return cert;
}

/*
 * Decode a private RSA key in PEM format into a RSA structure.
 */
RSA *pem_decode_rsa_private(char *key_pem)
{
	int count;
	RSA *rsa;
	BIO *bio;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;

	count = BIO_puts(bio, key_pem);
	if (count <= 0) {
		BIO_free_all(bio);
		return NULL;
	}

	rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

	BIO_free_all(bio);

	return rsa;
}

/*
 * Encode a RSA public key into PEM format.
 */
char *pem_encode_rsa_public(RSA *key)
{
	char *pubkey_pem;
	char *str;
	long len;
	BIO *bio;
	int rv;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;

	rv = PEM_write_bio_RSA_PUBKEY(bio, key);
	if (rv != 1) {
		BIO_free_all(bio);
		return NULL;
	}

	len = BIO_get_mem_data(bio, &str);
	if (len <= 0) {
		BIO_free_all(bio);
		return NULL;
	}

	pubkey_pem = strndup(str, len);
	BIO_free_all(bio);

	return pubkey_pem;
}

/*
 * Strip a buffer in PEM format by removing the BEGIN and END
 * encapsulation boundaries, and also remove any space or newline
 * in the base64-encoded data.
 *
 * Return a newly allocated buffer with the stripped PEM string.
 */
char *pem_strip(char *pem_str)
{
	char *begin;
	char *src, *dst;

	begin = strdup(pem_str);
	if (!begin)
		return NULL;

	/*
	 * From RFC 7468:
	 *
	 * Textual encoding begins with a line comprising "-----BEGIN ",
	 * a label, and "-----", and ends with a line comprising
	 * "-----END ", a label, and "-----".  Between these lines, or
	 * "encapsulation boundaries", are base64-encoded data.
	 *
	 * There is exactly one space character (SP) separating the
	 * "BEGIN" or "END" from the label.  There are exactly five
	 * hyphen-minus (also known as dash) characters ("-") on both
	 * ends of the encapsulation boundaries, no more, no less.
	 */

	/* search and skip "-----BEGIN " */
	src = strstr(begin, PEM_BEGIN);
	if (!src)
		goto error;

	src += STRLEN(PEM_BEGIN);

	/* search and skip "-----" */
	src = strstr(src, PEM_DASHES);
	if (!src)
		goto error;

	src += STRLEN(PEM_DASHES);

	/* skip spaces */
	while (*src && isspace(*src))
		src++;

	/*
	 * Copy non-space characters up until we reach the
	 * "-----END" encapsulation boundary.
	 */
	for (dst = begin; *src; src++) {

		if (isspace(*src))
			continue;

		if (*src != '-') {
			*dst++ = *src;
			continue;
		}

		/* we should have reached "-----END " */
		if (strncmp(PEM_END, src, STRLEN(PEM_END)) != 0)
			break;

		*dst = '\0';
		return begin;
	}

error:
	free(begin);
	return NULL;
}

/*
 * Return a certificate SHA1 fingerprint as a string with column (:)
 * separated values.
 */
char *cert_fingerprint(X509 *cert)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	char *fingerprint;
	int rv;
	int i;

	rv = X509_digest(cert, EVP_sha1(), md, &md_len);
	if (rv != 1)
		return NULL;

	fingerprint = malloc(md_len * 3 + 1);
	if (!fingerprint)
		return NULL;

	for (i = 0; i < md_len; i++)
		sprintf(fingerprint + i * 3, "%02X:", md[i]);

	/* replace the last colon (:) with '\0' */
	fingerprint[md_len * 3 - 1] = '\0';

	return fingerprint;
}

time_t cert_expiration(X509 *cert)
{
	const ASN1_TIME *not_after;
	struct tm tm;
	time_t time;
	int rv;

	not_after = x509_get_notAfter(cert);
	if (!not_after)
		return 0;

	rv = asn1_time_to_tm(not_after, &tm);
	if (rv != 1)
		return 0;

	time = mktime(&tm);
	if (time == (time_t)-1)
		return 0;

	return time;
}

/*
 * Generate a RSA key pair.
 */
RSA *rsa_generate_key(int key_size)
{
	BIGNUM *bn;
	RSA *key;
	int rv;

	bn = BN_new();
	if (!bn)
		return NULL;

	rv = BN_set_word(bn, RSA_F4);
	if (rv != 1) {
		BN_free(bn);
		return NULL;
	}

	key = RSA_new();
	if (!key) {
		BN_free(bn);
		return NULL;
	}

	rv = RSA_generate_key_ex(key, key_size, bn, NULL);
	BN_free(bn);
	if (rv != 1) {
		RSA_free(key);
		return NULL;
	}

	return key;
}

/*
 * Search the specified prefix in the subject entries of a certificate.
 * Return a pointer to the first subject entry with the prefix. The
 * returned value is an internal pointer which MUST NOT be freed
 */
const char *cert_subject_search_prefix(X509 *cert, const char *prefix)
{
	X509_NAME *subject;
	ASN1_STRING *entry_data;
	X509_NAME_ENTRY *entry;
	const char *data_str;
	size_t prefix_len;
	int count;
	int i;

	if (!prefix || *prefix == '\0')
		return NULL;

	subject = X509_get_subject_name(cert);
	if (!subject)
		return NULL;

	prefix_len = strlen(prefix);

	count = X509_NAME_entry_count(subject);

	for (i = 0; i < count; i++) {

		entry = X509_NAME_get_entry(subject, i);
		if (!entry)
			continue;

		entry_data = X509_NAME_ENTRY_get_data(entry);
		if (!entry_data)
			continue;

		data_str = (const char *)asn1_string_get_data(entry_data);

		if (!data_str)
			continue;

		if (strncmp(data_str, prefix, prefix_len) == 0)
			return data_str;
	}

	return NULL;
}
