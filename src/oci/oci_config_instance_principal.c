/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <openssl/pem.h>
#include <regex.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "oci.h"
#include "utils.h"

static int oci_config_refresh_token_instance_principal(struct oci_config *config);

static int oci_config_set_token_instance_principal(struct oci_config *config)
{
	RSA *session_key;
	char *token;

	/* use the tenant key for this request */
	session_key = config->private_key;
	config->private_key = config->tenant_key;

	/*
	 * Make a request to get a security token. Use the tenant key
	 * for this request. The session public key will be sent in
	 * the request payload.
	 */
	token = oci_auth_get_security_token(config,
					    config->cert_pem,
					    config->intermediate_pem,
					    session_key);

	/* restore the session key */
	config->private_key = session_key;

	if (!token) {
		OCI_ERROR("Failed to get security token\n");
		return -1;
	}

	/* set the security token */
	config->security_token = jwt_decode(token);
	free(token);
	if (!config->security_token) {
		OCI_ERROR("Failed to decode security token\n");
		return -1;
	}

	return 0;
}

/*
 * Set volatile data of an instance principal configuration i.e. data
 * which will expire at some point, like the tenant certificate, its
 * key or the security token.
 */
static int oci_config_set_instance_principal(struct oci_config *config)
{
	const char *cert_tenant;
	char *key_pem = NULL;
	X509 *cert = NULL;;
	int rv = -1;
	int err;

	/*
	 * Get information from the instance metadata service (IMDS).
	 *
	 * This information will be used to retrieve a security token
	 * from the Oracle Cloud auth service.
	 *
	 * Note that the certificate (and associate private key) rotates
	 * every two hours. The security token expires after 20 minutes,
	 * the expiration time is indicated in the token.
	 *
	 * The security token remains valid as long as it hasn't expired
	 * (even if the tenant certificate used to get it has expired).
	 * After a token has expired, a new token should be retrieved
	 * (with the tenant new certificate if the previous one has
	 * expired).
	 */

	/*
	 * Get the tenant certificate, extract the OCID from the
	 * certificate.
	 */
	config->cert_pem = oci_imds_get_str(config, "identity/cert.pem", NULL);
	if (!config->cert_pem) {
		OCI_ERROR("Failed to get tenant certificate\n");
		goto done;
	}

	cert = pem_decode_cert(config->cert_pem);
	if (!cert) {
		OCI_ERROR("Failed to decode tenant certificate\n");
		goto done;
	}

	config->cert_expiration = cert_expiration(cert);
	if (config->cert_expiration == 0) {
		OCI_ERROR("Failed to get certificate expiration\n");
		goto done;
	}

	cert_tenant = cert_subject_search_prefix(cert, "opc-tenant:");
	if (!cert_tenant) {
		OCI_ERROR("Failed to get tenant ID from certificate\n");
		goto done;
	}

	config->tenancy = strdup(cert_tenant + STRLEN("opc-tenant:"));
	if (!config->tenancy) {
		OCI_ERROR("Failed to set tenancy\n");
		goto done;
	}

	/* build the fingerprint from the tenant certificate digest */
	config->fingerprint = cert_fingerprint(cert);
	if (!config->fingerprint) {
		OCI_ERROR("Failed to get tenant certificate fingerprint\n");
		goto done;
	}

	/* get intermediate certificate */
	config->intermediate_pem = oci_imds_get_str(config,
						    "identity/intermediate.pem",
						    NULL);
	if (!config->intermediate_pem) {
		OCI_ERROR("Failed to get intermediate certificate\n");
		goto done;
	}

	/* get tenant key */
	key_pem = oci_imds_get_str(config, "identity/key.pem", NULL);
	if (!key_pem) {
		OCI_ERROR("Failed to get tenant key\n");
		goto done;
	}

	config->tenant_key = pem_decode_rsa_private(key_pem);
	if (!config->tenant_key) {
		OCI_ERROR("Failed to decode tenant key\n");
		goto done;
	}

	/*
	 * The tenant key is used as the private key to get the
	 * security token.
	 */
	oci_config_init_private_key(config->tenant_key);

	/* set the security token */
	err = oci_config_set_token_instance_principal(config);
	if (err)
		goto done;

	/* configuration is completed, cleanup */
	rv = 0;
done:
	free(key_pem);
	X509_free(cert);

	return rv;
}

/*
 * Create a configuration for instance principals.
 */
struct oci_config *oci_config_instance_principal(const char *region,
						 const char *user_agent,
						 int debug)
{
	struct oci_config *config;
	int err;

	config = oci_config_create_common(OCI_CONFIG_AUTH_INSTANCE_PRINCIPAL,
					  region, user_agent,
					  oci_config_refresh_token_instance_principal,
					  debug);
	if (!config)
		return NULL;

	/*
	 * First initialize immutable parameters of an instance
	 * principal configuration. Other parameters are set when
	 * refreshing the configuration.
	 */

	/* set user */
	config->user = "fed-x509";

	/* set domain from region */
	if (!config->domain) {
		region = oci_imds_get_str(config, "instance/region", NULL);
		if (!region) {
			OCI_ERROR("Failed to get tenant region\n");
			goto error;
		}
		config->domain = oci_region_to_domain(region);
		free((char *)region);
	}

	if (!config->domain) {
		OCI_ERROR("Failed to set domain\n");
		goto error;
	}

	/* generate a key for the session */
	config->private_key = rsa_generate_key(2048);
	if (!config->private_key) {
		OCI_ERROR("Failed to generate session key\n");
		goto error;
	}

	oci_config_init_private_key(config->private_key);

	err = oci_config_set_instance_principal(config);
	if (err)
		goto error;

	return config;

error:
	oci_config_destroy(config);
	return NULL;
}

static int oci_config_refresh_instance_principal(struct oci_config *config)
{
	/* free and clear all fields which will be refreshed */

	free((char *)config->tenancy);
	free((char *)config->fingerprint);
	jwt_destroy(config->security_token);
	RSA_free(config->tenant_key);
	free(config->cert_pem);
	free(config->intermediate_pem);

	config->tenancy = NULL;
	config->fingerprint = NULL;
	config->security_token = NULL;
	config->tenant_key = NULL;
	config->cert_pem = NULL;
	config->intermediate_pem = NULL;

	return oci_config_set_instance_principal(config);
}

static int oci_config_refresh_token_instance_principal(struct oci_config *config)
{
	/*
	 * If the tenant certificate has expired then we need to refresh
	 * the entire configuration to get a new certificate and a new
	 * security token and not just the security token.
	 */
	if (time(NULL) + OCI_CONFIG_EXPIRATION_JITTER > config->cert_expiration)
		return oci_config_refresh_instance_principal(config);

	return oci_config_set_token_instance_principal(config);
}
