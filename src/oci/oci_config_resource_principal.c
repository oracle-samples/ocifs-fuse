/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <string.h>

#include "oci.h"

static int oci_config_refresh_token_resource_principal(struct oci_config *config)
{
	char *token;
	char *rpst;

	rpst = getenv("OCI_RESOURCE_PRINCIPAL_RPST");
	if (!rpst) {
		OCI_ERROR("OCI_RESOURCE_PRINCIPAL_RPST is not set\n");
		return -1;
	}

	/*
	 * If the value of OCI_RESOURCE_PRINCIPAL_RPST starts with a
	 * slash (/) then it references a file with the security token.
	 * Otherwise it directly provides the security token.
	 */
	if (rpst[0] == '/') {
		token = file_read(rpst, NULL);
		if (!token) {
			OCI_ERROR("Failed to read RPST file '%s'\n", rpst);
			return -1;
		}
	} else {
		token = rpst;
	}

	config->security_token = jwt_decode(token);
	if (rpst[0] == '/')
		free(token);
	if (!config->security_token) {
		OCI_ERROR("Failed to decode security token\n");
		return -1;
	}

	return 0;
}

struct oci_config *oci_config_resource_principal(const char *region,
						 const char *user_agent,
						 int debug)
{
	struct oci_config *config;
	char *passphrase;
	char *keyfile;
	char *version;
	int err;

	version = getenv("OCI_RESOURCE_PRINCIPAL_VERSION");
	if (!version) {
		OCI_ERROR("OCI_RESOURCE_PRINCIPAL_VERSION is not set\n");
		return NULL;
	}

	if (strcmp(version, "2.2") != 0) {
		OCI_ERROR("Unknown resource principal version %s\n", version);
		return NULL;
	}

	config = oci_config_create_common(OCI_CONFIG_AUTH_RESOURCE_PRINCIPAL,
					  region, user_agent,
					  oci_config_refresh_token_resource_principal,
					  debug);
	if (!config)
		return NULL;

	/* set domain region */
	if (!config->domain) {
		region = getenv("OCI_RESOURCE_PRINCIPAL_REGION");
		if (!region) {
			OCI_ERROR("Failed to get tenant region\n");
			goto error;
		}
		config->domain = oci_region_to_domain(region);
	}

	if (!config->domain) {
		OCI_ERROR("Failed to set domain\n");
		goto error;
	}

	/*
	 * The RPST, private key and passphrase may be used in one of two
	 * modes. In the first mode, they contain the actual contents of
	 * the RPST, private key (in PEM format) and the passphrase. In
	 * the second mode, if these variables contain absolute paths,
	 * then those paths are taken as the on-filesystem location of
	 * the values in question.
	 */

	/* get passphrase */
	passphrase = getenv("OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM_PASSPHRASE");
	if (passphrase && passphrase[0] == '/')
		passphrase = file_read(passphrase, NULL); // XXX should free

	/* get the session key */
	keyfile = getenv("OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM");
	if (!keyfile) {
		OCI_ERROR("OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM is not set\n");
		goto error;
	}

	if (keyfile[0] == '/') {
		config->keyfile = expand_path(keyfile);
		if (!config->keyfile) {
			OCI_ERROR("Failed to expand key file path '%s'\n",
				  keyfile);
			goto error;
		}

		config->private_key = load_private_key(config->keyfile,
						       passphrase);
		if (!config->private_key) {
			OCI_ERROR("Failed to load key from '%s'\n",
				  config->keyfile);
			goto error;
		}
	} else {
		config->private_key = read_private_key(keyfile, passphrase);
		if (!config->private_key) {
			OCI_ERROR("Failed to read key from '%s'\n", keyfile);
			goto error;
		}
	}

	oci_config_init_private_key(config->private_key);

	/* set the security token */
	err = oci_config_refresh_token_resource_principal(config);
	if (err)
		goto error;

	/*
	 * The resource tenant is available in the "res_tenant" claim
	 * of the security token.
	 */
	config->tenancy = jwt_claim_str(config->security_token, "res_tenant");
	if (!config->tenancy) {
		OCI_ERROR("Failed to get tenancy from security token\n");
		goto error;
	}

	/*
	 * config->user and config->fingerprint are not defined because
	 * we use a security token.
	 */

	return config;

error:
	oci_config_destroy(config);
	return NULL;
}
