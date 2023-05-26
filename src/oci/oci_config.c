/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <regex.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <sys/types.h>

#include "oci.h"
#include "utils.h"

static bool oci_config_use_security_token(struct oci_config *config);

void oci_config_init_private_key(RSA *key)
{
	/*
	 * Disable blinding for the OCI configuration private key as we
	 * have notice issues with old openssl libraries which causes
	 * the request signature to be invalid.
	 *
	 * Also we don't need blinding as the private key is used to
	 * build the request signature so we are provided the function
	 * and its input so there is no need to blind the input/output.
	 */
	RSA_blinding_off(key);
}

struct oci_config *oci_config_create_common(enum oci_config_auth auth,
					    const char *region,
					    const char *user_agent,
					    oci_config_token_refresh_f
					    token_refresh,
					    int debug)
{
	struct oci_config *config;
	int err;

	if (curl_global_init(CURL_GLOBAL_ALL) < 0) {
		OCI_ERROR("Failed to initialize CURL\n");
		return NULL;
	}

	config = malloc(sizeof(*config));
	if (!config)
		return NULL;

	bzero(config, sizeof(*config));

	config->auth = auth;

	if (user_agent) {
		config->user_agent = strdup(user_agent);
		if (!config->user_agent) {
			OCI_ERROR("Failed to set user-agent\n");
			goto error;
		}
	}

	/*
	 * If the region has a dot (.) in its name then it's a full
	 * domain name and we use it directly. Otherwise, build the
	 * domain name from the region by appending ".oraclecloud.com".
	 */
	if (region) {
		if (strchr(region, '.'))
			config->domain = strdup(region);
		else
			config->domain = oci_region_to_domain(region);
		if (!config->domain) {
			OCI_ERROR("Failed to set domain\n");
			goto error;
		}
	}

	if (token_refresh) {
		err = pthread_rwlock_init(&config->rwlock, NULL);
		if (err) {
			OCI_ERROR("Failed to initialize config rwlock\n");
			goto error;
		}

		config->security_token_refresh = token_refresh;
	}

	config->debug = debug;

	return config;

error:
	oci_config_destroy(config);
	return NULL;
}

struct oci_config *oci_config_create_empty(int debug)
{
	return oci_config_create_common(OCI_CONFIG_AUTH_NONE, NULL, NULL, NULL,
					debug);
}

void oci_config_destroy(struct oci_config *config)
{
	if (!config)
		return;

	free((char *)config->tenancy);
	free((char *)config->fingerprint);
	free((char *)config->domain);
	free((char *)config->keyfile);
	free((char *)config->user_agent);
	RSA_free(config->private_key);
	jwt_destroy(config->security_token);

	if (config->auth == OCI_CONFIG_AUTH_INSTANCE_PRINCIPAL) {
		RSA_free(config->tenant_key);
		free(config->cert_pem);
		free(config->intermediate_pem);
	} else {
		free((char *)config->user);
	}

	if (oci_config_use_security_token(config))
		pthread_rwlock_destroy(&config->rwlock);

	free(config->os_bucket);
	free(config->os_namespace);
	free(config);
}

int oci_config_init_object_storage(struct oci_config *config,
				   const char *bucket)
{
	struct oci_error error = OCI_ERROR_INIT_VERBOSE;
	struct oci_os_bucket_head bucket_head;
	int err;

	/*
	 * To initialize Object Storage, we should first define the
	 * namespace, and then the bucket.
	 */

	/* define the namespace */
	config->os_namespace = oci_os_get_namespace(config, &error);
	if (!config->os_namespace) {
		OCI_ERROR("Failed to get Object Storage namespace\n");
		oci_error_print(&error);
		oci_error_fini(&error);
		return -1;
	}

	/* define the bucket */
	if (!bucket) {
		config->os_bucket = NULL;
		return 0;
	}

	err = oci_os_head_bucket(config, bucket, &bucket_head, &error);
	if (err) {
		OCI_ERROR("Failed to access '%s' bucket\n", bucket);
		oci_error_print(&error);
		oci_error_fini(&error);
		return -1;
	}
	oci_os_bucket_head_fini(&bucket_head);

	config->os_bucket = strdup(bucket);
	if (!config->os_bucket)
		return -1;

	return 0;
}

/*
 * Return true if the configuration can use a security token.
 */
static bool oci_config_use_security_token(struct oci_config *config)
{
	/*
	 * Configurations using a security token have a security token
	 * refresh function.
	 */
	return (config->security_token_refresh != NULL);
}

/*
 * Return true if the configuration currently has a security token.
 */
bool oci_config_has_security_token(struct oci_config *config)
{
	return (config->security_token != NULL);
}

/*
 * Refresh the security token if it has expired or is about to expire.
 * If we are unable to refresh the security token, or if the refreshed
 * token has expired then return -1. In that case, the security token
 * remains set with the most recent token we have.
 */
static int oci_config_refresh_security_token(struct oci_config *config)
{
	struct jwt *token_old;
	int err = 0;

	rw_wrlock(&config->rwlock);

	if (!jwt_has_expired(config->security_token,
			     OCI_CONFIG_EXPIRATION_JITTER))
		goto done;

	token_old = config->security_token;
	config->security_token = NULL;

	/*
	 * Refresh the token. If this fails then return an error but keep
	 * the most recent token we have so that we can still try to use
	 * or refresh it.
	 */
	err = (*config->security_token_refresh)(config);
	if (err) {
		OCI_ERROR("Failed to refresh security token\n");
		config->security_token = token_old;
	} else {
		if (jwt_has_expired(config->security_token, 0)) {
			OCI_ERROR("Refreshed token has expired\n");
			err = -1;
		}
		jwt_destroy(token_old);
	}

done:
	rw_unlock(&config->rwlock);
	return err;
}

char *oci_config_get_security_token(struct oci_config *config)
{
	int err;

	if (!oci_config_use_security_token(config))
		return NULL;

	rw_rdlock(&config->rwlock);
	if (jwt_has_expired(config->security_token,
			    OCI_CONFIG_EXPIRATION_JITTER)) {
		rw_unlock(&config->rwlock);
		err = oci_config_refresh_security_token(config);
		if (err)
			return NULL;
		rw_rdlock(&config->rwlock);
	}

	/*
	 * Return the security token without releasing the lock so
	 * that the token is not changed or freed while it is used.
	 */
	return config->security_token->raw;
}

void oci_config_put_security_token(struct oci_config *config)
{
	rw_unlock(&config->rwlock);
}

bool oci_config_refresh(struct oci_config *config)
{
	int err;

	/*
	 * With the current possible configurations, only the security
	 * token can be refreshed.
	 */
	if (!oci_config_use_security_token(config))
		return false;

	err = oci_config_refresh_security_token(config);
	if (err)
		return false;

	return true;
}
