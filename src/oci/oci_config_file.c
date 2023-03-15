/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <regex.h>
#include <string.h>
#include <sys/types.h>

#include "oci.h"

enum oci_config_regexp {
	OCI_CONFIG_RE_EMPTY = 0,
	OCI_CONFIG_RE_COMMENT,
	OCI_CONFIG_RE_SECTION,
	OCI_CONFIG_RE_ENTRY,
	OCI_CONFIG_RE_COUNT,
};

/*
 * Regular expressions for parsing an OCI configuration file
 * (e.g. ~/.oci/config)
 */
static const char *oci_config_regexp[] = {
	/* empty line */
	[OCI_CONFIG_RE_EMPTY] = "^[[:space:]]*$",

	/* comment */
	[OCI_CONFIG_RE_COMMENT] = "^[[:space:]]*#",

	/* section i.e. "[SECTION]" */
	[OCI_CONFIG_RE_SECTION] =
	"^[[:space:]]*"
	"\\[" "[[:space:]]*" "([-_[:alnum:]]+)" "[[:space:]]*" "\\]"
	"[[:space:]]*$",

	/* entry and value i.e. "entry=value" */
	[OCI_CONFIG_RE_ENTRY] =
	"^[[:space:]]*" "([a-z_]+)" "[[:space:]]*"
	"="
	"[[:space:]]*" "([^[:space:]]+)" "[[:space:]]*$",
};

/*
 * Maximum number of pattern matching when using regexps
 * from oci_config_regexp.
 */
#define OCI_CONFIG_PMATCH_MAX 3

enum oci_config_entry {
	OCI_CONFIG_ENTRY_TENANCY = 0,
	OCI_CONFIG_ENTRY_USER,
	OCI_CONFIG_ENTRY_FINGERPRINT,
	OCI_CONFIG_ENTRY_REGION,
	OCI_CONFIG_ENTRY_KEYFILE,
	OCI_CONFIG_ENTRY_COUNT
};

static char *oci_config_entry_names[] = {
	[OCI_CONFIG_ENTRY_TENANCY] = "tenancy",
	[OCI_CONFIG_ENTRY_USER] = "user",
	[OCI_CONFIG_ENTRY_FINGERPRINT] = "fingerprint",
	[OCI_CONFIG_ENTRY_REGION] = "region",
	[OCI_CONFIG_ENTRY_KEYFILE] = "key_file",
};

/*
 * Check if a section line (i.e. "[<SECTION>]") matches with the specified
 * section name.
 *
 * Return 1 if the section matches, 0 if it doesn't, and -1 if there is
 * an error.
 */
static int oci_config_check_file_section(const char *filename, int lineno,
					 const char *section_name, char *line,
					 regmatch_t *pmatch)
{
	size_t len;
	char *str;

	if (pmatch[1].rm_so == -1) {
		OCI_ERROR("%s line %d: failed to parse section\n",
			  filename, lineno);
		return -1;
	}

	str = line + pmatch[1].rm_so;
	len = pmatch[1].rm_eo - pmatch[1].rm_so;

	return strncmp(section_name, str, len) == 0 ? 1 : 0;
}

/*
 * Check if an entry line (i.e. "<entry>=<value>") matches with the
 * specified entry name. If it matches then the associated value is
 * stored in value_p.
 *
 * Return 1 if the entry matches, 0 if it doesn't, and -1 if there is
 * an error.
 */
static int oci_config_check_file_entry(const char *filename, int lineno,
				       const char *entry_name, char *line,
				       regmatch_t *pmatch, char **value_p)

{
	size_t entry_len, value_len;
	char *entry, *value;

	entry = line + pmatch[1].rm_so;
	entry_len = pmatch[1].rm_eo - pmatch[1].rm_so;

	if (strncmp(entry_name, entry, entry_len) != 0)
		return 0;

	value = line + pmatch[2].rm_so;
	value_len = line + pmatch[2].rm_eo - value;

	value = strndup(value, value_len);
	if (!value) {
		/* the entry matches but we can't store the value */
		return -1;
	}

	if (*value_p) {
		OCI_ERROR("%s line %d: entry %s is duplicated\n",
			  filename, lineno, entry_name);
		free(*value_p);
	}

	*value_p = value;

	return 1;
}

/*
 * Match an entry line (i.e. "<entry>=<param>") against the OCI
 * configuration entry names (defined in oci_config_entry_names[]),
 * and returns the matching value in the corresponding entry array.
 */
static void oci_config_match_file_entry(const char *filename, int lineno,
					char *line, regmatch_t *pmatch,
					char **entry)
{
	int i, match;

	if (pmatch[1].rm_so == -1 || pmatch[2].rm_so == -1) {
		OCI_ERROR("%s line %d: failed to parse entry\n",
			  filename, lineno);
		return;
	}

	match = 0;
	for (i = 0; i < OCI_CONFIG_ENTRY_COUNT; i++) {
		match = oci_config_check_file_entry(filename, lineno,
						    oci_config_entry_names[i],
						    line, pmatch, &entry[i]);
		if (match)
			break;
	}

	if (match < 0) {
		OCI_ERROR("%s line %d: failed to handle entry '%s'\n",
			  filename, lineno, oci_config_entry_names[i]);
	} else if (!match) {
		OCI_ERROR("%s line %d: ignoring unknown parameter\n",
			  filename, lineno);
	}

	return;
}

struct oci_config *oci_config_create_from_file(const char *filename,
					       const char *region,
					       const char *user_agent,
					       int debug)
{
	regmatch_t pmatch[OCI_CONFIG_PMATCH_MAX];
	regex_t r_config[OCI_CONFIG_RE_COUNT];
	char *entry[OCI_CONFIG_ENTRY_COUNT] = {0};
	int i, j, err, lineno, rv, match;
	struct oci_config *config;
	char *default_cfg;
	bool in_section;
	size_t bufsize;
	FILE *file;
	char *buf;

	if (!filename) {
		default_cfg = expand_path("~/.oci/config");
		if (!default_cfg) {
			OCI_ERROR("Failed to expand default OCI configuration file");
			return NULL;
		}
		filename = default_cfg;
	} else {
		default_cfg = NULL;
	}

	for (i = 0; i < OCI_CONFIG_RE_COUNT; i++) {
		err = regcomp(&r_config[i], oci_config_regexp[i], REG_EXTENDED);
		if (err) {
			OCI_ERROR("Failed to compile regex: %s\n",
				  oci_config_regexp[i]);
			for (j = 0; j < i; j++)
				regfree(&r_config[j]);
			free(default_cfg);
			return NULL;
		}
	}

	lineno = 1;
	buf = NULL;
	bufsize = 0;
	in_section = false;

	file = fopen(filename, "r");
	if (!file) {
		OCI_ERROR("Failed to open configuration file '%s'\n", filename);
		for (i = 0; i < OCI_CONFIG_RE_COUNT; i++)
			regfree(&r_config[i]);
		free(default_cfg);
		return NULL;
	}

	while (getline(&buf, &bufsize, file) != -1) {

		for (i = 0; i < OCI_CONFIG_RE_COUNT; i++) {
			match = regexec(&r_config[i], buf,
					OCI_CONFIG_PMATCH_MAX, pmatch, 0);
			if (match == 0)
				break;
		}

		switch (i) {

		case OCI_CONFIG_RE_EMPTY:
		case OCI_CONFIG_RE_COMMENT:
			break;

		case OCI_CONFIG_RE_SECTION:
			rv = oci_config_check_file_section(filename, lineno,
							   "DEFAULT",
							   buf, pmatch);
			if (rv == 1)
				in_section = true;
			else
				in_section = false;
			break;

		case OCI_CONFIG_RE_ENTRY:
			if (!in_section)
				break;
			oci_config_match_file_entry(filename, lineno, buf,
						    pmatch, entry);
			break;

		default:
			OCI_ERROR("%s line %d: ignoring unrecognized line\n",
				  filename, lineno);
			break;
		}

		lineno++;
	}

	free(buf);
	fclose(file);

	for (i = 0; i < OCI_CONFIG_RE_COUNT; i++)
		regfree(&r_config[i]);

	/*
	 * Check that we have all parameters we need.
	 */
	err = 0;
	for (i = 0; i < OCI_CONFIG_ENTRY_COUNT; i++) {
		if (!entry[i]) {
			OCI_ERROR("%s: value for '%s' is not defined\n",
				  filename, oci_config_entry_names[i]);
			err++;
		}
	}
	free(default_cfg);
	if (err) {
		config = NULL;
		goto done;
	}

	if (!region)
		region = entry[OCI_CONFIG_ENTRY_REGION];

	config = oci_config_create_common(OCI_CONFIG_AUTH_API_KEY,
					  region, user_agent, NULL, debug);
	if (!config)
		goto done;

	config->tenancy = strdup(entry[OCI_CONFIG_ENTRY_TENANCY]);
	if (!config->tenancy)
		goto error;

	config->user = strdup(entry[OCI_CONFIG_ENTRY_USER]);
	if (!config->user)
		goto error;

	config->fingerprint = strdup(entry[OCI_CONFIG_ENTRY_FINGERPRINT]);
	if (!config->fingerprint)
		goto error;

	config->keyfile = expand_path(entry[OCI_CONFIG_ENTRY_KEYFILE]);
	if (!config->keyfile) {
		OCI_ERROR("Failed to expand key file path '%s'\n",
			  entry[OCI_CONFIG_ENTRY_KEYFILE]);
		goto error;
	}

	config->private_key = load_private_key(config->keyfile, NULL);
	if (!config->private_key) {
		OCI_ERROR("Failed to load key from '%s'\n", config->keyfile);
		goto error;
	}

done:
	for (i = 0; i < OCI_CONFIG_ENTRY_COUNT; i++)
		free(entry[i]);

	return config;

error:
	oci_config_destroy(config);
	config = NULL;
	goto done;
}
