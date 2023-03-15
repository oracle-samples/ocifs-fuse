/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <string.h>

#include "utils.h"

#define OCI_DOMAIN "oraclecloud.com"

enum oci_realm {
	OCI_REALM_OC1,
	OCI_REALM_OC2,
	OCI_REALM_OC3,
	OCI_REALM_OC4,
	OCI_REALM_OC8,
	OCI_REALM_OC9,
	OCI_REALM_OC10,
};

static const char *oci_realm_domains[] = {
	[OCI_REALM_OC1] = "oraclecloud.com",
	[OCI_REALM_OC2] = "oraclegovcloud.com",
	[OCI_REALM_OC3] = "oraclegovcloud.com",
	[OCI_REALM_OC4] = "oraclegovcloud.com",
	[OCI_REALM_OC8] = "oraclecloud8.com",
	[OCI_REALM_OC9] = "oraclecloud9.com",
	[OCI_REALM_OC10] = "oraclecloud10.com",
};

struct oci_region {
	const char *code;	/* 3-letter region code */
	const char *id;		/* region id */
	enum oci_realm realm;	/* region realm */
};

static struct oci_region oci_regions[] = {
	{ "yny", "ap-chuncheon-1", OCI_REALM_OC1 },
	{ "hyd", "ap-hyderabad-1", OCI_REALM_OC1 },
	{ "mel", "ap-melbourne-1", OCI_REALM_OC1 },
	{ "bom", "ap-mumbai-1", OCI_REALM_OC1 },
	{ "kix", "ap-osaka-1", OCI_REALM_OC1 },
	{ "icn", "ap-seoul-1", OCI_REALM_OC1 },
	{ "syd", "ap-sydney-1", OCI_REALM_OC1 },
	{ "nrt", "ap-tokyo-1", OCI_REALM_OC1 },
	{ "yul", "ca-montreal-1", OCI_REALM_OC1 },
	{ "yyz", "ca-toronto-1", OCI_REALM_OC1 },
	{ "ams", "eu-amsterdam-1", OCI_REALM_OC1 },
	{ "fra", "eu-frankfurt-1", OCI_REALM_OC1 },
	{ "zrh", "eu-zurich-1", OCI_REALM_OC1 },
	{ "jed", "me-jeddah-1", OCI_REALM_OC1 },
	{ "dxb", "me-dubai-1", OCI_REALM_OC1 },
	{ "gru", "sa-saopaulo-1", OCI_REALM_OC1 },
	{ "cwl", "uk-cardiff-1", OCI_REALM_OC1 },
	{ "lhr", "uk-london-1", OCI_REALM_OC1 },
	{ "iad", "us-ashburn-1", OCI_REALM_OC1 },
	{ "phx", "us-phoenix-1", OCI_REALM_OC1 },
	{ "sjc", "us-sanjose-1", OCI_REALM_OC1 },
	{ "vcp", "sa-vinhedo-1", OCI_REALM_OC1 },
	{ "scl", "sa-santiago-1", OCI_REALM_OC1 },
	{ "mtz", "il-jerusalem-1", OCI_REALM_OC1 },
	{ "mrs", "eu-marseille-1", OCI_REALM_OC1 },
	{ "sin", "ap-singapore-1", OCI_REALM_OC1 },
	{ "auh", "me-abudhabi-1", OCI_REALM_OC1 },
	{ "lin", "eu-milan-1", OCI_REALM_OC1 },
	{ "arn", "eu-stockholm-1", OCI_REALM_OC1 },
	{ "jnb", "af-johannesburg-1", OCI_REALM_OC1 },
	{ "cdg", "eu-paris-1", OCI_REALM_OC1 },
	{ "qro", "mx-queretaro-1", OCI_REALM_OC1 },
	{ "lfi", "us-langley-1", OCI_REALM_OC2 },
	{ "luf", "us-luke-1", OCI_REALM_OC2 },
	{ "ric", "us-gov-ashburn-1", OCI_REALM_OC3 },
	{ "pia", "us-gov-chicago-1", OCI_REALM_OC3 },
	{ "tus", "us-gov-phoenix-1", OCI_REALM_OC3 },
	{ "ltn", "uk-gov-london-1", OCI_REALM_OC4 },
	{ "brs", "uk-gov-cardiff-1", OCI_REALM_OC4 },
	{ "nja", "ap-chiyoda-1", OCI_REALM_OC8 },
	{ "ukb", "ap-ibaraki-1", OCI_REALM_OC8 },
	{ "mct", "me-dcc-muscat-1", OCI_REALM_OC9 },
	{ "wga", "ap-dcc-canberra-1", OCI_REALM_OC10 },
};

/*
 * Lookup a region from its region id or code. Return NULL if the
 * region is not found.
 */
static struct oci_region *oci_region_lookup(const char *region_name)
{
	struct oci_region *region;
	int i;

	for (i = 0; i < ARRAY_SIZE(oci_regions); i++) {
		region = &oci_regions[i];
		if (strcmp(region->code, region_name) == 0 ||
		    strcmp(region->id, region_name) == 0)
			return region;
	}

	return NULL;
}

/*
 * Return an OCI domain name from a region id or region code.
 */
const char *oci_region_to_domain(const char *region_name)
{
	struct oci_region *region;
	const char *domain;
	const char *id;

	region = oci_region_lookup(region_name);
	if (region) {
		id = region->id;
		domain = oci_realm_domains[region->realm];
	} else {
		id = region_name;
		domain = OCI_DOMAIN;
	}

	return strfmt("%s.%s", id, domain);
}
