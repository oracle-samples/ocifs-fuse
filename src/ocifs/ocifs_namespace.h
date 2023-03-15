/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#ifndef __OCIFS_NAMESPACE_H__
#define __OCIFS_NAMESPACE_H__

void ocifs_ns_rdlock(const char *name);
void ocifs_ns_wrlock(const char *name);
void ocifs_ns_unlock(const char *name);

#endif	/* __OCIFS_NAMESPACE_H__ */
