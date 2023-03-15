/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * Licensed under the Universal Permissive License v 1.0
 * as shown at https://oss.oracle.com/licenses/upl/
 */

#include <pthread.h>

#include "ocifs_namespace.h"
#include "utils.h"

/*
 * Function to lock the OCIFS namespace to protect Object Storage
 * object names. The namespace can be locked for reading or writing.
 * Multiple readers are possible simultaneously.
 *
 * Currently the lock is implemented with a global rwlock so this will
 * will lock the entire namespaced. Granularity could be improved with
 * a mechanism to hierarchically lock names.
 */

static pthread_rwlock_t ocifs_ns_lock = PTHREAD_RWLOCK_INITIALIZER;

void ocifs_ns_rdlock(const char *name)
{
	rw_rdlock(&ocifs_ns_lock);
}

void ocifs_ns_wrlock(const char *name)
{
	rw_wrlock(&ocifs_ns_lock);
}

void ocifs_ns_unlock(const char *name)
{
	rw_unlock(&ocifs_ns_lock);
}
