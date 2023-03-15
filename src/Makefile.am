#
# Copyright (c) 2023, Oracle and/or its affiliates.
#
# Licensed under the Universal Permissive License v 1.0
# as shown at https://oss.oracle.com/licenses/upl/
#

AUTOMAKE_OPTIONS = subdir-objects

#
# Use gnu99 instead of c99 to get raw string literals.
# Need _GNU_SOURCE for stpcpy()
# Need POSIX_C_SOURCE >= 200809L for *at()
#
# fuse requires -D_FILE_OFFSET_BITS=64
#
AM_CFLAGS = -std=c99 -Wall -Werror -Wfatal-errors

#
# The code uses OpenSSL functions which are deprecated starting with
# version 3. So, when using OpenSSL 3, do not make deprecated
# declarations warnings into errors.
#
if OPENSSL3
AM_CFLAGS += -Wno-error=deprecated-declarations
endif

AM_CFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_POSIX_C_SOURCE=200809L
AM_CFLAGS += -DOCIFS_VERSION=\"$(PACKAGE_VERSION)\"
AM_CFLAGS += -Ioci -Iutils

debug : AM_CFLAGS += -DDEBUG
debug : AM_CFLAGS += -fsanitize=address
debug : all

bin_PROGRAMS = ocifs/ocifs
noinst_LIBRARIES = oci/liboci.a utils/libutils.a

#
# Librairies (static)
#

utils_libutils_a_SOURCES =	utils/crypto.c		\
				utils/dstore.c		\
				utils/json.c		\
				utils/range.c		\
				utils/utils.c		\
				utils/utils.h

LIBUTILS = utils/libutils.a $(LIBJSON) $(LIBPTHREAD) $(LIBCRYPTO)

oci_liboci_a_SOURCES =	oci/oci.h				\
			oci/oci_api.c				\
			oci/oci_auth.c				\
			oci/oci_config.c			\
			oci/oci_config_file.c			\
			oci/oci_config_instance_principal.c	\
			oci/oci_config_resource_principal.c	\
			oci/oci_error.c				\
			oci/oci_region.c			\
			oci/oci_request.c

LIBOCI = oci/liboci.a $(LIBCURL) $(LIBCRYPTO) $(LIBUTILS)

#
# Main Program (ocifs)
#

ocifs_ocifs_SOURCES =	ocifs/ocifs.c 			\
			ocifs/ocifs.h			\
			ocifs/ocifs_cache.c		\
			ocifs/ocifs_cache.h		\
			ocifs/ocifs_cloud.c		\
			ocifs/ocifs_cloud.h		\
			ocifs/ocifs_dir.c		\
			ocifs/ocifs_file.c		\
			ocifs/ocifs_namespace.c		\
			ocifs/ocifs_namespace.h

ocifs_ocifs_LDADD = $(LIBFUSE) $(LIBOCI)
