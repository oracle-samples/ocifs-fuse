#
# Copyright (c) 2023, Oracle and/or its affiliates.
#
# Licensed under the Universal Permissive License v 1.0
# as shown at https://oss.oracle.com/licenses/upl/
#

AUTOMAKE_OPTIONS = subdir-objects

SRC = ../src

#
# Use gnu99 instead of c99 to get raw string literals.
# Need _GNU_SOURCE for stpcpy()
# Need POSIX_C_SOURCE >= 200809L for *at()
#
# fuse requires -D_FILE_OFFSET_BITS=64
#
AM_CFLAGS = -std=c99 -Wall -Werror -Wfatal-errors
AM_CFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_POSIX_C_SOURCE=200809L
AM_CFLAGS += -I$(SRC)/oci -I$(SRC)/utils
AM_CFLAGS += -fsanitize=address

check_PROGRAMS = oci range rmtree
if TEST_FRAMEWORK
check_PROGRAMS += test_json test_oci test_ocifs test_utils
endif

LIBUTILS = $(SRC)/utils/libutils.a $(LIBJSON) $(LIBPTHREAD) $(LIBCRYPTO)
LIBOCI = $(SRC)/oci/liboci.a $(LIBCURL) $(LIBCRYPTO) $(LIBUTILS)

#
# Test Programs
#

oci_SOURCES = oci.c
oci_LDADD = $(LIBOCI)

range_SOURCES = range.c
range_LDADD = $(LIBUTILS)

rmtree_SOURCES = rmtree.c
rmtree_LDADD = $(LIBUTILS)

if TEST_FRAMEWORK

test_json_SOURCES = test_json.c
test_json_LDADD = $(LIBTEST) $(LIBUTILS) $(LIBJSON)

test_oci_SOURCES = test_oci.c
test_oci_LDADD = $(LIBTEST) $(LIBOCI) $(LIBUTILS)

test_ocifs_SOURCE = test_ocifs.c
test_ocifs_LDADD = $(LIBTEST) $(LIBOCI)

test_utils_SOURCE = test_utils.c
test_utils_LDADD = $(LIBTEST) $(LIBUTILS)

TESTS = test_utils test_json

else

no_test_framework:
	@echo "test program cannot be built because test framework (libcmocka) was not found"
	@false

test_json test_oci test_ocifs test_utils: no_test_framework

endif
