#
# Copyright (c) 2023, Oracle and/or its affiliates.
#
# Licensed under the Universal Permissive License v 1.0
# as shown at https://oss.oracle.com/licenses/upl/
#

#
# OCIFS version and release number
#
m4_define([OCIFS_VERSION], [1.1.0])
m4_define([OCIFS_RELEASE], [1])

AC_INIT([OCIFS], m4_defn([OCIFS_VERSION])[-]m4_defn([OCIFS_RELEASE]))
AM_INIT_AUTOMAKE([foreign])

[OCIFS_VERSION]=OCIFS_VERSION
[OCIFS_RELEASE]=OCIFS_RELEASE
AC_SUBST([OCIFS_VERSION])
AC_SUBST([OCIFS_RELEASE])

AC_PREFIX_DEFAULT([/usr])
AC_PROG_CC
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  tests/Makefile
])

#
# Checks for header files.
#
AC_CHECK_HEADERS([fcntl.h malloc.h stddef.h stdlib.h string.h unistd.h])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_CHECK_HEADER_STDBOOL
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT64_T

#
# Checks for library functions.
#
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero clock_gettime ftruncate regcomp rmdir strchr strdup \
		strerror strndup strrchr strstr])

AC_CHECK_LIB([curl], [curl_global_init], [LIBCURL=-lcurl],
	     [AC_MSG_FAILURE("libcurl not found")])
AC_CHECK_LIB([crypto], [RSA_sign], [LIBCRYPTO=-lcrypto],
	     [AC_MSG_FAILURE("libcrypto not found")])
AC_CHECK_LIB([fuse], [fuse_main], [LIBFUSE=-lfuse],
	     [AC_MSG_FAILURE("libfuse not found")])
AC_CHECK_LIB([jansson], [json_object], [LIBJSON=-ljansson],
	     [AC_MSG_FAILURE("libjansson not found")])
AC_CHECK_LIB([pthread], [pthread_mutex_lock], [LIBPTHREAD=-lpthread],
	     [AC_MSG_FAILURE("libpthread not found")])

AC_SUBST([LIBCURL])
AC_SUBST([LIBCRYPTO])
AC_SUBST([LIBFUSE])
AC_SUBST([LIBJSON])
AC_SUBST([LIBPTHREAD])

AC_CHECK_LIB([cmocka], [_cmocka_run_group_tests], [LIBTEST=-lcmocka],
	     [AC_MSG_WARN(["libcmocka not found, some tests won't be available"])])
AM_CONDITIONAL([TEST_FRAMEWORK], [test -n "$LIBTEST"])
AC_SUBST([LIBTEST])

AC_CHECK_PROG([RPMBUILD_CMD], [rpmbuild], 1, 0)
AM_CONDITIONAL([RPMBUILD], [test ${RPMBUILD_CMD} -eq 1])

#
# Check if rpmbuild has the --build-in-place option. This option is
# available since version 4.13.0.
#
AS_IF([test ${RPMBUILD_CMD} -eq 1],
	    [rpmbuild_version=$(rpmbuild --version | cut -d ' ' -f 3)],
	    [rpmbuild_version="0"])
AX_COMPARE_VERSION([${rpmbuild_version}], [ge], [4.13.0], [rpmbuild_bip=1])
AM_CONDITIONAL([RPMBUILD_BIP], [test "${rpmbuild_bip}" -eq 1])

#
# Check if we are using OpenSSL 3.x
#
AX_COMPARE_VERSION([$(openssl version | awk '{print $2}')], [ge], [3.0.0], [openssl3=1])
AM_CONDITIONAL([OPENSSL3], [test "${openssl3}" -eq 1])

AM_PROG_AR
AC_PROG_RANLIB
#
# AM_PROG_CC_C_O is obsolete since automake 1.14 but requires for the
# build to work with old version of automake.
#
AM_PROG_CC_C_O

AC_OUTPUT
