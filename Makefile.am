#
# Copyright (c) 2023, Oracle and/or its affiliates.
#
# Licensed under the Universal Permissive License v 1.0
# as shown at https://oss.oracle.com/licenses/upl/
#

SUBDIRS = src tests

dist_man_MANS = doc/ocifs.1

EXTRA_DIST = LICENSE.txt THIRD_PARTY_LICENSE.txt \
	buildrpm/ol7/ocifs.spec \
	buildrpm/ol8/ocifs.spec \
	buildrpm/ol9/ocifs.spec

debug:
	(cd src ; make debug)

if RPMBUILD

#
# The RPM spec file is buildrpm/<dist>/ocifs.spec where <dist> is the
# RPM dist value (%{?dist}). If the RPM dist is elN (RHEL) then it is
# changed to olN (Oracle Linux).
#
RPMDIST = $(shell rpm --eval '%{?dist}' | sed 's/^\.// ; s/^el\([0-9]\)/ol\1/')
RPMSPEC = buildrpm/$(RPMDIST)/ocifs.spec

#
# Use the RPM build in place option if it is available. Otherwise
# build the tar.bz2 file and copy it to the RPM sources directory.
#

if RPMBUILD_BIP

BUILD_IN_PLACE = --build-in-place

rpm_prepare: clean
	mkdir -p rpmbuild

else

rpm_prepare: clean
	mkdir -p rpmbuild/SOURCES
	git archive --prefix ocifs-$(OCIFS_VERSION)/ \
		-o rpmbuild/SOURCES/ocifs-$(OCIFS_VERSION).tar HEAD
	bzip2 rpmbuild/SOURCES/ocifs-$(OCIFS_VERSION).tar

endif

rpm: $(RPMSPEC) rpm_prepare
	rpmbuild -bb $(BUILD_IN_PLACE) \
		--define '_topdir $(PWD)/rpmbuild' \
		$(RPMSPEC)

clean-rpm:
	rm -fr rpmbuild

else

rpm:
	@echo "rpm cannot be built because the rpmbuild command was not found"
	@false

clean-rpm:

endif

clean-local: clean-rpm
	rm -f $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz

#
# Print the version environment variables. When invoke from rpmbuild
# (i.e. when RPM_PACKAGE_* variables are set) then check that the
# configure.ac and the RPM spec files are using the same versions
# for the binary and the packaging.
#
check-version:
	@echo
	@echo "Configure Versions:"
	@echo
	@echo " PACKAGE_NAME:    " $(PACKAGE_NAME)
	@echo " PACKAGE_VERSION: " $(PACKAGE_VERSION)
	@echo " PACKAGE_TARNAME: " $(PACKAGE_TARNAME)
	@echo " PACKAGE_STRING:  " $(PACKAGE_STRING)
	@echo
	@echo " OCIFS_VERSION:   " $(OCIFS_VERSION)
	@echo " OCIFS_RELEASE:   " $(OCIFS_RELEASE)
	@echo
	@if [ -n "$(RPM_PACKAGE_VERSION)" -o -n "$(RPM_PACKAGE_RELEASE)" ]; then \
		echo ; \
		echo "RPM Versions:" ; \
		echo ; \
		echo " RPM_PACKAGE_NAME:    " $(RPM_PACKAGE_NAME) ; \
		echo " RPM_PACKAGE_VERSION: " $(RPM_PACKAGE_VERSION) ; \
		echo " RPM_PACKAGE_RELEASE: " $(RPM_PACKAGE_RELEASE) ; \
		echo ; \
		if [ "$(OCIFS_VERSION)" != "$(RPM_PACKAGE_VERSION)" ]; then \
			echo "OCIFS_VERSION and RPM_PACKAGE_VERSION mismatch" ; \
		fi ; \
		release=`echo $(RPM_PACKAGE_RELEASE) | sed 's/\..*//'` ; \
		if [ "$(OCIFS_RELEASE)" != $${release} ]; then \
			echo "OCIFS_RELEASE and RPM_PACKAGE_RELEASE mismatch" ; \
		fi ; \
		[ "$(OCIFS_VERSION)" = "$(RPM_PACKAGE_VERSION)" -a \
		  "$(OCIFS_RELEASE)" = "$${release}" ]; \
	fi

all: check-version
