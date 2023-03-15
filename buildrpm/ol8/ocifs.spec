#
# Copyright (c) 2023, Oracle and/or its affiliates.
#
# Licensed under the Universal Permissive License v 1.0
# as shown at https://oss.oracle.com/licenses/upl/
#

Name:		ocifs
Version:	1.1.0
Release:	1%{?dist}
Summary:	Filesystem for OCI Object Storage
Source:		%{name}-%{version}.tar.bz2

License:	Universal Permissive License (UPL), Version 1.0

BuildRequires:	autoconf automake make gcc libasan
BuildRequires:	pkgconfig(cmocka) pkgconfig(jansson) pkgconfig(fuse)
BuildRequires:	pkgconfig(libcurl) pkgconfig(openssl)
Requires:	jansson fuse fuse-libs libcurl openssl-libs

%description
Filesystem for Oracle Cloud Infrastructure (OCI) Object Storage.

%prep
%setup -q

%build
autoreconf --install
%{_configure} --prefix=/usr
%{make_build}

%install
%{make_install}

%check
%{__make} check

%files
%doc %{_mandir}/man1/%{name}.1.gz
%license LICENSE.txt
%license THIRD_PARTY_LICENSE.txt
%{_bindir}/%{name}

%changelog
* Thu May 04 2023 Alexandre Chartre <alexandre.chartre@oracle.com> - 1.1.0-1
- Initial release
