Summary: PAM module for authentication via GSS-API
Name: gssapi-pam-module
Version: 1.0.0
Release: 1%{?dist}

License: GPLv2+ and LGPLv2+
Group: Applications/System
URL: https://github.com/PADL/pam_gss

%global dist_base pam_gss-master

Source0: https://github.com/PADL/pam_gss/archive/%{dist_base}.zip
Source1: Makefile

#BuildRequires: krb5-devel
#BuildRequires: autoconf
#BuildRequires: gdbm-devel
#BuildRequires: openssl
#BuildRequires: openssl-devel
BuildRequires: pam-devel
#BuildRequires: zlib-devel
#BuildRequires: net-snmp-devel
#BuildRequires: net-snmp-utils
#BuildRequires: readline-devel
#BuildRequires: libpcap-devel
#BuildRequires: libtalloc-devel
#BuildRequires: pcre-devel

#Requires: openssl

%description
The GSS-API PAM module provides the functionality necessary to use the 
Kerberos GSS API for authentication in PAM.


%prep
%setup -q -n %{dist_base}
cp -p %{SOURCE1} .
# Note: We explicitly do not make patch backup files because 'make install'

# mistakenly includes the backup files, especially problematic for raddb config files.

#%patch1 -p1
#%patch2 -p1

%build
# Force compile/link options, extra security for network facing daemon
%global _hardened_build 1


make KRB5DIR=/usr

%install
#mkdir -p $RPM_BUILD_ROOT/usr/lib/pam
make install R=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/security
mv $RPM_BUILD_ROOT/usr/lib/pam/pam_gss.so $RPM_BUILD_ROOT/%{_libdir}/security/

%files
%defattr(-,root,root)

# the PAM module
%dir %attr(755,root,root) %{_libdir}/security
%attr(755,root,root) %{_libdir}/security/pam_gss.so

%changelog
* Thu May 1 2014 Stefan Paetow <stefan.paetow@ja.net> - 1.0.0-1
- Initial build.
