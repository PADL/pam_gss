Summary: PAM module for authentication via GSS-API
Name: gssapi-pam-module
Version: 1.5.0
Release: 1%{?dist}
License: GPLv2+ and LGPLv2+
Group: Applications/System
URL: https://github.com/PADL/pam_gss

%global dist_base pam_gss-master

Source0: https://github.com/PADL/pam_gss/archive/%{dist_base}.zip
Source1: pam_gss.te
# Temporary until Luke fixes Makefile
Source2: Makefile

BuildRequires: pam-devel, selinux-policy-devel, /usr/share/selinux/devel/policyhelp
Requires(post):   /usr/sbin/semodule, /sbin/restorecon
Requires(postun): /usr/sbin/semodule, /sbin/restorecon

# Get the SELinux policy versions based on the build platform
%{!?_selinux_policy_version: %global _selinux_policy_version %(sed -e 's,.*selinux-policy-\\([^/]*\\)/.*,\\1,' /usr/share/selinux/devel/policyhelp 2>/dev/null)}
%if "%{_selinux_policy_version}" != ""
Requires:      selinux-policy >= %{_selinux_policy_version}
%endif

# Ditto
%global selinux_types %(%{__awk} '/^#[[:space:]]*SELINUXTYPE=/,/^[^#]/ { if ($3 == "-") printf "%s ", $2 }' /etc/selinux/config 2>/dev/null)
%global selinux_variants %([ -z "%{selinux_types}" ] && echo mls targeted || echo %{selinux_types})

%description
The GSS-API PAM module provides the functionality necessary to use the 
Kerberos GSS API for authentication in PAM.

%prep
%setup -q -n %{dist_base}
mkdir SELinux
cp -p %{SOURCE1} SELinux/
# Note: This is temporary until the Makefile is fixed
cp -p %{SOURCE2} .

%build
# Force compile/link options, extra security for network facing daemon
%global _hardened_build 1

# On RHEL, the KRB5 tree is under /usr, not /usr/local
make KRB5DIR=/usr
cd SELinux
for selinuxvariant in %{selinux_variants}
do
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile
  mv pam_gss.pp pam_gss.pp.${selinuxvariant}
  make NAME=${selinuxvariant} -f /usr/share/selinux/devel/Makefile clean
done
cd -

%install
make install R=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/security
mv $RPM_BUILD_ROOT/usr/lib/pam/pam_gss.so $RPM_BUILD_ROOT/%{_libdir}/security/
for selinuxvariant in %{selinux_variants}
do
  install -d %{buildroot}%{_datadir}/selinux/${selinuxvariant}
  install -p -m 644 SELinux/pam_gss.pp.${selinuxvariant} \
    %{buildroot}%{_datadir}/selinux/${selinuxvariant}/pam_gss.pp
done

%post
for selinuxvariant in %{selinux_variants}
do
  /usr/sbin/semodule -s ${selinuxvariant} -i \
    %{_datadir}/selinux/${selinuxvariant}/pam_gss.pp &> /dev/null || :
done

%postun
if [ $1 -eq 0 ] ; then
  for selinuxvariant in %{selinux_variants}
  do
    /usr/sbin/semodule -s ${selinuxvariant} -r pam_gss &> /dev/null || :
  done
fi

%files
%defattr(-,root,root)

# the PAM module
%dir %attr(755,root,root) %{_libdir}/security
%attr(755,root,root) %{_libdir}/security/pam_gss.so
%defattr(-,root,root,0755)
%doc SELinux/*
%{_datadir}/selinux/*/pam_gss.pp

%changelog
* Thu May 1 2014 Stefan Paetow <stefan.paetow@ja.net> - 1.5.0-1
- Initial build.
