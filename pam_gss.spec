Summary: PAM module for GSS-API
Name: pam_gss
Version: 6
Release: 3%{?dist}
License: LGPL
Group: Applications/System
URL: https://github.com/PADL/pam_gss

%global dist_base pam_gss-master

Source0: https://github.com/PADL/pam_gss/archive/%{dist_base}.zip
Source1: gss-auth
Source2: pam_gss.te
# Temporary until Luke fixes Makefile
Source3: Makefile

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
Kerberos GSS API for authentication in PAM. This module is compiled 
against the MIT Kerberos implementation.

%prep
%setup -q -n %{dist_base}
mkdir SELinux
cp -p %{SOURCE2} SELinux/
# Note: This is temporary until the Makefile is fixed
cp -p %{SOURCE3} .

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
# copy the PAM include
install -d $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/
install -m644 %{SOURCE1} $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/gss-auth
# copy the PAM module into the right folder
install -d $RPM_BUILD_ROOT/%{_lib}/security/
mv $RPM_BUILD_ROOT/usr/lib/pam/pam_gss.so $RPM_BUILD_ROOT/%{_lib}/security/
# compile the SELinux policy for each policy type
for selinuxvariant in %{selinux_variants}
do
  install -d $RPM_BUILD_ROOT/%{_datadir}/selinux/${selinuxvariant}
  install -p -m 644 SELinux/pam_gss.pp.${selinuxvariant} \
    $RPM_BUILD_ROOT/%{_datadir}/selinux/${selinuxvariant}/pam_gss.pp
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
%attr(755,root,root) /%{_lib}/security/pam_gss.so
%attr(644,root,root) %config(noreplace) /etc/pam.d/gss-auth
%defattr(-,root,root,0755)
%doc SELinux/*
%{_datadir}/selinux/*/pam_gss.pp

%changelog
* Wed May  7 2014 Stefan Paetow <stefan.paetow@ja.net> - 6-3
- Tweaks to install the binary into the right location.

* Tue May  6 2014 Stefan Paetow <stefan.paetow@ja.net> - 6-2
- Includes gss-auth file for PAM.

* Fri May  2 2014 Stefan Paetow <stefan.paetow@ja.net> - 6-1
- Updated to version 6.
- Includes and installs SELinux policy.
- Tweaks to the spec.

* Thu May 1 2014 Stefan Paetow <stefan.paetow@ja.net> - 5-1
- Initial build.
