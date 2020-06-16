# evaluate systemd availability
%if 0%{?fedora} >= 17 || 0%{?rhel} >= 7
%global _with_systemd 1
%else
%global _with_systemd 0
%endif


Summary: Aside Utility for Kerberos Support
Name: auks
Version: 0.5.0
Release: 1%{?dist}
License: CeCILL-C License
Group: System Environment/Base
URL: http://sourceforge.net/projects/auks/
Source0: %{name}-%{version}.tar.gz


# For kerberos prior to 1.8, you should define
# -DLIBKRB5_MEMORY_LEAK_WORKAROUND in the configure
# to activate a workaround in auks that corrects a memory
# leak in replay cache management
Requires: krb5-libs >= 1.8
BuildRequires: krb5-devel >= 1.8
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool

%if 0%{?_with_systemd}
# Required for %%post, %%preun, %%postun
Requires:       systemd
%if 0%{?fedora} >= 18 || 0%{?rhel} >= 7
BuildRequires:  systemd
%else
BuildRequires:  systemd-units
%endif
%else
# Required for %%post and %%preun
Requires:       chkconfig
# Required for %%preun and %%postun
Requires:       initscripts
%endif

%if 0%{?fedora} >= 28 || 0%{?rhel} >= 8
BuildRequires: libtirpc-devel
Requires: libtirpc
%endif

#  set default _auks_sysconfdir to /etc/auks
%{!?_auks_sysconfdir: %global _auks_sysconfdir /etc/auks}

# Compiled with slurm plugin as default (disable using --without slurm)
%bcond_without slurm

%description
Auks is an open source project that helps Batch Systems to provide
Kerberos Credential Support.
Auks is not an authentication system. It only enables to set up
a trusted remote cache system for storage and retrieval of kerberos
TGT.

%package devel
Summary: Development package for AUKS.
Group: Development/System
Requires: auks
%description devel
Development package for AUKS.  This package includes the header files
for the AUKS API.

%if %{with slurm}
%package slurm
Summary: Slurm plugins for Auks
Group: System Environment/Base
Requires: slurm >= 1.3.0
Requires: auks >= %{version}
BuildRequires: slurm-devel >= 1.3.0
%description slurm
Plugins that provides Kerberos Credential Support to Slurm
%endif

%prep
%setup -q


%build
autoreconf -fvi
%configure CFLAGS="${CFLAGS} -DSYSCONFDIR=\\\"%{_auks_sysconfdir}\\\"" %{?with_slurm:--with-slurm}
make %{?_smp_mflags}

%install
make install DESTDIR="$RPM_BUILD_ROOT"

# Delete unpackaged files:
rm -f %{buildroot}%{_libdir}/*.{a,la}
%if %{with slurm}
rm -f %{buildroot}%{_libdir}/slurm/*.{a,la}
%endif

%if 0%{?_with_systemd}
# Systemd for fedora >= 17 or el 7
%{__install} -d -m0755  %{buildroot}%{_unitdir}
install -Dp -m0644 etc/auksd.service %{buildroot}%{_unitdir}/auksd.service
install -Dp -m0644 etc/auksdrenewer.service %{buildroot}%{_unitdir}/auksdrenewer.service
install -Dp -m0644 etc/aukspriv.service %{buildroot}%{_unitdir}/aukspriv.service
%else
# Otherwise init.d for fedora < 17 or el 5, 6
install -Dp -m0755 etc/init.d.auksd %{buildroot}%{_initrddir}/auksd
install -Dp -m0755 etc/init.d.auksdrenewer %{buildroot}%{_initrddir}/auksdrenewer
install -Dp -m0755 etc/init.d.aukspriv %{buildroot}%{_initrddir}/aukspriv
%endif
install -D -m0644 etc/logrotate.d.auks $RPM_BUILD_ROOT/etc/logrotate.d/auks
install -D -m0644 etc/auks.conf.example ${RPM_BUILD_ROOT}%{_auks_sysconfdir}/auks.conf.example
install -D -m0644 etc/auks.acl.example ${RPM_BUILD_ROOT}%{_auks_sysconfdir}/auks.acl.example

mkdir -pm 0700 ${RPM_BUILD_ROOT}%{_localstatedir}/cache/auks

%if %{with slurm}
install -D -m644 src/plugins/slurm/slurm-spank-auks.conf ${RPM_BUILD_ROOT}/etc/slurm/plugstack.conf.d/auks.conf.example
%endif

%files
%defattr(-,root,root,-)
%{_libdir}/libauksapi.so.*
%{_bindir}/*
%{_sbindir}/*
%{_auks_sysconfdir}/auks.conf.example
%{_auks_sysconfdir}/auks.acl.example
%if 0%{?_with_systemd}
%{_unitdir}/auksd.service
%{_unitdir}/auksdrenewer.service
%{_unitdir}/aukspriv.service
%else
%{_initrddir}/auksd
%{_initrddir}/auksdrenewer
%{_initrddir}/aukspriv
%endif
%config(noreplace) /etc/logrotate.d/auks
%{_localstatedir}/cache/auks
%{_mandir}/man1/auks.1.gz
%{_mandir}/man5/auks.acl.5.gz
%{_mandir}/man5/auks.conf.5.gz
%{_mandir}/man8/auksd.8.gz
%{_mandir}/man8/auksdrenewer.8.gz
%{_mandir}/man8/aukspriv.8.gz

%files devel
%{_includedir}/*
%{_libdir}/libauksapi.so

%if %{with slurm}
%files slurm
%defattr(-,root,root,-)
/etc/slurm/plugstack.conf.d/auks.conf.example
%{_libdir}/slurm/auks.so
%{_mandir}/man8/auks.so.8*
%endif

%changelog
* Tue Jun 16 2020 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.5.0-1
- Add libtirpc(-devel) requirements for RHEL>8 and Fedora > 28
- Add /var/cache/auks directory creation
* Wed Nov 18 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.4-1
- Correct a regression resulting in badly located initscripts
* Mon Oct 19 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.3-3
- Integrate Systemd init scripts for auks components
* Fri Mar 27 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.3-2
- spec file cleanup
* Fri Mar 27 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.3-1
- CentOS-7.x compatible version
* Thu Jan 29 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.2-4
- no longer explicitely remove -fstack-protector (it was required to
  cope with a strange behavior when linking against the kerberos lib
  (krb5-libs-1.6.1-25.el5)
* Wed Jan 28 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.2-3
- spec file cleaning & refactoring
* Tue Jan 27 2015 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.2-2
- spec file cleaning
* Tue Mar 10 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.1-2
- Minor bug corrections
* Tue Feb 24 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.1-1
- Initial build.
