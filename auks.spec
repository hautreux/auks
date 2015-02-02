Summary: Aside Utility for Kerberos Support
Name: auks
Version: 0.4.2
Release: 4%{?dist}
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

#  Allow override of sysconfdir via _auks_sysconfdir.
%{!?_auks_sysconfdir: %global _auks_sysconfdir /etc/auks}
%define _sysconfdir %_auks_sysconfdir

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
Requires: auks >= 0.3.1
BuildRequires: slurm-devel >= 1.3.0
%description slurm
Plugins that provides Kerberos Credential Support to Slurm
%endif

%prep
%setup -q

%build
autoreconf -fvi
%configure --program-prefix=%{?_program_prefix:%{_program_prefix}} %{?with_slurm:--with-slurm}
make %{?_smp_mflags}

%install
DESTDIR="$RPM_BUILD_ROOT" make install

# Delete unpackaged files:
rm -f $RPM_BUILD_ROOT/%{_libdir}/*.{a,la}
%if %{with slurm}
rm -f $RPM_BUILD_ROOT/%{_libdir}/slurm/*.{a,la}
%endif

install -D -m755 etc/init.d.auksd $RPM_BUILD_ROOT/etc/init.d/auksd
install -D -m755 etc/init.d.auksdrenewer $RPM_BUILD_ROOT/etc/init.d/auksdrenewer
install -D -m755 etc/init.d.aukspriv $RPM_BUILD_ROOT/etc/init.d/aukspriv
install -D -m755 etc/logrotate.d.auks $RPM_BUILD_ROOT/etc/logrotate.d/auks

install -D -m644 etc/auks.conf.example ${RPM_BUILD_ROOT}%{_sysconfdir}/auks.conf.example
install -D -m644 etc/auks.acl.example ${RPM_BUILD_ROOT}%{_sysconfdir}/auks.acl.example

mkdir -pm 0700 ${RPM_BUILD_ROOT}%{_localstatedir}/cache/auks

%if %{with slurm}
install -D -m644 src/plugins/slurm/slurm-spank-auks.conf ${RPM_BUILD_ROOT}/etc/slurm/plugstack.conf.d/auks.conf.example
%endif

%files
%defattr(-,root,root,-)
%{_libdir}/libauksapi.so.*
%{_bindir}/*
%{_sbindir}/*
%{_sysconfdir}/auks.conf.example
%{_sysconfdir}/auks.acl.example
/etc/init.d/auksd
/etc/init.d/auksdrenewer
/etc/init.d/aukspriv
/etc/logrotate.d/auks
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
