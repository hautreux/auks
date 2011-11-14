Summary: Aside Utility for Kerberos Support
Name: auks
Version: 0.4.0
Release: 1
License: CeCILL-C License
Group: System Environment/Base
URL: http://
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

### Thanks to slurm packagers
#
%define auks_with_opt() %{expand:%%{!?_without_%{1}:%%global auks_with_%{1} 1}}
%define auks_without_opt() %{expand:%%{?_with_%{1}:%%global auks_with_%{1} 1}}
%define auks_with() %{expand:%%{?auks_with_%{1}:1}%%{!?auks_with_%{1}:0}}
#
#  Allow override of sysconfdir via _auks_sysconfdir.
%{!?_auks_sysconfdir: %global _auks_sysconfdir /etc/auks}
%define _sysconfdir %_auks_sysconfdir
#
# Should unpackaged files in a build root terminate a build?
# Note: The default value should be 0 for legacy compatibility.
%define _unpackaged_files_terminate_build      0
#
###

# Compiled with slurm plugin as default (disable using --without slurm)
%auks_with_opt slurm

%description
Auks is an open source project that helps Batch Systems to provide 
Kerberos Credential Support.
Auks is not an authentication system. It only enables to set up
a trusted remote cache system for storage and retrieval of kerberos
TGT.
It currently provides a spank plugin for slurm.

%package devel
Summary: Development package for AUKS.
Group: Development/System
Requires: auks
%description devel
Development package for AUKS.  This package includes the header files
for the AUKS API.

%if %{auks_with slurm}
%package slurm
Summary: Slurm plugins for Auks
Group: System Environment/Base
# For kerberos prior to 1.8, you should define 
# -DLIBKRB5_MEMORY_LEAK_WORKAROUND in the configure
# to activate a workaround in auks that corrects a memory
# leak in replay cache management
Requires: slurm >= 1.3.0 auks >= 0.3.1 krb5-libs >= 1.8
%description slurm
Plugins that provides Kerberos Credential Support to Slurm
%endif

%prep
%setup -n %{name}-%{version}

%build
autoreconf -fvi
## ensure that stack-protector is not set (gcc-4.1.2-14.el5)
## bad interaction between krb5 (krb5-libs-1.6.1-25.el5) and this feature
%configure CFLAGS="$(echo $RPM_OPT_FLAGS | %{__sed} 's/-fstack-protector//')" \
	--program-prefix=%{?_program_prefix:%{_program_prefix}} \
	%{?auks_with_slurm:--with-slurm}

make %{?_smp_mflags} 

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p "$RPM_BUILD_ROOT"
DESTDIR="$RPM_BUILD_ROOT" make install

# Delete unpackaged files:
rm -f $RPM_BUILD_ROOT/%{_libdir}/*.{a,la}
%if %{auks_with slurm}
rm -f $RPM_BUILD_ROOT/%{_libdir}/slurm/*.{a,la}
%endif

if [ -d /etc/init.d ]; then
   install -D -m755 etc/init.d.auksd $RPM_BUILD_ROOT/etc/init.d/auksd
   install -D -m755 etc/init.d.auksdrenewer $RPM_BUILD_ROOT/etc/init.d/auksdrenewer
   install -D -m755 etc/init.d.aukspriv $RPM_BUILD_ROOT/etc/init.d/aukspriv
fi
if [ -d /etc/logrotate.d ]; then
   install -D -m755 etc/logrotate.d.auks    $RPM_BUILD_ROOT/etc/logrotate.d/auks
fi
install -D -m644 etc/auks.conf.example  ${RPM_BUILD_ROOT}%{_sysconfdir}/auks.conf.example
install -D -m644 etc/auks.acl.example ${RPM_BUILD_ROOT}%{_sysconfdir}/auks.acl.example
install -D -m644 src/plugins/slurm/slurm-spank-auks.conf ${RPM_BUILD_ROOT}/etc/slurm/plugstack.conf.d/auks.conf.example

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libauksapi.so*
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

%if %{auks_with slurm}
%files slurm
%defattr(-,root,root,-)
/etc/slurm/plugstack.conf.d/auks.conf.example
%{_libdir}/slurm/auks.so
%{_mandir}/man8/auks.so.8*
%endif

%post
if [ ! -d /var/cache/auks ]; then
	mkdir -m 0700 /var/cache/auks
fi

%changelog
* Thu Oct 07 2010  Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.4.0-1
* Wed Apr  1 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.5-1
* Fri Mar 27 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.4-1
* Thu Mar 26 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.3-1
* Tue Mar 10 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.1-2
- Minor bug corrections
* Tue Feb 24 2009 Matthieu Hautreux <matthieu.hautreux@cea.fr> - 0.3.1-1
- Initial build.
