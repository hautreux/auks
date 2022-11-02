
if HAVE_PAM

man8_MANS		=	pam_auks.so.8

LIBAUKSAPI		=	../../api/auks/libauksapi.la

pamplugdir		=	/usr/lib64/security

pamplug_LTLIBRARIES	=	pam_auks.la

pam_auks_la_SOURCES	=	pam_auks.c
pam_auks_la_CPPFLAGS	=	-I$(top_srcdir)/src/api $(PAM_CPPFLAGS) \
				-DBINDIR=\"$(bindir)\"
pam_auks_la_LDFLAGS	=	$(PAM_LDFLAGS) -module \
				-avoid-version --export-dynamic --quiet
pam_auks_la_LIBADD	=	$(LIBAUKSAPI)

endif

