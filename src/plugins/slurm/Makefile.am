EXTRA_DIST		=	slurm-spank-auks.conf auks.so.8

if HAVE_SLURM

man8_MANS		=	auks.so.8

LIBAUKSAPI		=	../../api/auks/libauksapi.la

slurmplugdir		=	$(libdir)/slurm

slurmplug_LTLIBRARIES	=	auks.la

auks_la_SOURCES		=	slurm-spank-auks.c
auks_la_CPPFLAGS	=	-I$(top_srcdir)/src/api $(SLURM_CPPFLAGS) \
				$(AM_CPPFLAGS) -DBINDIR=\"$(bindir)\"
auks_la_LDFLAGS		=	$(SLURM_LDFLAGS) -module \
				-avoid-version --export-dynamic
auks_la_LIBADD		=	$(LIBAUKSAPI)

endif
