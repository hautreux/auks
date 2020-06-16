LIBAUKSAPI		=	../api/auks/libauksapi.la

bin_PROGRAMS            =       auks

auks_SOURCES		=	auks.c
auks_CPPFLAGS		=	$(AM_CPPFLAGS) -I$(srcdir)/../api
auks_LDADD		=	$(LIBAUKSAPI)
auks_LDFLAGS		=	$(LIB_LDFLAGS) -lkrb5 -pthread
