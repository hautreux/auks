AM_CPPFLAGS             =       -I$(srcdir)/../api

LIBAUKSAPI		=	../api/auks/libauksapi.la

bin_PROGRAMS            =       auks

auks_SOURCES		=	auks.c
auks_LDADD		=	$(LIBAUKSAPI)
auks_LDFLAGS		=	$(LIB_LDFLAGS) -lkrb5 -pthread
