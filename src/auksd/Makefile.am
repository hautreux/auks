AM_CPPFLAGS             =       -I$(srcdir)/../api -I$(srcdir)/../api

LIBAUKSAPI		=	../api/auks/libauksapi.la

dist_sbin_SCRIPTS       =       aukspriv

sbin_PROGRAMS           =       auksd auksdrenewer

auksd_SOURCES		=	auksd.c auksd_req.c auksd_req.h
auksd_LDADD		=	$(LIBAUKSAPI)
auksd_LDFLAGS		=	$(LIB_LDFLAGS) -lkrb5 -pthread

auksdrenewer_SOURCES	=	auksdrenewer.c
auksdrenewer_LDADD	=	$(LIBAUKSAPI)
auksdrenewer_LDFLAGS	=	$(LIB_LDFLAGS) -lkrb5
