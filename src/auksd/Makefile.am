LIBAUKSAPI		=	../api/auks/libauksapi.la

dist_sbin_SCRIPTS       =       aukspriv

sbin_PROGRAMS           =       auksd auksdrenewer

auksd_SOURCES		=	auksd.c auksd_req.c auksd_req.h
auksd_CPPFLAGS		=	$(AM_CPPFLAGS) -I$(srcdir)/../api
auksd_LDADD		=	$(LIBAUKSAPI)
auksd_LDFLAGS		=	$(LIB_LDFLAGS) -lkrb5 -pthread

auksdrenewer_SOURCES	=	auksdrenewer.c
auksdrenewer_CPPFLAGS	=	$(AM_CPPFLAGS) -I$(srcdir)/../api
auksdrenewer_LDADD	=	$(LIBAUKSAPI)
auksdrenewer_LDFLAGS	=	$(LIB_LDFLAGS) -lkrb5
