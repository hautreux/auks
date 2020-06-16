noinst_HEADERS		=	xerror.h xlogger.h \
				xstream.h xqueue.h \
				xmessage.h xfreelist.h \
				xlibrary.h

noinst_LTLIBRARIES	=       libxternal.la

libxternal_la_CPPFLAGS	=	$(AM_CPPFLAGS) -pthread
libxternal_la_SOURCES	=       xlogger.c xstream.c \
				xmessage.c xqueue.c \
				xfreelist.c xlibrary.c  
libxternal_la_LDFLAGS	=       $(LIB_LDFLAGS) $(LIBTIRPC) -pthread
