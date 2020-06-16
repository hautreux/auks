lib_LTLIBRARIES		=	libauksapi.la

auks_includedir		=	$(includedir)/auks

auks_include_HEADERS	=	auks_api.h auks_error.h \
				auks_engine.h \
				auks_cred.h auks_buffer.h \
				auks_acl.h auks_message.h \
				auks_cred_repo.h

noinst_HEADERS		=	auks_krb5_stream.h auks_krb5_cred.h \
				auks_log.h

libauksapi_la_SOURCES	=	auks_krb5_stream.c auks_krb5_cred.c \
				auks_cred.c auks_cred_repo.c \
				auks_acl.c auks_message.c \
				auks_buffer.c \
				auksd_engine.c auks_engine.c \
				auks_error.c auks_api.c

libauksapi_la_CPPFLAGS	= 	-I../ -pthread \
				-DLOCALSTATEDIR=\"$(localstatedir)\" \
				$(AM_CPPFLAGS)

libauksapi_la_LDFLAGS	= 	$(LIB_LDFLAGS) \
				-version-info 0:1:0 \
				-lkrb5 -pthread

libauksapi_la_LIBADD	= 	../confparse/libconfig_parsing.la \
				../xternal/libxternal.la
