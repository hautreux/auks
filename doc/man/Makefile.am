EXTRA_DIST	=	man1 man5 man8


man1_MANS	=	man1/auks.1


man5_MANS	=	man5/auks.conf.5 \
			man5/auks.acl.5

man8_MANS	=	man8/auksd.8 \
			man8/auksdrenewer.8 \
			man8/aukspriv.8

dist-hook:
	-rm -rf `find $(distdir) -name .svn`
