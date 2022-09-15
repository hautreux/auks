
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src etc doc

EXTRA_DIST    =	auks.spec build-aux/git-version-gen

.PHONY = force


BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@


force:

tar: force
	git archive --prefix $(PACKAGE_NAME)-$(PACKAGE_VERSION)/ HEAD | gzip -c > $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

rpm: tar force
	test -d .rpmbuild/SOURCES || mkdir -p .rpmbuild/SOURCES/
	ln -sf $(PWD)/$(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz .rpmbuild/SOURCES/
	rpmbuild --define '_topdir $(PWD)/.rpmbuild' -ba $(PACKAGE_NAME).spec
	find $(PWD)/.rpmbuild -type f -iname '*.rpm' -exec cp {} . \;
