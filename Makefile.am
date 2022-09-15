
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src etc doc

EXTRA_DIST    =	auks.spec

.PHONY = force

force:

tar: force
	git archive --prefix $(PACKAGE_NAME)-$(PACKAGE_VERSION)/ HEAD | gzip -c > $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

rpm: tar force
	rpmbuild --define '_topdir $(PWD)/.rpmbuild' -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz
	find $(PWD)/.rpmbuild -type f -iname '*.rpm' -exec cp {} . \;
