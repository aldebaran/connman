
DOC_MODULE = connman

DOC_MAIN_SGML_FILE = $(DOC_MODULE)-docs.xml

DOC_SOURCE_DIR = ../src

SCAN_OPTIONS = --rebuild-sections --source-dir=../include

MKDB_OPTIONS = --sgml-mode --output-format=xml --tmpl-dir=. \
						--ignore-files=connman \
						--source-dir=../include \
						--source-suffixes=c,h

MKTMPL_OPTIONS = --output-dir=.

HFILE_GLOB = $(top_srcdir)/include/*.h
CFILE_GLOB = $(top_srcdir)/src/*.c $(top_srcdir)/src/*.h

IGNORE_HFILES = connman connman.h rtnl.h dbus.h iface.h

HTML_IMAGES =

content_files = connman-introduction.xml

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/gdbus \
	$(GTHREAD_CFLAGS) $(GMODULE_CFLAGS) $(GLIB_CFLAGS) $(DBUS_CFLAGS)

GTKDOC_LIBS = $(DBUS_LIBS) $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS)

MAINTAINERCLEANFILES = Makefile.in \
	$(DOC_MODULE).types $(DOC_MODULE)-*.txt *.sgml

if ENABLE_GTK_DOC
include $(top_srcdir)/doc/gtk-doc.make

all-local: xml/dbus-manager.xml

xml/dbus-manager.xml : dbus-manager.xml dbus-introspection.xsl
	echo "<?xml version=\"1.0\"?>" > $@
	echo "<!DOCTYPE refentry PUBLIC \"-//OASIS//DTD DocBook XML V4.1.2//EN\" \"http://www.oasis-open.org/docbook/xml/4.1.2/docbookx.dtd\">" >> $@
	$(XSLTPROC) dbus-introspection.xsl $< | tail -n +2 >> $@

else
EXTRA_DIST = $(DOC_MAIN_SGML_FILE) $(content_files)
endif

EXTRA_DIST += dbus-introspection.dtd dbus-introspection.xsl \
		dbus-manager.xml

EXTRA_DIST += manager-api.txt element-api.txt agent-api.txt plugin-api.txt
