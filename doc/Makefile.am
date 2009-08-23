
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

IGNORE_HFILES = connman connman.h

HTML_IMAGES =

content_files = connman-introduction.xml

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/gdbus \
	$(GTHREAD_CFLAGS) $(GMODULE_CFLAGS) $(GLIB_CFLAGS) $(DBUS_CFLAGS)

GTKDOC_LIBS = $(DBUS_LIBS) $(GLIB_LIBS) $(GMODULE_LIBS) $(GTHREAD_LIBS)

MAINTAINERCLEANFILES = Makefile.in \
	$(DOC_MODULE).types $(DOC_MODULE)-*.txt *.sgml *.bak

if ENABLE_GTK_DOC
include $(top_srcdir)/doc/gtk-doc.make
else
EXTRA_DIST = $(DOC_MAIN_SGML_FILE) connman-introduction.xml
endif
