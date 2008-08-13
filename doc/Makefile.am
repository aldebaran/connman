
DOC_MODULE = connman

DOC_MAIN_SGML_FILE = $(DOC_MODULE)-docs.xml

DOC_SOURCE_DIR = ../src

MKDB_OPTIONS = --sgml-mode --output-format=xml --tmpl-dir=.

MKTMPL_OPTIONS = --output-dir=.

HFILE_GLOB = $(top_srcdir)/include/*.h
CFILE_GLOB = $(top_srcdir)/src/*.c

IGNORE_HFILES = config.h connman.h

HTML_IMAGES =

content_files = version.xml connman-introduction.xml

INCLUDES = -I$(top_srcdir) $(GLIB_CFLAGS) $(DBUS_CFLAGS)

GTKDOC_LIBS =

MAINTAINERCLEANFILES = Makefile.in \
	$(DOC_MODULE).types $(DOC_MODULE)-*.sgml $(DOC_MODULE)-*.txt

include $(top_srcdir)/doc/gtk-doc.make

EXTRA_DIST += manager-api.txt element-api.txt agent-api.txt plugin-api.txt
