
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES = libconnman-80203.la libconnman-80211.la \
			libconnman-dhclient.la

libconnman_80203_la_SOURCES = 80203.c net.h net.c

libconnman_80211_la_SOURCES = 80211.c net.h net.c

libconnman_dhclient_la_SOURCES = dhclient.c net.h net.c
libconnman_dhclient_la_LIBADD = @GDBUS_LIBS@

AM_LDFLAGS = -module -avoid-version -export-symbols-regex connman_plugin_desc

statedir = $(localstatedir)/run/connman

if MAINTAINER_MODE
scriptdir = $(abs_top_srcdir)/scripts
else
scriptdir = $(libdir)/connman/scripts
endif

AM_CFLAGS = @GDBUS_CFLAGS@ \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"

INCLUDES = -I$(top_builddir)/include

MAINTAINERCLEANFILES = Makefile.in
