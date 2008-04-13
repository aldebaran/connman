
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES = libconnman-80203.la libconnman-80211.la \
			libconnman-bluetooth.la \
			libconnman-dhclient.la libconnman-resolvconf.la

libconnman_80203_la_SOURCES = 80203.c

libconnman_80211_la_SOURCES = 80211.c supplicant.h supplicant.c

libconnman_bluetooth_la_SOURCES = bluetooth.c

libconnman_dhclient_la_SOURCES = dhclient.c
libconnman_dhclient_la_LIBADD = @GDBUS_LIBS@
libconnman_dhclient_la_CFLAGS = @GDBUS_CFLAGS@ -DDHCLIENT=\"@DHCLIENT@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"

libconnman_resolvconf_la_SOURCES = resolvconf.c

AM_LDFLAGS = -module -avoid-version -export-symbols-regex connman_plugin_desc

statedir = $(localstatedir)/run/connman

if MAINTAINER_MODE
scriptdir = $(abs_top_srcdir)/scripts
else
scriptdir = $(libdir)/connman/scripts
endif

AM_CFLAGS = @GDBUS_CFLAGS@

INCLUDES = -I$(top_builddir)/include

MAINTAINERCLEANFILES = Makefile.in
