
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES = hal.la ethernet.la bluetooth.la dhclient.la ipv4.la \
					80203.la 80211.la resolvconf.la

hal_la_SOURCES = hal.c
hal_la_LIBADD = @HAL_LIBS@
hal_la_CFLAGS = @GLIB_CFLAGS@ @HAL_CFLAGS@

ethernet_la_SOURCES = ethernet.c

bluetooth_la_SOURCES = bluetooth.c

dhclient_la_SOURCES = dhclient.c
dhclient_la_CFLAGS = @GDBUS_CFLAGS@ -DDHCLIENT=\"@DHCLIENT@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"

ipv4_la_SOURCES = ipv4.c

80203_la_SOURCES = 80203.c

80211_la_SOURCES = 80211.c supplicant.h supplicant.c

resolvconf_la_SOURCES = resolvconf.c

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
