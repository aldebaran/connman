
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES = ethernet.la wifi.la bluetooth.la \
				netdev.la dhclient.la ipv4.la \
				resolvconf.la resolvfile.la rtnllink.la

ethernet_la_SOURCES = ethernet.c

wifi_la_SOURCES = wifi.c inet.h inet.c supplicant.h supplicant.c

bluetooth_la_SOURCES = bluetooth.c
bluetooth_la_LIBADD = @GDBUS_LIBS@

netdev_la_SOURCES = netdev.c

dhclient_la_SOURCES = dhclient.c
dhclient_la_CFLAGS = @GLIB_CFLAGS@ @GDBUS_CFLAGS@ -DDHCLIENT=\"@DHCLIENT@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"

ipv4_la_SOURCES = ipv4.c

resolvconf_la_SOURCES = resolvconf.c inet.h inet.c

resolvfile_la_SOURCES = resolvfile.c

rtnllink_la_SOURCES = rtnllink.c

if HAL
plugin_LTLIBRARIES += hal.la

hal_la_SOURCES = hal.c
hal_la_LIBADD = @HAL_LIBS@
hal_la_CFLAGS = @GLIB_CFLAGS@ @HAL_CFLAGS@
endif

if POLKIT
plugin_LTLIBRARIES += polkit.la

polkit_la_SOURCES = polkit.c
polkit_la_LIBADD = @POLKIT_LIBS@ @GLIB_LIBS@
polkit_la_CFLAGS = @GLIB_CFLAGS@ @POLKIT_CFLAGS@

policydir = $(datadir)/PolicyKit/policy

policy_DATA = connman.policy
endif

AM_LDFLAGS = -no-undefined -module -avoid-version \
				-export-symbols-regex connman_plugin_desc

statedir = $(localstatedir)/run/connman

if MAINTAINER_MODE
scriptdir = $(abs_top_srcdir)/scripts
else
scriptdir = $(libdir)/connman/scripts
endif

AM_CFLAGS = @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_builddir)/include

EXTRA_DIST = connman.policy

MAINTAINERCLEANFILES = Makefile.in
