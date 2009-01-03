
initdir = $(sysconfdir)/init.d

init_SCRIPTS = connman

DISTCLEANFILES = $(init_SCRIPTS)

scriptdir = $(libdir)/connman/scripts

script_DATA = dhclient.conf

script_PROGRAMS =
script_LTLIBRARIES =

if UDHCP
script_PROGRAMS += udhcpc-script

udhcpc_script_LDADD = @DBUS_LIBS@
endif

if DHCLIENT
script_PROGRAMS += dhclient-script

dhclient_script_LDADD = @DBUS_LIBS@
endif

if PPPD
script_LTLIBRARIES += pppd-plugin.la

pppd_plugin_la_LDFLAGS = -module -avoid-version
endif

AM_CFLAGS = @DBUS_CFLAGS@

EXTRA_DIST = $(script_DATA)

MAINTAINERCLEANFILES = Makefile.in
