
initdir = $(sysconfdir)/init.d

init_SCRIPTS = connman

dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = fi.epitest.hostap.WPASupplicant.conf

servicedir = $(datadir)/dbus-1/system-services

service_DATA = fi.epitest.hostap.WPASupplicant.service

DISTCLEANFILES = $(init_SCRIPTS) $(service_DATA)

scriptdir = $(libdir)/connman/scripts

script_DATA = dhclient.conf

script_PROGRAMS = dhclient-script

dhclient_script_LDADD = @DBUS_LIBS@

AM_CFLAGS = @DBUS_CFLAGS@

EXTRA_DIST = $(script_DATA) $(dbus_DATA)

MAINTAINERCLEANFILES = Makefile.in
