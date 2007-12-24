
scriptdir = $(libdir)/connman/scripts

script_DATA = dhclient.conf

script_PROGRAMS = dhclient-script

dhclient_script_LDADD = @DBUS_LIBS@

AM_CFLAGS = @DBUS_CFLAGS@

EXTRA_DIST = $(script_DATA)

MAINTAINERCLEANFILES = Makefile.in
