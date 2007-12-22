
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = connman.conf

sbin_PROGRAMS = connmand

connmand_SOURCES = main.c connman.h

connmand_LDADD = @GDBUS_LIBS@

AM_CFLAGS = @GDBUS_CFLAGS@

EXTRA_DIST = $(dbus_DATA)

MAINTAINERCLEANFILES = Makefile.in
