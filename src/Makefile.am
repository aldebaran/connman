
if DATAFILES
dbusdir = @DBUS_DATADIR@

dbus_DATA = connman.conf
endif

sbin_PROGRAMS = connmand

connmand_SOURCES = main.c connman.h log.c selftest.c error.c plugin.c \
			element.c device.c network.c connection.c \
			manager.c profile.c service.c agent.c notifier.c \
			security.c resolver.c ipconfig.c rfkill.c \
			storage.c ipv4.c detect.c rtnl.c inet.c dbus.c

if UDEV
connmand_SOURCES += udev.c
endif

connmand_LDADD = $(top_builddir)/plugins/libbuiltin.la \
		@GDBUS_LIBS@ @GLIB_LIBS@ @GTHREAD_LIBS@ @UDEV_LIBS@ -ldl

connmand_LDFLAGS = -Wl,--export-dynamic -Wl,--version-script=connman.ver

connmand_DEPENDENCIES = connman.ver $(top_builddir)/plugins/libbuiltin.la

CLEANFILES = connman.ver connman.exp connman.conf

statedir = $(localstatedir)/run/connman

storagedir = $(localstatedir)/lib/connman

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins/.libs
else
plugindir = $(libdir)/connman/plugins
endif

AM_CFLAGS = @UDEV_CFLAGS@ @GTHREAD_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@ \
					-DSTATEDIR=\""$(statedir)"\" \
					-DPLUGINDIR=\""$(plugindir)"\" \
					-DSTORAGEDIR=\""$(storagedir)\""

INCLUDES = -I$(top_builddir)/include -I$(top_builddir)/plugins

EXTRA_DIST = connman-dbus.conf connman-polkit.conf

MAINTAINERCLEANFILES = Makefile.in

connman.exp: $(connmand_OBJECTS)
	nm -B *.o | awk '{ print $$3 }' | sort -u | grep -E -e '^connman_' > $@

connman.ver: connman.exp
	echo "{ global:" > $@
	cat $< | sed -e "s/\(.*\)/\1;/" >> $@
	echo "local: *; };" >> $@

connman.conf: connman-dbus.conf connman-polkit.conf
if POLKIT
	cp $(top_srcdir)/src/connman-polkit.conf $@
else
	cp $(top_srcdir)/src/connman-dbus.conf $@
endif
