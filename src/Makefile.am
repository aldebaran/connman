
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = connman.conf

servicedir = $(datarootdir)/dbus-1/system-services

service_DATA = connman.service

DISTCLEANFILES = $(service_DATA)

sbin_PROGRAMS = connmand

connmand_SOURCES = main.c connman.h log.c selftest.c error.c plugin.c \
			profile.c element.c device.c network.c security.c \
			resolver.c storage.c manager.c agent.c rtnl.c dbus.c

if UDEV
connmand_SOURCES += udev.c
endif

connmand_LDADD = @GDBUS_LIBS@ @GLIB_LIBS@ @UDEV_LIBS@ -ldl

connmand_LDFLAGS = -Wl,--export-dynamic -Wl,--version-script=connman.ver

connmand_DEPENDENCIES = connman.ver

CLEANFILES = connman.ver connman.exp

statedir = $(localstatedir)/run/connman

storagedir = $(localstatedir)/lib/connman

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins/.libs
else
plugindir = $(libdir)/connman/plugins
endif

AM_CFLAGS = @UDEV_CFLAGS@ @GLIB_CFLAGS@ @GDBUS_CFLAGS@ \
				-DSTATEDIR=\""$(statedir)"\" \
					-DSTORAGEDIR=\""$(storagedir)\"" \
						-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_builddir)/include

EXTRA_DIST = $(dbus_DATA)

MAINTAINERCLEANFILES = Makefile.in

connman.exp:
	nm -B *.o | awk '{ print $$3 }' | sort -u | grep -E -e '^connman_' > $@

connman.ver: connman.exp
	echo "{ global:" > $@
	cat $< | sed -e "s/\(.*\)/\1;/" >> $@
	echo "local: *; };" >> $@
