
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = connman.conf

sbin_PROGRAMS = connmand

connmand_SOURCES = main.c connman.h log.c selftest.c error.c plugin.c \
			profile.c element.c device.c network.c connection.c \
			security.c resolver.c storage.c manager.c agent.c \
			detect.c rtnl.c dbus.c

if UDEV
connmand_SOURCES += udev.c

rulesdir = $(sysconfdir)/udev/rules.d

rules_DATA = 92-connman.rules
endif

connmand_LDADD = @GDBUS_LIBS@ @GLIB_LIBS@ @UDEV_LIBS@ -ldl

connmand_LDFLAGS = -Wl,--export-dynamic -Wl,--version-script=connman.ver

connmand_DEPENDENCIES = connman.ver

CLEANFILES = connman.ver connman.exp 92-connman.rules

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

EXTRA_DIST = $(dbus_DATA) connman.rules

MAINTAINERCLEANFILES = Makefile.in

connman.exp: $(connmand_OBJECTS)
	nm -B *.o | awk '{ print $$3 }' | sort -u | grep -E -e '^connman_' > $@

connman.ver: connman.exp
	echo "{ global:" > $@
	cat $< | sed -e "s/\(.*\)/\1;/" >> $@
	echo "local: *; };" >> $@

92-connman.rules: connman.rules
	cp $< $@
