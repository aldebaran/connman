
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = connman.conf

servicedir = $(datarootdir)/dbus-1/system-services

service_DATA = connman.service

DISTCLEANFILES = $(service_DATA)

sbin_PROGRAMS = connmand

connmand_SOURCES = main.c connman.h log.c manager.c agent.c plugin.c \
			iface.c iface-storage.c iface-helper.c iface-inet.c \
					network.c rtnl.c dhcp.c resolver.c

connmand_LDADD = @HAL_LIBS@ @GDBUS_LIBS@ @GMODULE_LIBS@
 
statedir = $(localstatedir)/run/connman

storagedir = $(localstatedir)/lib/connman

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins/.libs
else
plugindir = $(libdir)/connman/plugins
endif

AM_CFLAGS = @GMODULE_CFLAGS@ @GDBUS_CFLAGS@ @HAL_CFLAGS@ \
			-DSTATEDIR=\""$(statedir)"\" \
			-DSTORAGEDIR=\""$(storagedir)\"" \
			-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_builddir)/include

EXTRA_DIST = $(dbus_DATA)

MAINTAINERCLEANFILES = Makefile.in
