
dbusdir = $(sysconfdir)/dbus-1/system.d

dbus_DATA = connman.conf

sbin_PROGRAMS = connmand

connmand_SOURCES = main.c connman.h plugin.c iface.c

connmand_LDADD = @HAL_LIBS@ @GDBUS_LIBS@ @GMODULE_LIBS@
 
if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins
else
plugindir = $(libdir)/connman/plugins
endif

AM_CFLAGS = @GMODULE_CFLAGS@ @GDBUS_CFLAGS@ @HAL_CFLAGS@ \
			-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_builddir)/include

EXTRA_DIST = $(dbus_DATA)

MAINTAINERCLEANFILES = Makefile.in
