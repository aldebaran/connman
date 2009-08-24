
AM_MAKEFLAGS = --no-print-directory

includedir = @includedir@/connman

include_HEADERS = include/types.h include/log.h include/plugin.h \
			include/security.h include/notifier.h \
			include/storage.h include/service.h \
			include/device.h include/network.h include/inet.h

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/driver.h include/element.h include/property.h \
			include/rtnl.h include/wifi.h include/task.h \
			include/dbus.h include/rfkill.h include/option.h \
			include/resolver.h include/ipconfig.h \
			include/profile.h include/provider.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/connman/$(notdir $(file)))


gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/object.c gdbus/watch.c

if DATAFILES
dbusdir = @DBUS_DATADIR@

dbus_DATA = src/connman.conf
endif

plugin_LTLIBRARIES =

plugin_objects =

builtin_modules =
builtin_sources =
builtin_libadd =
builtin_cflags =

noinst_PROGRAMS =

sbin_PROGRAMS = src/connmand

src_connmand_SOURCES = $(gdbus_sources) $(builtin_sources) \
			src/main.c src/connman.h src/log.c src/selftest.c \
			src/error.c src/plugin.c src/task.c src/element.c \
			src/device.c src/network.c src/connection.c \
			src/manager.c src/profile.c src/service.c \
			src/agent.c src/notifier.c src/provider.c \
			src/security.c src/resolver.c src/ipconfig.c \
			src/ipv4.c src/storage.c src/rfkill.c src/rtnl.c \
			src/inet.c src/wifi.c src/dbus.c

if UDEV
src_connmand_SOURCES += src/udev.c
else
src_connmand_SOURCES += src/udev-compat.c
endif

src_connmand_LDADD = $(builtin_libadd) @GLIB_LIBS@ @GTHREAD_LIBS@ \
						@DBUS_LIBS@ @UDEV_LIBS@ -ldl

src_connmand_LDFLAGS = -Wl,--export-dynamic -Wl,--version-script=src/connman.ver

src_connmand_DEPENDENCIES = src/connman.ver

CLEANFILES = src/connman.ver src/connman.exp src/connman.conf \
						src/builtin.h $(local_headers)

statedir = $(localstatedir)/run/connman

plugindir = $(libdir)/connman/plugins

scriptdir = $(libdir)/connman/scripts

storagedir = $(localstatedir)/lib/connman

if MAINTAINER_MODE
build_plugindir = $(abs_top_srcdir)/plugins/.libs
build_scriptdir = $(abs_top_srcdir)/scripts
else
build_plugindir = $(plugindir)
build_scriptdir = $(scriptdir)
endif

AM_CFLAGS = @UDEV_CFLAGS@ @NETLINK_CFLAGS@ @DBUS_CFLAGS@ \
		@GLIB_CFLAGS@ @GTHREAD_CFLAGS@ $(builtin_cflags) \
				-DCONNMAN_PLUGIN_BUILTIN \
				-DSTATEDIR=\""$(statedir)"\" \
				-DPLUGINDIR=\""$(build_plugindir)"\" \
				-DSCRIPTDIR=\""$(build_scriptdir)"\" \
				-DSTORAGEDIR=\""$(storagedir)\""

INCLUDES = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

EXTRA_DIST = src/genbuiltin src/connman-dbus.conf src/connman-polkit.conf


script_DATA =
script_PROGRAMS =
script_LTLIBRARIES =

include Makefile.plugins

if CLIENT
noinst_PROGRAMS += client/cm

client_cm_SOURCES = client/main.c
client_cm_LDADD = @DBUS_LIBS@
endif

if TOOLS
noinst_PROGRAMS += tools/wifi-scan tools/addr-test tools/tap-test

tools_wifi_scan_LDADD = @GLIB_LIBS@ @NETLINK_LIBS@
endif

EXTRA_DIST += test/get-state test/list-profiles test/list-services \
		test/connect-service test/list-connections \
		test/select-connection test/list-devices test/enable-device \
		test/disable-device test/start-scanning test/list-networks \
		test/set-passphrase test/set-address test/test-profile \
		test/simple-agent test/show-introspection test/test-compat \
		test/test-manager test/test-connman test/monitor-connman \
		test/monitor-services test/debug-connman

EXTRA_DIST += doc/overview-api.txt doc/behavior-api.txt \
				doc/ipconfig-api.txt doc/plugin-api.txt \
				doc/manager-api.txt doc/agent-api.txt \
				doc/profile-api.txt doc/service-api.txt \
				doc/device-lowlevel-api.txt \
				doc/network-lowlevel-api.txt \
				doc/connection-lowlevel-api.txt

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = connman.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc \
				--disable-datafiles \
				--enable-loopback \
				--enable-ethernet \
				--enable-wifi \
				--enable-bluetooth \
				--enable-ofono \
				--enable-udhcp \
				--enable-dhclient \
				--enable-resolvconf \
				--enable-dnsproxy \
				--enable-novatel \
				--enable-huawei \
				--enable-hso \
				--enable-mbm \
				--enable-udev \
				--enable-polkit \
				--enable-client \
				--enable-tools

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs


src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

src/connman.exp: $(src_connmand_OBJECTS)
	$(AM_V_GEN)$(NM) $^ | $(AWK) '{ print $$3 }' | sort -u | \
				$(EGREP) -e '^connman_' -e '^g_dbus_' > $@

src/connman.ver: src/connman.exp
	$(AM_V_at)echo "{ global:" > $@
	$(AM_V_GEN)$(SED) -e "s/\(.*\)/\1;/" $< >> $@
	$(AM_V_at)echo "local: *; };" >> $@

src/connman.conf: src/connman-dbus.conf src/connman-polkit.conf
if POLKIT
	$(AM_V_GEN)cp $(srcdir)/src/connman-polkit.conf $@
else
	$(AM_V_GEN)cp $(srcdir)/src/connman-dbus.conf $@
endif

$(src_connmand_OBJECTS) $(plugin_objects): $(local_headers)

include/connman/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/connman/%.h: include/%.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $(abs_top_srcdir)/$< $@

clean-local: include/connman
	@$(RM) -r $<
