
AM_MAKEFLAGS = --no-print-directory

includedir = @includedir@/connman

include_HEADERS = include/types.h include/log.h include/plugin.h \
			include/notifier.h \
			include/storage.h include/service.h \
			include/resolver.h include/ipconfig.h \
			include/device.h include/network.h include/inet.h \
			include/ondemand.h

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/driver.h include/element.h include/property.h \
			include/rtnl.h include/wifi.h include/task.h \
			include/dbus.h include/rfkill.h include/option.h \
			include/profile.h include/provider.h include/dhcp.h \
			include/utsname.h include/timeserver.h include/proxy.h \
			include/location.h include/technology.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/connman/$(notdir $(file)))


gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

gdhcp_sources = gdhcp/gdhcp.h gdhcp/common.h gdhcp/common.c gdhcp/client.c \
		gdhcp/server.c gdhcp/ipv4ll.h gdhcp/ipv4ll.c

gweb_sources = gweb/gweb.h gweb/gweb.c gweb/gresolv.h gweb/gresolv.c \
					gweb/giognutls.h gweb/giognutls.c

if DATAFILES
dbusconfdir = @DBUS_CONFDIR@

dbusconf_DATA = src/connman.conf

if SYSTEMD
systemdunitdir = @SYSTEMD_UNITDIR@

systemdunit_DATA = src/connman.service
endif
endif

plugin_LTLIBRARIES =

plugin_objects =

builtin_modules =
builtin_sources =
builtin_libadd =
builtin_cflags =

noinst_PROGRAMS =

sbin_PROGRAMS = src/connmand

src_connmand_SOURCES = $(gdbus_sources) $(gdhcp_sources) \
			gweb/gweb.h gweb/gweb.c \
			gweb/gresolv.h gweb/gresolv.c \
			gweb/giognutls.h gweb/gionotls.c \
			$(builtin_sources) src/connman.ver \
			src/main.c src/connman.h src/log.c \
			src/error.c src/plugin.c src/task.c src/element.c \
			src/device.c src/network.c src/connection.c \
			src/manager.c src/profile.c src/service.c \
			src/agent.c src/notifier.c src/provider.c \
			src/resolver.c src/ipconfig.c src/detect.c src/inet.c \
			src/ipv4.c src/dhcp.c src/rtnl.c src/proxy.c \
			src/utsname.c src/timeserver.c src/rfkill.c \
			src/wifi.c src/storage.c src/dbus.c src/config.c \
			src/technology.c src/counter.c src/location.c \
			src/session.c src/tethering.c src/ondemand.c \
			src/wpad.c src/wispr.c src/stats.c src/iptables.c \
			src/dnsproxy.c

src_connmand_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ \
				@CAPNG_LIBS@ @XTABLES_LIBS@ -lresolv -ldl

src_connmand_LDFLAGS = -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/connman.ver

CLEANFILES = src/connman.conf src/builtin.h $(local_headers)

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

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ @CAPNG_CFLAGS@ @XTABLES_CFLAGS@ \
				@NETLINK_CFLAGS@ @GNUTLS_CFLAGS@ \
				$(builtin_cflags) \
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
noinst_PROGRAMS += tools/wispr tools/wifi-scan tools/supplicant-test \
			tools/dhcp-test tools/dhcp-server-test \
			tools/addr-test tools/web-test tools/resolv-test \
			tools/dbus-test tools/polkit-test \
			tools/iptables-test tools/tap-test tools/wpad-test \
			tools/stats-tool

tools_wispr_SOURCES = $(gweb_sources) tools/wispr.c
tools_wispr_LDADD = @GLIB_LIBS@ @GNUTLS_LIBS@ -lresolv

tools_wifi_scan_LDADD = @GLIB_LIBS@ @NETLINK_LIBS@

tools_supplicant_test_SOURCES = $(gdbus_sources) tools/supplicant-test.c \
			tools/supplicant-dbus.h tools/supplicant-dbus.c \
			tools/supplicant.h tools/supplicant.c
tools_supplicant_test_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

tools_web_test_SOURCES = $(gweb_sources) tools/web-test.c
tools_web_test_LDADD = @GLIB_LIBS@ @GNUTLS_LIBS@ -lresolv

tools_resolv_test_SOURCES = gweb/gresolv.h gweb/gresolv.c tools/resolv-test.c
tools_resolv_test_LDADD = @GLIB_LIBS@ -lresolv

tools_wpad_test_SOURCES = gweb/gresolv.h gweb/gresolv.c tools/wpad-test.c
tools_wpad_test_LDADD = @GLIB_LIBS@ -lresolv

tools_stats_tool_LDADD = @GLIB_LIBS@

tools_dhcp_test_SOURCES = $(gdhcp_sources) tools/dhcp-test.c
tools_dhcp_test_LDADD = @GLIB_LIBS@

tools_dhcp_server_test_SOURCES = $(gdhcp_sources) tools/dhcp-server-test.c
tools_dhcp_server_test_LDADD = @GLIB_LIBS@

tools_dbus_test_SOURCES = $(gdbus_sources) tools/dbus-test.c
tools_dbus_test_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

tools_polkit_test_LDADD = @DBUS_LIBS@

tools_iptables_test_LDADD = @GLIB_LIBS@ @XTABLES_LIBS@
endif

test_scripts = test/get-state test/list-profiles test/list-services \
		test/connect-service test/monitor-services \
		test/set-address test/test-profile \
		test/simple-agent test/show-introspection test/test-compat \
		test/test-manager test/test-connman test/monitor-connman \
		test/connect-vpn test/disconnect-vpn test/monitor-manager \
		test/test-counter test/set-ipv4-method test/set-ipv6-method \
		test/set-nameservers test/set-domains test/find-service \
		test/get-services test/get-proxy-autoconfig test/set-proxy \
		test/enable-tethering test/disable-tethering test/backtrace

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

EXTRA_DIST += $(test_scripts)

EXTRA_DIST += doc/overview-api.txt doc/behavior-api.txt \
				doc/ipconfig-api.txt doc/plugin-api.txt \
				doc/manager-api.txt doc/agent-api.txt \
				doc/profile-api.txt doc/service-api.txt \
				doc/technology-api.txt doc/counter-api.txt \
				doc/advanced-configuration.txt \
				doc/config-format.txt

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = connman.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc \
				--disable-datafiles \
				--enable-loopback \
				--enable-ethernet \
				--enable-wifi \
				--enable-bluetooth \
				--enable-ofono \
				--enable-pacrunner \
				--enable-google \
				--enable-meego \
				--enable-client \
				--enable-portal \
				--enable-hh2serial-gps \
				--enable-ntpd \
				--enable-openconnect \
				--enable-tools

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs


src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

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

clean-local:
	@$(RM) -rf include/connman
