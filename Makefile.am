
AM_MAKEFLAGS = --no-print-directory

includedir = @includedir@/connman

include_HEADERS = include/types.h include/log.h include/plugin.h \
			include/notifier.h include/service.h \
			include/resolver.h include/ipconfig.h \
			include/device.h include/network.h include/inet.h \
			include/storage.h

nodist_include_HEADERS = include/version.h

noinst_HEADERS = include/rtnl.h include/task.h \
			include/dbus.h include/option.h \
			include/provider.h \
			include/utsname.h include/timeserver.h include/proxy.h \
			include/technology.h include/setting.h

local_headers = $(foreach file,$(include_HEADERS) $(nodist_include_HEADERS) \
			$(noinst_HEADERS), include/connman/$(notdir $(file)))


gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

gdhcp_sources = gdhcp/gdhcp.h gdhcp/common.h gdhcp/common.c gdhcp/client.c \
		gdhcp/server.c gdhcp/ipv4ll.h gdhcp/ipv4ll.c

gweb_sources = gweb/gweb.h gweb/gweb.c gweb/gresolv.h gweb/gresolv.c

if WISPR
gweb_sources += gweb/giognutls.h gweb/giognutls.c
else
gweb_sources += gweb/giognutls.h gweb/gionotls.c
endif

if DATAFILES

if NMCOMPAT
nmcompat_conf = plugins/connman-nmcompat.conf
endif

dbusconfdir = @DBUS_CONFDIR@

dbusconf_DATA = src/connman.conf $(nmcompat_conf)

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

unit_objects =

sbin_PROGRAMS = src/connmand

src_connmand_SOURCES = $(gdbus_sources) $(gdhcp_sources) $(gweb_sources) \
			$(builtin_sources) src/connman.ver \
			src/main.c src/connman.h src/log.c \
			src/error.c src/plugin.c src/task.c \
			src/device.c src/network.c src/connection.c \
			src/manager.c src/service.c \
			src/clock.c src/timezone.c \
			src/agent.c src/notifier.c src/provider.c \
			src/resolver.c src/ipconfig.c src/detect.c src/inet.c \
			src/dhcp.c src/dhcpv6.c src/rtnl.c src/proxy.c \
			src/utsname.c src/timeserver.c src/rfkill.c \
			src/storage.c src/dbus.c src/config.c \
			src/technology.c src/counter.c src/ntp.c \
			src/session.c src/tethering.c src/wpad.c src/wispr.c \
			src/stats.c src/iptables.c src/dnsproxy.c src/6to4.c \
			src/ippool.c src/bridge.c src/nat.c

src_connmand_LDADD = $(builtin_libadd) @GLIB_LIBS@ @DBUS_LIBS@ \
				@XTABLES_LIBS@ @GNUTLS_LIBS@ -lresolv -ldl

src_connmand_LDFLAGS = -Wl,--export-dynamic \
				-Wl,--version-script=$(srcdir)/src/connman.ver

BUILT_SOURCES = $(local_headers) src/builtin.h

CLEANFILES = src/connman.conf $(BUILT_SOURCES)

statedir = $(localstatedir)/run/connman

plugindir = $(libdir)/connman/plugins

scriptdir = $(libdir)/connman/scripts

storagedir = $(localstatedir)/lib/connman

configdir = ${sysconfdir}/connman

if MAINTAINER_MODE
build_plugindir = $(abs_top_srcdir)/plugins/.libs
build_scriptdir = $(abs_top_srcdir)/scripts
else
build_plugindir = $(plugindir)
build_scriptdir = $(scriptdir)
endif

AM_CFLAGS = @DBUS_CFLAGS@ @GLIB_CFLAGS@ @XTABLES_CFLAGS@ \
				@GNUTLS_CFLAGS@ $(builtin_cflags) \
				-DCONNMAN_PLUGIN_BUILTIN \
				-DSTATEDIR=\""$(statedir)"\" \
				-DPLUGINDIR=\""$(build_plugindir)"\" \
				-DSCRIPTDIR=\""$(build_scriptdir)"\" \
				-DSTORAGEDIR=\""$(storagedir)\"" \
				-DCONFIGDIR=\""$(configdir)\""

INCLUDES = -I$(builddir)/include -I$(builddir)/src -I$(srcdir)/gdbus

EXTRA_DIST = src/genbuiltin src/connman-dbus.conf src/connman-polkit.conf \
						plugins/connman-nmcompat.conf


script_DATA =
script_PROGRAMS =
script_LTLIBRARIES =

include Makefile.plugins

if CLIENT
noinst_PROGRAMS += client/cm

client_cm_SOURCES = client/main.c
client_cm_LDADD = @DBUS_LIBS@
endif

if WISPR
noinst_PROGRAMS += tools/wispr

tools_wispr_SOURCES = $(gweb_sources) tools/wispr.c
tools_wispr_LDADD = @GLIB_LIBS@ @GNUTLS_LIBS@ -lresolv
endif

if TOOLS
noinst_PROGRAMS += tools/supplicant-test \
			tools/dhcp-test tools/dhcp-server-test \
			tools/addr-test tools/web-test tools/resolv-test \
			tools/dbus-test tools/polkit-test \
			tools/iptables-test tools/tap-test tools/wpad-test \
			tools/stats-tool tools/private-network-test \
			unit/test-session unit/test-ippool unit/test-nat

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

tools_private_network_test_LDADD = @GLIB_LIBS@ @DBUS_LIBS@

unit_test_session_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
		unit/test-session.c unit/utils.c unit/manager-api.c \
		unit/session-api.c unit/test-connman.h
unit_test_session_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl
unit_objects += $(unit_test_session_OBJECTS)

unit_test_ippool_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
		 src/ippool.c unit/test-ippool.c
unit_test_ippool_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ -ldl
unit_objects += $(unit_test_ippool_OBJECTS)

unit_test_nat_SOURCES = $(gdbus_sources) src/log.c src/dbus.c \
		src/iptables.c  src/nat.c unit/test-nat.c
unit_test_nat_LDADD = @GLIB_LIBS@ @DBUS_LIBS@  @XTABLES_LIBS@ -ldl
unit_objects += $(unit_nat_ippool_OBJECTS)
endif

test_scripts = test/get-state test/list-services \
		test/monitor-services test/test-clock \
		test/simple-agent test/show-introspection test/test-compat \
		test/test-manager test/test-connman test/monitor-connman \
		test/connect-vpn test/disconnect-vpn \
		test/test-counter test/set-ipv4-method test/set-ipv6-method \
		test/get-services test/get-proxy-autoconfig test/set-proxy \
		test/enable-tethering test/disable-tethering test/backtrace \
		test/test-session test/test-supplicant \
		test/test-new-supplicant test/service-move-before \
		test/set-global-timeservers test/get-global-timeservers \
		test/set-nameservers test/set-domains

if TEST
testdir = $(pkglibdir)/test
test_SCRIPTS = $(test_scripts)
endif

EXTRA_DIST += $(test_scripts)

EXTRA_DIST += doc/overview-api.txt doc/behavior-api.txt \
				doc/ipconfig-api.txt doc/plugin-api.txt \
				doc/manager-api.txt doc/agent-api.txt \
				doc/service-api.txt doc/technology-api.txt \
				doc/counter-api.txt doc/config-format.txt \
				doc/clock-api.txt doc/session-api.txt \
				doc/session-overview.txt doc/backtrace.txt \
				doc/advanced-configuration.txt


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = connman.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc \
				--disable-datafiles \
				--enable-hh2serial-gps \
				--enable-openconnect \
				--enable-openvpn \
				--enable-vpnc \
				--enable-nmcompat \
				--enable-polkit

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs


src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

src/connman.conf: src/connman-dbus.conf src/connman-polkit.conf
if POLKIT
	$(AM_V_GEN)cp $(srcdir)/src/connman-polkit.conf $@
else
	$(AM_V_GEN)cp $(srcdir)/src/connman-dbus.conf $@
endif

include/connman/version.h: include/version.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $(abs_top_builddir)/$< $@

include/connman/%.h: $(abs_top_srcdir)/include/%.h
	$(AM_V_at)$(MKDIR_P) include/connman
	$(AM_V_GEN)$(LN_S) $< $@

clean-local:
	@$(RM) -rf include/connman
