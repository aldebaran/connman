
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES =

if LOOPBACK
plugin_LTLIBRARIES += loopback.la

loopback_la_SOURCES = loopback.c
endif

if ETHERNET
plugin_LTLIBRARIES += ethernet.la

ethernet_la_SOURCES = ethernet.c inet.h inet.c
endif

if WIFI
plugin_LTLIBRARIES += wifi.la

wifi_la_SOURCES = wifi.c inet.h inet.c supplicant.h supplicant.c
wifi_la_LIBADD = @GDBUS_LIBS@
endif

if WIMAX
plugin_LTLIBRARIES += wimax.la

wimax_la_SOURCES = wimax.c
endif

if BLUETOOTH
plugin_LTLIBRARIES += bluetooth.la

bluetooth_la_SOURCES = bluetooth.c inet.h inet.c
bluetooth_la_LIBADD = @GDBUS_LIBS@
endif

if NOVATEL
plugin_LTLIBRARIES += novatel.la

novatel_la_SOURCES = novatel.c modem.h modem.c
endif

if HUAWEI
plugin_LTLIBRARIES += huawei.la

huawei_la_SOURCES = huawei.c modem.h modem.c
endif

if HSO
plugin_LTLIBRARIES += hso.la

hso_la_SOURCES = hso.c modem.h modem.c
endif

if UDHCP
plugin_LTLIBRARIES += udhcp.la

udhcp_la_SOURCES = udhcp.c inet.h inet.c task.h task.c
udhcp_la_CFLAGS = @GLIB_CFLAGS@ @GDBUS_CFLAGS@ -DUDHCPC=\"@UDHCPC@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"
endif

if DHCLIENT
plugin_LTLIBRARIES += dhclient.la

dhclient_la_SOURCES = dhclient.c inet.h inet.c
dhclient_la_CFLAGS = @GLIB_CFLAGS@ @GDBUS_CFLAGS@ -DDHCLIENT=\"@DHCLIENT@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"
endif

if PPPD
plugin_LTLIBRARIES += pppd.la

pppd_la_SOURCES = pppd.c
pppd_la_CFLAGS = @GLIB_CFLAGS@ -DPPPD=\"@PPPD@\"
endif

if RESOLVCONF
plugin_LTLIBRARIES += resolvconf.la

resolvconf_la_SOURCES = resolvconf.c
resolvconf_la_CFLAGS = @GLIB_CFLAGS@ -DRESOLVCONF=\"@RESOLVCONF@\"
endif

if DNSPROXY
plugin_LTLIBRARIES += dnsproxy.la

dnsproxy_la_SOURCES = dnsproxy.c
endif

if POLKIT
plugin_LTLIBRARIES += polkit.la

polkit_la_SOURCES = polkit.c
polkit_la_LIBADD = @POLKIT_LIBS@ @GLIB_LIBS@
polkit_la_CFLAGS = @GLIB_CFLAGS@ @POLKIT_CFLAGS@

if DATAFILES
policydir = @POLKIT_DATADIR@

policy_DATA = connman.policy
endif
endif

if OSPM
plugin_LTLIBRARIES += ospm.la

polkit_la_SOURCES = ospm.c
polkit_la_CFLAGS = @GDBUS_CFLAGS@
endif

if FAKE
plugin_LTLIBRARIES += fake.la

fake_la_SOURCES = fake.c
endif

AM_LDFLAGS = -no-undefined -module -avoid-version \
				-export-symbols-regex connman_plugin_desc

statedir = $(localstatedir)/run/connman

if MAINTAINER_MODE
scriptdir = $(abs_top_srcdir)/scripts
else
scriptdir = $(libdir)/connman/scripts
endif

AM_CFLAGS = @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_builddir)/include

CLEANFILES = connman.policy

EXTRA_DIST = polkit.policy

MAINTAINERCLEANFILES = Makefile.in

connman.policy: polkit.policy
	cp $< $@
