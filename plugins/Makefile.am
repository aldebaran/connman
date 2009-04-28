
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES =

builtin_modules =
builtin_sources =
builtin_cflags =

if LOOPBACK
if LOOPBACK_BUILTIN
builtin_modules += loopback
builtin_sources += loopback.c
else
plugin_LTLIBRARIES += loopback.la
endif
endif

if ETHERNET
if ETHERNET_BUILTIN
builtin_modules += ethernet
builtin_sources += ethernet.c inet.h inet.c
else
plugin_LTLIBRARIES += ethernet.la
ethernet_la_SOURCES = ethernet.c inet.h inet.c
endif
endif

if WIFI
if WIFI_BUILTIN
builtin_modules += wifi
builtin_sources += wifi.c inet.h inet.c supplicant.h supplicant.c
else
plugin_LTLIBRARIES += wifi.la
wifi_la_SOURCES = wifi.c inet.h inet.c supplicant.h supplicant.c
wifi_la_LIBADD = @GDBUS_LIBS@
endif
endif

if BLUETOOTH
if BLUETOOTH_BUILTIN
builtin_modules += bluetooth
builtin_sources += bluetooth.c inet.h inet.c
else
plugin_LTLIBRARIES += bluetooth.la
bluetooth_la_SOURCES = bluetooth.c inet.h inet.c
bluetooth_la_LIBADD = @GDBUS_LIBS@
endif
endif

if MODEMMGR
plugin_LTLIBRARIES += modemmgr.la
modemmgr_la_LIBADD = @GDBUS_LIBS@
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
udhcp_la_CFLAGS = $(AM_CFLAGS) -DUDHCPC=\"@UDHCPC@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"
endif

if DHCLIENT
plugin_LTLIBRARIES += dhclient.la
dhclient_la_SOURCES = dhclient.c inet.h inet.c
dhclient_la_CFLAGS = $(AM_CFLAGS) -DDHCLIENT=\"@DHCLIENT@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"
endif

if PPPD
plugin_LTLIBRARIES += pppd.la
pppd_la_CFLAGS = $(AM_CFLAGS) -DPPPD=\"@PPPD@\"
endif

if RESOLVCONF
if RESOLVCONF_BUILTIN
builtin_modules += resolvconf
builtin_sources += resolvconf.c
builtin_cflags += -DRESOLVCONF=\"@RESOLVCONF@\"
else
plugin_LTLIBRARIES += resolvconf.la
resolvconf_la_CFLAGS = $(AM_CFLAGS) -DRESOLVCONF=\"@RESOLVCONF@\"
endif
endif

if DNSPROXY
if DNSPROXY_BUILTIN
builtin_modules += dnsproxy
builtin_sources += dnsproxy.c
else
plugin_LTLIBRARIES += dnsproxy.la
endif
endif

if POLKIT
plugin_LTLIBRARIES += polkit.la
polkit_la_LIBADD = @POLKIT_LIBS@ @GLIB_LIBS@
polkit_la_CFLAGS = $(AM_CFLAGS) @POLKIT_CFLAGS@

if DATAFILES
policydir = @POLKIT_DATADIR@

policy_DATA = connman.policy
endif
endif

if IOSPM
plugin_LTLIBRARIES += iospm.la
endif

if IWMXSDK
plugin_LTLIBRARIES += iwmxsdk.la
iwmxsdk_la_SOURCES = iwmxsdk.c inet.h inet.c
iwmxsdk_la_LIBADD = @IWMXSDK_LIBS@ @GLIB_LIBS@
iwmxsdk_la_CFLAGS = $(AM_CFLAGS) @IWMXSDK_CFLAGS@
endif

if FAKE
plugin_LTLIBRARIES += fake.la
endif

noinst_LTLIBRARIES = libbuiltin.la

libbuiltin_la_SOURCES = $(builtin_sources)
libbuiltin_la_LDFLAGS =
libbuiltin_la_CFLAGS = $(AM_CFLAGS) $(builtin_cflags) -DCONNMAN_PLUGIN_BUILTIN

BUILT_SOURCES = builtin.h

nodist_libbuiltin_la_SOURCES = $(BUILT_SOURCES)

AM_LDFLAGS = -no-undefined -module -avoid-version

statedir = $(localstatedir)/run/connman

if MAINTAINER_MODE
scriptdir = $(abs_top_srcdir)/scripts
else
scriptdir = $(libdir)/connman/scripts
endif

AM_CFLAGS = -fvisibility=hidden @GLIB_CFLAGS@ @GDBUS_CFLAGS@

INCLUDES = -I$(top_builddir)/include

CLEANFILES = $(BUILT_SOURCES) connman.policy

EXTRA_DIST = polkit.policy

MAINTAINERCLEANFILES = Makefile.in

builtin.h:
	echo "" > $@
	list='$(builtin_modules)'; for i in $$list; \
	  do echo "extern struct connman_plugin_desc __connman_builtin_$$i;" >> $@; done
	echo "" >> $@
	echo "static struct connman_plugin_desc *__connman_builtin[] = {" >> $@
	list='$(builtin_modules)'; for i in $$list; \
	  do echo "&__connman_builtin_$$i," >> $@; done
	echo "NULL };" >> $@

connman.policy: polkit.policy
	cp $< $@
