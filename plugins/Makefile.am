
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES =

builtin_modules =
builtin_sources =
builtin_libadd =
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
builtin_sources += ethernet.c
else
plugin_LTLIBRARIES += ethernet.la
endif
endif

if WIFI
if WIFI_BUILTIN
builtin_modules += wifi
builtin_sources += wifi.c supplicant.h supplicant.c
else
plugin_LTLIBRARIES += wifi.la
wifi_la_SOURCES = wifi.c supplicant.h supplicant.c
wifi_la_LIBADD = @GDBUS_LIBS@
endif
endif

if BLUETOOTH
if BLUETOOTH_BUILTIN
builtin_modules += bluetooth
builtin_sources += bluetooth.c
else
plugin_LTLIBRARIES += bluetooth.la
bluetooth_la_LIBADD = @GDBUS_LIBS@
endif
endif

if OFONO
if OFONO_BUILTIN
builtin_modules += ofono
builtin_sources += ofono.c
else
plugin_LTLIBRARIES += ofono.la
ofono_la_LIBADD = @GDBUS_LIBS@
endif
endif

if MODEMMGR
if MODEMMGR_BUILTIN
builtin_modules += modemmgr
builtin_sources += modemmgr.c
else
plugin_LTLIBRARIES += modemmgr.la
modemmgr_la_LIBADD = @GDBUS_LIBS@
endif
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
if HSO_BUILTIN
builtin_modules += hso
builtin_sources += hso.c modem.h modem.c
builtin_libadd += @GATCHAT_LIBS@
builtin_cflags += @GATCHAT_CFLAGS@
else
plugin_LTLIBRARIES += hso.la
hso_la_SOURCES = hso.c modem.h modem.c
hso_la_LIBADD = @GATCHAT_LIBS@
hso_la_CFLAGS = $(AM_CFLAGS) @GATCHAT_CFLAGS@
endif
endif

if MBM
if MBM_BUILTIN
builtin_modules += mbm
builtin_sources += mbm.c
builtin_libadd += @GATCHAT_LIBS@
builtin_cflags += @GATCHAT_CFLAGS@
else
plugin_LTLIBRARIES += mbm.la
mbm_la_LIBADD = @GATCHAT_LIBS@
mbm_la_CFLAGS = $(AM_CFLAGS) @GATCHAT_CFLAGS@
endif
endif

if UDHCP
if UDHCP_BUILTIN
builtin_modules += udhcp
builtin_sources += udhcp.c task.h task.c
builtin_cflags += -DUDHCPC=\"@UDHCPC@\"
else
plugin_LTLIBRARIES += udhcp.la
udhcp_la_SOURCES = udhcp.c task.h task.c
udhcp_la_CFLAGS = $(AM_CFLAGS) -DUDHCPC=\"@UDHCPC@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"
endif
endif

if DHCLIENT
if DHCLIENT_BUILTIN
builtin_modules += dhclient
builtin_sources += dhclient.c
builtin_cflags += -DDHCLIENT=\"@DHCLIENT@\"
else
plugin_LTLIBRARIES += dhclient.la
dhclient_la_CFLAGS = $(AM_CFLAGS) -DDHCLIENT=\"@DHCLIENT@\" \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"
endif
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
if POLKIT_BUILTIN
builtin_modules += polkit
builtin_sources += polkit.c
builtin_libadd += @POLKIT_LIBS@
builtin_cflags += @POLKIT_CFLAGS@
else
plugin_LTLIBRARIES += polkit.la
polkit_la_LIBADD = @POLKIT_LIBS@ @GLIB_LIBS@
polkit_la_CFLAGS = $(AM_CFLAGS) @POLKIT_CFLAGS@
endif

if DATAFILES
policydir = @POLKIT_DATADIR@

policy_DATA = connman.policy
endif
endif

if IWMX
plugin_LTLIBRARIES += iwmxsdk.la
iwmxsdk_la_SOURCES = iwmx.h iwmx.c iwmxsdk.c
iwmxsdk_la_LIBADD = @IWMXSDK_LIBS@ @GLIB_LIBS@
iwmxsdk_la_CFLAGS = $(AM_CFLAGS) @IWMXSDK_CFLAGS@
endif

if IOSPM
plugin_LTLIBRARIES += iospm.la
endif

if FAKE
plugin_LTLIBRARIES += fake.la
endif

noinst_LTLIBRARIES = libbuiltin.la

libbuiltin_la_SOURCES = $(builtin_sources)
libbuiltin_la_LIBADD = $(builtin_libadd)
libbuiltin_la_CFLAGS = $(AM_CFLAGS) \
		$(builtin_cflags) -DCONNMAN_PLUGIN_BUILTIN \
		-DSTATEDIR=\""$(statedir)"\" -DSCRIPTDIR=\""$(scriptdir)"\"

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
	$(AM_V_at)echo "" > $@
	$(AM_V_GEN)list='$(builtin_modules)'; for i in $$list; \
	  do echo "extern struct connman_plugin_desc __connman_builtin_$$i;" >> $@; done
	$(AM_V_at)echo "" >> $@
	$(AM_V_at)echo "static struct connman_plugin_desc *__connman_builtin[] = {" >> $@
	$(AM_V_at)list='$(builtin_modules)'; for i in $$list; \
	  do echo "&__connman_builtin_$$i," >> $@; done
	$(AM_V_at)echo "NULL };" >> $@

connman.policy: polkit.policy
if POLKIT
	$(AM_V_GEN)cp $< $@
endif
