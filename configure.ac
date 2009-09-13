AC_PREREQ(2.60)
AC_INIT(connman, 0.42)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_CONFIG_HEADER(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_FLAGS

AC_SUBST(abs_top_srcdir)
AC_SUBST(abs_top_builddir)

AC_LANG_C

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_PIE
AC_PROG_INSTALL
AC_PROG_SED
AC_PROG_AWK
AM_PROG_MKDIR_P

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_PROG_NM

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

GTK_DOC_CHECK

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

AC_ARG_ENABLE(threads,
	AC_HELP_STRING([--enable-threads], [enable threading support]),
			[enable_threads=${enableval}], [enable_threads="no"])

AC_ARG_ENABLE(ethernet,
	AC_HELP_STRING([--enable-ethernet], [enable Ethernet support]),
			[enable_ethernet=${enableval}], [enable_ethernet="no"])
AM_CONDITIONAL(ETHERNET, test "${enable_ethernet}" != "no")
AM_CONDITIONAL(ETHERNET_BUILTIN, test "${enable_ethernet}" = "builtin")

AC_ARG_ENABLE(wifi,
	AC_HELP_STRING([--enable-wifi], [enable WiFi support]),
			[enable_wifi=${enableval}], [enable_wifi="no"])
if (test "${enable_wifi}" != "no"); then
	AC_PATH_PROG(WPASUPPLICANT, [wpa_supplicant], [],
						$PATH:/sbin:/usr/sbin)
fi
AM_CONDITIONAL(WIFI, test "${enable_wifi}" != "no")
AM_CONDITIONAL(WIFI_BUILTIN, test "${enable_wifi}" = "builtin")

AC_ARG_ENABLE(bluetooth,
	AC_HELP_STRING([--enable-bluetooth], [enable Bluetooth support]),
			[enable_bluetooth=${enableval}], [enable_bluetooth="no"])
AM_CONDITIONAL(BLUETOOTH, test "${enable_bluetooth}" != "no")
AM_CONDITIONAL(BLUETOOTH_BUILTIN, test "${enable_bluetooth}" = "builtin")

AC_ARG_ENABLE(ofono,
	AC_HELP_STRING([--enable-ofono], [enable oFono support]),
			[enable_ofono=${enableval}], [enable_ofono="no"])
AM_CONDITIONAL(OFONO, test "${enable_ofono}" != "no")
AM_CONDITIONAL(OFONO_BUILTIN, test "${enable_ofono}" = "builtin")

AC_ARG_ENABLE(modemmgr,
	AC_HELP_STRING([--enable-modemmgr], [enable Modem Manager support]),
			[enable_modemmgr=${enableval}], [enable_modemmgr="no"])
AM_CONDITIONAL(MODEMMGR, test "${enable_modemmgr}" != "no")
AM_CONDITIONAL(MODEMMGR_BUILTIN, test "${enable_modemmgr}" = "builtin")

AC_ARG_WITH(udhcpc, AC_HELP_STRING([--with-udhcpc=PROGRAM],
	[specify location of udhcpc binary]), [path_udhcpc=${withval}])

AC_ARG_ENABLE(udhcp,
	AC_HELP_STRING([--enable-udhcp], [enable uDHCP support]),
			[enable_udhcp=${enableval}], [enable_udhcp="no"])
if (test "${enable_udhcp}" != "no"); then
	if (test -z "${path_udhcpc}"); then
		AC_PATH_PROG(UDHCPC, [udhcpc], [], $PATH:/sbin:/usr/sbin)
	else
		UDHCPC="${path_udhcpc}"
		AC_SUBST(UDHCPC)
	fi
fi
AM_CONDITIONAL(UDHCP, test "${enable_udhcp}" != "no")
AM_CONDITIONAL(UDHCP_BUILTIN, test "${enable_udhcp}" = "builtin")

AC_ARG_WITH(dhclient, AC_HELP_STRING([--with-dhclient=PROGRAM],
	[specify location of dhclient binary]), [path_dhclient=${withval}])

AC_ARG_ENABLE(dhclient,
	AC_HELP_STRING([--enable-dhclient], [enable dhclient support]),
			[enable_dhclient=${enableval}], [enable_dhclient="no"])
if (test "${enable_dhclient}" != "no"); then
	if (test -z "${path_dhclient}"); then
		AC_PATH_PROG(DHCLIENT, [dhclient], [], $PATH:/sbin:/usr/sbin)
	else
		DHCLIENT="${path_dhclient}"
		AC_SUBST(DHCLIENT)
	fi
fi
AM_CONDITIONAL(DHCLIENT, test "${enable_dhclient}" != "no")
AM_CONDITIONAL(DHCLIENT_BUILTIN, test "${enable_dhclient}" = "builtin")

AC_ARG_WITH(resolvconf, AC_HELP_STRING([--with-resolvconf=PROGRAM],
	[specify location of resolvconf binary]), [path_resolvconf=${withval}])

AC_ARG_ENABLE(resolvconf,
	AC_HELP_STRING([--enable-resolvconf], [enable resolvconf support]),
			[enable_resolvconf=${enableval}], [enable_resolvconf="no"])
if (test "${enable_resolvconf}" != "no"); then
	if (test -z "${path_resolvconf}"); then
		AC_PATH_PROG(RESOLVCONF, [resolvconf], [], $PATH:/sbin:/usr/sbin)
	else
		RESOLVCONF="${path_resolvconf}"
		AC_SUBST(RESOLVCONF)
	fi
fi
AM_CONDITIONAL(RESOLVCONF, test "${enable_resolvconf}" != "no")
AM_CONDITIONAL(RESOLVCONF_BUILTIN, test "${enable_resolvconf}" = "builtin")

AC_ARG_ENABLE(loopback,
	AC_HELP_STRING([--enable-loopback], [enable loopback support]),
			[enable_loopback=${enableval}], [enable_loopback="no"])
if (test "${enable_loopback}" != "no"); then
	AC_CHECK_HEADERS(sys/inotify.h, dummy=yes,
			AC_MSG_ERROR(inotify header files are required))

	AC_CHECK_LIB(c, inotify_init, dummy=yes,
			AC_MSG_ERROR(inotify library support is required))
fi
AM_CONDITIONAL(LOOPBACK, test "${enable_loopback}" != "no")
AM_CONDITIONAL(LOOPBACK_BUILTIN, test "${enable_loopback}" = "builtin")

AC_ARG_ENABLE(dnsproxy,
	AC_HELP_STRING([--enable-dnsproxy], [enable DNS proxy support]),
			[enable_dnsproxy=${enableval}], [enable_dnsproxy="no"])
AM_CONDITIONAL(DNSPROXY, test "${enable_dnsproxy}" != "no")
AM_CONDITIONAL(DNSPROXY_BUILTIN, test "${enable_dnsproxy}" = "builtin")

AC_ARG_ENABLE(novatel, AC_HELP_STRING([--enable-novatel],
		[enable Novatel support]), [enable_novatel=${enableval}])
AM_CONDITIONAL(NOVATEL, test "${enable_novatel}" = "yes")

AC_ARG_ENABLE(huawei, AC_HELP_STRING([--enable-huawei],
		[enable HUAWEI support]), [enable_huawei=${enableval}])
AM_CONDITIONAL(HUAWEI, test "${enable_huawei}" = "yes")

AC_ARG_ENABLE(hso,
	AC_HELP_STRING([--enable-hso], [enable HSO support]),
			[enable_hso=${enableval}], [enable_hso="no"])
AM_CONDITIONAL(HSO, test "${enable_hso}" != "no")
AM_CONDITIONAL(HSO_BUILTIN, test "${enable_hso}" = "builtin")

AC_ARG_ENABLE(mbm,
	AC_HELP_STRING([--enable-mbm], [enable MBM support]),
			[enable_mbm=${enableval}], [enable_mbm="no"])
AM_CONDITIONAL(MBM, test "${enable_mbm}" != "no")
AM_CONDITIONAL(MBM_BUILTIN, test "${enable_mbm}" = "builtin")

AC_ARG_WITH(pppd, AC_HELP_STRING([--with-pppd=PROGRAM],
	[specify location of pppd binary]), [path_pppd=${withval}])

AC_ARG_ENABLE(ppp, AC_HELP_STRING([--enable-ppp],
		[enable PPP support]), [enable_ppp=${enableval}])
if (test "${enable_ppp}" = "yes" || test "${enable_novatel}" = "yes" ||
					test "${enable_huawei}" = "yes"); then
	if (test -z "${path_pppd}"); then
		AC_PATH_PROG(PPPD, [pppd], [], $PATH:/sbin:/usr/sbin)
	else
		PPPD="${path_pppd}"
		AC_SUBST(PPPD)
	fi
	AC_CHECK_HEADERS(pppd/pppd.h, enable_ppp=yes,
			AC_MSG_ERROR(PPP development files are required))
fi
AM_CONDITIONAL(PPPD, test "${enable_ppp}" = "yes")

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

AC_ARG_WITH(iwmxsdk, AC_HELP_STRING([--with-iwmxsdk=PATH],
						[path to Intel WiMAX SDK]),
				[pkgconfig_iwmxsdk=${withval}/lib/pkgconfig])

AC_ARG_ENABLE(iwmx, AC_HELP_STRING([--enable-iwmx],
		[enable Intel WiMAX support]), [enable_iwmx=${enableval}])
if (test "${enable_iwmx}" = "yes"); then
	enable_threads="yes"
	export PKG_CONFIG_PATH="${pkgconfig_iwmxsdk}"
	PKG_CHECK_MODULES(IWMXSDK, libiWmxSdk-0, dummy=yes,
				AC_MSG_ERROR(Intel WiMAX SDK is required))
	PKG_CONFIG_PATH=""
	AC_SUBST(IWMXSDK_CFLAGS)
	AC_SUBST(IWMXSDK_LIBS)
fi
AM_CONDITIONAL(IWMX, test "${enable_iwmx}" = "yes")

AC_ARG_ENABLE(iospm, AC_HELP_STRING([--enable-iospm],
		[enable Intel OSPM support]), [enable_iospm=${enableval}])
AM_CONDITIONAL(IOSPM, test "${enable_iospm}" = "yes")

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.16 is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

if (test "${enable_threads}" = "yes"); then
	AC_DEFINE(NEED_THREADS, 1, [Define if threading support is required])
	PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(GThread >= 2.16 is required))
	GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
	GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"
fi

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
				AC_MSG_ERROR(D-Bus >= 1.0 is required))
AC_CHECK_LIB(dbus-1, dbus_watch_get_unix_fd, dummy=yes,
	AC_DEFINE(NEED_DBUS_WATCH_GET_UNIX_FD, 1,
		[Define to 1 if you need the dbus_watch_get_unix_fd() function.]))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_ARG_WITH(dbusconf, AC_HELP_STRING([--with-dbusconf=PATH],
	[path to D-Bus config directory]), [path_dbusconf=${withval}],
		[path_dbusconf="`$PKG_CONFIG --variable=sysconfdir dbus-1`"])
if (test -z "${path_dbusconf}"); then
	DBUS_DATADIR="${sysconfdir}/dbus-1/system.d"
else
	DBUS_DATADIR="${path_dbusconf}/dbus-1/system.d"
fi
AC_SUBST(DBUS_DATADIR)

AC_ARG_ENABLE(polkit,
	AC_HELP_STRING([--enable-polkit], [enable PolicyKit support]),
			[enable_polkit=${enableval}], [enable_polkit="no"])
if (test "${enable_polkit}" != "no"); then
	PKG_CHECK_MODULES(POLKIT, polkit-dbus >= 0.7, dummy=yes,
				AC_MSG_ERROR(PolicyKit >= 0.7 is required))
	AC_SUBST(POLKIT_CFLAGS)
	AC_SUBST(POLKIT_LIBS)
	POLKIT_DATADIR="`$PKG_CONFIG --variable=policydir polkit`"
	if (test -z "${POLKIT_DATADIR}"); then
		POLKIT_DATADIR="${datadir}/PolicyKit/policy"
	fi
	AC_SUBST(POLKIT_DATADIR)
fi
AM_CONDITIONAL(POLKIT, test "${enable_polkit}" != "no")
AM_CONDITIONAL(POLKIT_BUILTIN, test "${enable_polkit}" = "builtin")

AC_ARG_ENABLE(client, AC_HELP_STRING([--enable-client],
		[enable command line client]), [enable_client=${enableval}])
AM_CONDITIONAL(CLIENT, test "${enable_client}" = "yes")

AC_ARG_ENABLE(tools, AC_HELP_STRING([--enable-tools],
		[enable testing tools]), [enable_tools=${enableval}])
if (test "${enable_tools}" = "yes"); then
	PKG_CHECK_MODULES(NETLINK, libnl-1, dummy=yes,
				AC_MSG_ERROR(Netlink library is required))
	AC_SUBST(NETLINK_CFLAGS)
	AC_SUBST(NETLINK_LIBS)
fi
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE(fake, AC_HELP_STRING([--enable-fake],
		[enable fake device support]), [enable_fake=${enableval}])
AM_CONDITIONAL(FAKE, test "${enable_fake}" = "yes")

AC_ARG_ENABLE(udev, AC_HELP_STRING([--disable-udev],
			[don't use udev support even if available]),
						[enable_udev=${enableval}])
if (test "${enable_udev}" != "no"); then
	PKG_CHECK_MODULES(UDEV, libudev >= 141,
				[enable_udev="yes"], [enable_udev="no"])
fi
if (test "${enable_udev}" = "yes"); then
	AC_CHECK_LIB(udev, udev_monitor_filter_update, dummy=yes,
		AC_DEFINE(NEED_UDEV_MONITOR_FILTER, 1,
			[Define to 1 if you need the
					udev_monitor_filter...() functions.]))
	UDEV_DATADIR="`$PKG_CONFIG --variable=udevdir udev`"
	if (test -z "${UDEV_DATADIR}"); then
		UDEV_DATADIR="${sysconfdir}/udev/rules.d"
	else
		UDEV_DATADIR="${UDEV_DATADIR}/rules.d"
	fi
	AC_SUBST(UDEV_DATADIR)
fi
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)
AM_CONDITIONAL(UDEV, test "${enable_udev}" = "yes")

AC_ARG_ENABLE(datafiles, AC_HELP_STRING([--disable-datafiles],
			[don't install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL(DATAFILES, test "${enable_datafiles}" != "no")

AC_OUTPUT(Makefile include/version.h src/connman.service
				scripts/connman doc/version.xml connman.pc)
