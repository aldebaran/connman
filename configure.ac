AC_PREREQ(2.60)
AC_INIT()

AM_INIT_AUTOMAKE(connman, 0.15)
AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

GTK_DOC_CHECK

SHAVE_ARG_ENABLE

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g -O0"
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

AC_ARG_ENABLE(threads, AC_HELP_STRING([--enable-threads],
		[enable threading support]), [enable_threads=${enableval}])

AC_ARG_ENABLE(loopback, AC_HELP_STRING([--enable-loopback],
		[enable loopback support]), [enable_loopback=${enableval}])
AM_CONDITIONAL(LOOPBACK, test "${enable_loopback}" != "no")
AM_CONDITIONAL(LOOPBACK_BUILTIN, test "${enable_loopback}" = "builtin")

AC_ARG_ENABLE(ethernet, AC_HELP_STRING([--enable-ethernet],
		[enable Ethernet support]), [enable_ethernet=${enableval}])
AM_CONDITIONAL(ETHERNET, test "${enable_ethernet}" != "no")
AM_CONDITIONAL(ETHERNET_BUILTIN, test "${enable_ethernet}" = "builtin")

AC_ARG_ENABLE(wifi, AC_HELP_STRING([--enable-wifi],
		[enable WiFi support]), [enable_wifi=${enableval}])
if (test "${enable_wifi}" = "yes"); then
	AC_PATH_PROG(WPASUPPLICANT, [wpa_supplicant], [],
						$PATH:/sbin:/usr/sbin)
fi
AM_CONDITIONAL(WIFI, test "${enable_wifi}" != "no")
AM_CONDITIONAL(WIFI_BUILTIN, test "${enable_wifi}" = "builtin")

AC_ARG_ENABLE(bluetooth, AC_HELP_STRING([--enable-bluetooth],
		[enable Bluetooth support]), [enable_bluetooth=${enableval}])
AM_CONDITIONAL(BLUETOOTH, test "${enable_bluetooth}" != "no")
AM_CONDITIONAL(BLUETOOTH_BUILTIN, test "${enable_bluetooth}" = "builtin")

AC_ARG_ENABLE(modemmgr, AC_HELP_STRING([--enable-modemmgr],
                [enable Modem Manager support]), [enable_modemmgr=${enableval}])
AM_CONDITIONAL(MODEMMGR, test "${enable_modemmgr}" = "yes")

AC_ARG_WITH(udhcpc, AC_HELP_STRING([--with-udhcpc=PROGRAM],
	[specify location of udhcpc binary]), [path_udhcpc=${withval}])

AC_ARG_ENABLE(udhcp, AC_HELP_STRING([--enable-udhcp],
		[enable uDHCP support]), [enable_udhcp=${enableval}])
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

AC_ARG_ENABLE(dhclient, AC_HELP_STRING([--enable-dhclient],
		[enable dhclient support]), [enable_dhclient=${enableval}])
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

AC_ARG_ENABLE(resolvconf, AC_HELP_STRING([--enable-resolvconf],
		[enable resolvconf support]), [enable_resolvconf=${enableval}])
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

AC_ARG_ENABLE(dnsproxy, AC_HELP_STRING([--enable-dnsproxy],
		[enable DNS proxy support]), [enable_dnsproxy=${enableval}])
AM_CONDITIONAL(DNSPROXY, test "${enable_dnsproxy}" != "no")
AM_CONDITIONAL(DNSPROXY_BUILTIN, test "${enable_dnsproxy}" = "builtin")

AC_ARG_ENABLE(novatel, AC_HELP_STRING([--enable-novatel],
		[enable Novatel support]), [enable_novatel=${enableval}])
AM_CONDITIONAL(NOVATEL, test "${enable_novatel}" = "yes")

AC_ARG_ENABLE(huawei, AC_HELP_STRING([--enable-huawei],
		[enable HUAWEI support]), [enable_huawei=${enableval}])
AM_CONDITIONAL(HUAWEI, test "${enable_huawei}" = "yes")

AC_ARG_ENABLE(hso, AC_HELP_STRING([--enable-hso],
		[enable HSO support]), [enable_hso=${enableval}])
AM_CONDITIONAL(HSO, test "${enable_hso}" = "yes")

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

AC_CHECK_HEADERS(sys/inotify.h, dummy=yes,
			AC_MSG_ERROR(inotify header files are required))

AC_CHECK_LIB(c, inotify_init, dummy=yes,
			AC_MSG_ERROR(inotify library support is required))

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

AC_ARG_ENABLE(udev, AC_HELP_STRING([--enable-udev],
		[enable udev support]), [enable_udev=${enableval}])
if (test "${enable_udev}" = "yes"); then
	AC_DEFINE(HAVE_UDEV, 1, [Define if udev support is available])
	PKG_CHECK_MODULES(UDEV, libudev >= 129, enable_udev=yes,
				AC_MSG_ERROR(udev >= 129 is required))
	AC_CHECK_LIB(udev, udev_enumerate_add_match_property, dummy=yes,
		AC_DEFINE(NEED_UDEV_ENUMERATE_ADD_MATCH_PROPERTY, 1,
			[Define to 1 if you need the
				udev_enumerate_add_match_property() function.]))
	AC_CHECK_LIB(udev, udev_device_get_parent_with_subsystem_devtype, dummy=yes,
		AC_DEFINE(NEED_UDEV_DEVICE_GET_PARENT_WITH_SUBSYSTEM_DEVTYPE, 1,
			[Define to 1 if you need the
				udev_device_get_parent_with_subsystem_devtype()
									function.]))
	UDEV_DATADIR="`$PKG_CONFIG --variable=rulesdir libudev`"
	if (test -z "${UDEV_DATADIR}"); then
		UDEV_DATADIR="${sysconfdir}/udev/rules.d"
	fi
	AC_SUBST(UDEV_DATADIR)
fi
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)
AM_CONDITIONAL(UDEV, test "${enable_udev}" = "yes")

AC_ARG_ENABLE(iospm, AC_HELP_STRING([--enable-iospm],
		[enable Intel OSPM support]), [enable_iospm=${enableval}])
AM_CONDITIONAL(IOSPM, test "${enable_iospm}" = "yes")

AC_ARG_ENABLE(iwmxsdk, AC_HELP_STRING([--enable-iwmxsdk],
		[enable Intel WiMAX support]), [enable_iwmxsdk=${enableval}])
if (test "${enable_iwmxsdk}" = "yes"); then
	enable_threads="yes"
	PKG_CHECK_MODULES(IWMXSDK, libiWmxSdk-0, enable_iwmxsdk=yes,
				AC_MSG_ERROR(Intel WiMAX SDK is required))
	AC_SUBST(IWMXSDK_CFLAGS)
	AC_SUBST(IWMXSDK_LIBS)
fi
AM_CONDITIONAL(IWMXSDK, test "${enable_iwmxsdk}" = "yes")

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
DBUS_DATADIR="`$PKG_CONFIG --variable=sysconfdir dbus-1`"
if (test -z "{DBUS_DATADIR}"); then
	DBUS_DATADIR="${sysconfdir}/dbus-1/system.d"
else
	DBUS_DATADIR="$DBUS_DATADIR/dbus-1/system.d"
fi
AC_SUBST(DBUS_DATADIR)

AC_SUBST([GDBUS_CFLAGS], ['$(DBUS_CFLAGS) -I$(top_srcdir)/gdbus'])
AC_SUBST([GDBUS_LIBS], ['$(top_builddir)/gdbus/libgdbus.la $(DBUS_LIBS)'])

AC_ARG_ENABLE(polkit, AC_HELP_STRING([--enable-polkit],
		[enable PolicyKit support]), [enable_polkit=${enableval}])
if (test "${enable_polkit}" = "yes"); then
	PKG_CHECK_MODULES(POLKIT, polkit-dbus >= 0.7, enable_polkit=yes,
				AC_MSG_ERROR(PolicyKit >= 0.7 is required))
	AC_SUBST(POLKIT_CFLAGS)
	AC_SUBST(POLKIT_LIBS)
	POLKIT_DATADIR="`$PKG_CONFIG --variable=policydir polkit`"
	if (test -z "${POLKIT_DATADIR}"); then
		POLKIT_DATADIR="${datadir}/PolicyKit/policy"
	fi
	AC_SUBST(POLKIT_DATADIR)
fi
AM_CONDITIONAL(POLKIT, test "${enable_polkit}" = "yes")

AC_ARG_ENABLE(client, AC_HELP_STRING([--enable-client],
		[enable command line client]), [enable_client=${enableval}])
AM_CONDITIONAL(CLIENT, test "${enable_client}" = "yes")

AC_ARG_ENABLE(tools, AC_HELP_STRING([--enable-tools],
                [enable testing tools]), [enable_tools=${enableval}])
if (test "${enable_tools}" = "yes"); then
	PKG_CHECK_MODULES(NETLINK, libnl-1, enable_netlink=yes,
				AC_MSG_ERROR(Netlink library is required))
	AC_SUBST(NETLINK_CFLAGS)
	AC_SUBST(NETLINK_LIBS)
fi
AM_CONDITIONAL(TOOLS, test "${enable_tools}" = "yes")

AC_ARG_ENABLE(fake, AC_HELP_STRING([--enable-fake],
		[enable fake device support]), [enable_fake=${enableval}])
AM_CONDITIONAL(FAKE, test "${enable_fake}" = "yes")

AC_ARG_ENABLE(datafiles, AC_HELP_STRING([--disable-datafiles],
			[don't install configuration and data files]),
					[enable_datafiles=${enableval}])
AM_CONDITIONAL(DATAFILES, test "${enable_datafiles}" != "no")

SHAVE_INIT

AC_OUTPUT(Makefile gdbus/Makefile include/Makefile include/version.h
				src/Makefile src/connman.service
				scripts/connman scripts/Makefile
				plugins/Makefile client/Makefile
				tools/Makefile test/Makefile
				doc/Makefile doc/version.xml connman.pc)
