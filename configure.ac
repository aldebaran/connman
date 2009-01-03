AC_PREREQ(2.60)
AC_INIT()

AM_INIT_AUTOMAKE(connman, 0.5)
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
AM_CONDITIONAL(LOOPBACK, test "${enable_loopback}" = "yes")

AC_ARG_ENABLE(wifi, AC_HELP_STRING([--enable-wifi],
		[enable WiFi support]), [enable_wifi=${enableval}])
if (test "${enable_wifi}" = "yes"); then
	AC_PATH_PROG(WPASUPPLICANT, [wpa_supplicant], [],
						$PATH:/sbin:/usr/sbin)
fi
AM_CONDITIONAL(WIFI, test "${enable_wifi}" = "yes")

AC_ARG_WITH(udhcpc, AC_HELP_STRING([--with-udhcpc=PROGRAM],
		[Specific udhcpc binary]), [path_udhcpc=${withval}])

AC_ARG_ENABLE(UDHCP, AC_HELP_STRING([--enable-udhcp],
		[enable uDHCP support]), [enable_udhcp=${enableval}])
if (test "${enable_udhcp}" = "yes"); then
	if (test -z "${path_udhcpc}"); then
		AC_PATH_PROG(UDHCPC, [udhcpc], [], $PATH:/sbin:/usr/sbin)
	else
		UDHCPC="${path_udhcpc}"
		AC_SUBST(UDHCPC)
	fi
fi
AM_CONDITIONAL(UDHCP, test "${enable_udhcp}" = "yes")

AC_ARG_WITH(dhclient, AC_HELP_STRING([--with-dhclient=PROGRAM],
		[Specific dhclient binary]), [path_dhclient=${withval}])

AC_ARG_ENABLE(DHCLIENT, AC_HELP_STRING([--enable-dhclient],
		[enable dhclient support]), [enable_dhclient=${enableval}])
if (test "${enable_dhclient}" = "yes"); then
	if (test -z "${path_dhclient}"); then
		AC_PATH_PROG(DHCLIENT, [dhclient], [], $PATH:/sbin:/usr/sbin)
	else
		UDHCPC="${path_dhclient}"
		AC_SUBST(DHCLIENT)
	fi
fi
AM_CONDITIONAL(DHCLIENT, test "${enable_dhclient}" = "yes")

AC_PATH_PROG(RESOLVCONF, [resolvconf], [], $PATH:/sbin:/usr/sbin)

AC_ARG_ENABLE(novatel, AC_HELP_STRING([--enable-novatel],
		[enable Novatel support]), [enable_novatel=${enableval}])
AM_CONDITIONAL(NOVATEL, test "${enable_novatel}" = "yes")

AC_ARG_ENABLE(huawei, AC_HELP_STRING([--enable-huawei],
		[enable HUAWEI support]), [enable_huawei=${enableval}])
AM_CONDITIONAL(HUAWEI, test "${enable_huawei}" = "yes")

AC_ARG_ENABLE(hso, AC_HELP_STRING([--enable-hso],
		[enable HSO support]), [enable_hso=${enableval}])
AM_CONDITIONAL(HSO, test "${enable_hso}" = "yes")

AC_ARG_ENABLE(ppp, AC_HELP_STRING([--enable-ppp],
		[enable PPP support]), [enable_ppp=${enableval}])
if (test "${enable_ppp}" = "yes" || test "${enable_novatel}" = "yes" ||
					test "${enable_huawei}" = "yes"); then
	AC_PATH_PROG(PPPD, [pppd], [], $PATH:/sbin:/usr/sbin)
	AC_CHECK_HEADERS(pppd/pppd.h, enable_ppp=yes,
			AC_MSG_ERROR(PPP development files are required))
fi
AM_CONDITIONAL(PPPD, test "${enable_ppp}" = "yes")

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0, dummy=yes,
				AC_MSG_ERROR(glib is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

if (test "${enable_threads}" = "yes"); then
	AC_DEFINE(NEED_THREADS, 1, [Define if threading support is required])
	PKG_CHECK_MODULES(GTHREAD, gthread-2.0, dummy=yes,
				AC_MSG_ERROR(gthread is required))
	GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
	GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"
fi

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
				AC_MSG_ERROR(libdbus is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_SUBST([GDBUS_CFLAGS], ['$(DBUS_CFLAGS) -I$(top_srcdir)/gdbus'])
AC_SUBST([GDBUS_LIBS], ['$(top_builddir)/gdbus/libgdbus.la $(DBUS_LIBS)'])

AC_ARG_ENABLE(udev, AC_HELP_STRING([--enable-udev],
		[enable udev support]), [enable_udev=${enableval}])
if (test "${enable_udev}" = "yes"); then
	AC_DEFINE(HAVE_UDEV, 1, [Define if udev support is available])
	PKG_CHECK_MODULES(UDEV, libudev >= 129, enable_udev=yes,
				AC_MSG_ERROR(udev >= 129 is required))
	AC_CHECK_LIB(udev, udev_device_get_parent_with_devtype, dummy=yes,
		AC_DEFINE(NEED_UDEV_DEVICE_GET_PARENT_WITH_DEVTYPE, 1,
			[Define to 1 if you need the
				udev_device_get_parent_with_devtype() function.]))
	AC_CHECK_LIB(udev, udev_enumerate_add_match_property, dummy=yes,
		AC_DEFINE(NEED_UDEV_ENUMERATE_ADD_MATCH_PROPERTY, 1,
			[Define to 1 if you need the
				udev_enumerate_add_match_property() function.]))
fi
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)
AM_CONDITIONAL(UDEV, test "${enable_udev}" = "yes")

AC_ARG_ENABLE(polkit, AC_HELP_STRING([--enable-polkit],
		[enable PolicyKit support]), [enable_polkit=${enableval}])
if (test "${enable_polkit}" = "yes"); then
	PKG_CHECK_MODULES(POLKIT, polkit-dbus >= 0.7, enable_polkit=yes,
				AC_MSG_ERROR(PolicyKit >= 0.7 is required))
	AC_SUBST(POLKIT_CFLAGS)
	AC_SUBST(POLKIT_LIBS)
fi
AM_CONDITIONAL(POLKIT, test "${enable_polkit}" = "yes")

AC_ARG_ENABLE(client, AC_HELP_STRING([--enable-client],
		[enable command line client]), [enable_client=${enableval}])
AM_CONDITIONAL(CLIENT, test "${enable_client}" = "yes")

AC_ARG_ENABLE(fake, AC_HELP_STRING([--enable-fake],
		[enable fake device support]), [enable_fake=${enableval}])
AM_CONDITIONAL(FAKE, test "${enable_fake}" = "yes")

AC_OUTPUT(Makefile gdbus/Makefile include/Makefile src/Makefile doc/Makefile
		test/Makefile plugins/Makefile client/Makefile scripts/Makefile
		scripts/connman src/connman.service doc/version.xml connman.pc)
