AC_PREREQ(2.60)
AC_INIT()

AM_INIT_AUTOMAKE(connman, 0.5)
AM_CONFIG_HEADER(config.h)

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

if (test "${CFLAGS}" = ""); then
	CFLAGS="-Wall -O2 -D_FORTIFY_SOURCE=2"
fi

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

GTK_DOC_CHECK

AC_PATH_PROG([XSLTPROC], [xsltproc])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g -O0 -Werror"
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

AC_PATH_PROG(UDHCPC, [udhcpc], ,$PATH:/sbin:/usr/sbin)
AC_PATH_PROG(DHCLIENT, [dhclient], ,$PATH:/sbin:/usr/sbin)
AC_PATH_PROG(RESOLVCONF, [resolvconf], ,$PATH:/sbin:/usr/sbin)
AC_PATH_PROG(WPASUPPLICANT, [wpa_supplicant], ,$PATH:/sbin:/usr/sbin)

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0, dummy=yes,
				AC_MSG_ERROR(glib is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

AC_ARG_ENABLE(threads, AC_HELP_STRING([--enable-threads],
					[enable threading support]), [
	AC_DEFINE(NEED_THREADS, 1, [Define if threading support is required])

	PKG_CHECK_MODULES(GTHREAD, gthread-2.0, dummy=yes,
				AC_MSG_ERROR(gthread is required))
	GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
	GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"
])

PKG_CHECK_MODULES(DBUS, dbus-1 >= 1.0, dummy=yes,
				AC_MSG_ERROR(libdbus is required))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_SUBST([GDBUS_CFLAGS], ['$(DBUS_CFLAGS) -I$(top_srcdir)/gdbus'])
AC_SUBST([GDBUS_LIBS], ['$(top_builddir)/gdbus/libgdbus.la $(DBUS_LIBS)'])

PKG_CHECK_MODULES(UDEV, libudev >= 127, udev_found=yes, udev_found=no)
AC_SUBST(UDEV_CFLAGS)
AC_SUBST(UDEV_LIBS)
AM_CONDITIONAL(UDEV, test "${udev_found}" = "yes")

PKG_CHECK_MODULES(POLKIT, polkit-dbus >= 0.7, polkit_found=yes, polkit_found=no)
AC_SUBST(POLKIT_CFLAGS)
AC_SUBST(POLKIT_LIBS)
AM_CONDITIONAL(POLKIT, test "${polkit_found}" = "yes")

AC_ARG_ENABLE(fake, AC_HELP_STRING([--enable-fake],
			[enable fake plugin]), [enable_fake=${enableval}])
AM_CONDITIONAL(FAKE, test "${enable_fake}" = "yes")

AC_OUTPUT(Makefile gdbus/Makefile include/Makefile src/Makefile doc/Makefile
		test/Makefile plugins/Makefile client/Makefile scripts/Makefile
		scripts/connman src/connman.service doc/version.xml connman.pc)
