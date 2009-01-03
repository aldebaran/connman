
SUBDIRS = gdbus include src plugins client scripts test doc

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = connman.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc \
				--enable-loopback \
				--enable-wifi \
				--enable-udhcp \
				--enable-dhclient \
				--enable-novatel \
				--enable-huawei \
				--enable-hso \
				--enable-client

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp missing install-sh mkinstalldirs
