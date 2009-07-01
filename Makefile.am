
SUBDIRS = gdbus gatchat include plugins src client tools scripts test doc

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = connman.pc

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc \
				--disable-datafiles \
				--enable-loopback \
				--enable-ethernet \
				--enable-wifi \
				--enable-bluetooth \
				--enable-ofono \
				--enable-udhcp \
				--enable-dhclient \
				--enable-resolvconf \
				--enable-dnsproxy \
				--enable-novatel \
				--enable-huawei \
				--enable-hso \
				--enable-mbm \
				--enable-udev \
				--enable-polkit \
				--enable-client \
				--enable-tools

DISTCLEANFILES = $(pkgconfig_DATA)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs
