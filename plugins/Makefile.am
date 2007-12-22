
plugindir = $(libdir)/connman/plugins

plugin_LTLIBRARIES = libconnman-80203.la libconnman-80211.la

libconnman_80203_la_SOURCES = 80203.c net.h net.c

libconnman_80211_la_SOURCES = 80211.c net.h net.c

AM_LDFLAGS = -module -avoid-version -export-symbols-regex connman_plugin_desc

INCLUDES = -I$(top_builddir)/include

MAINTAINERCLEANFILES = Makefile.in
