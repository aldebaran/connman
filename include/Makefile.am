
includedir = @includedir@/connman

include_HEADERS = log.h plugin.h driver.h element.h property.h rtnl.h dbus.h

noinst_HEADERS = iface.h dhcp.h resolver.h

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@if [ ! -e connman ] ; then $(LN_S) $(top_srcdir)/include connman ; fi

clean-local:
	@rm -f connman
