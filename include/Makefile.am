
includedir = @includedir@/connman

include_HEADERS = log.h plugin.h security.h resolver.h \
					driver.h element.h property.h \
					device.h network.h rtnl.h dbus.h

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@if [ ! -e connman ] ; then $(LN_S) $(top_srcdir)/include connman ; fi

clean-local:
	@rm -f connman
