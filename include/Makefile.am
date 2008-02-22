
includedir = @includedir@/connman

noinst_HEADERS = log.h plugin.h iface.h rtnl.h dhcp.h

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@if [ ! -e connman ] ; then $(LN_S) $(top_srcdir)/include connman ; fi

clean-local:
	@rm -f connman
