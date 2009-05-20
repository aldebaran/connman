
includedir = @includedir@/connman

include_HEADERS = types.h log.h plugin.h security.h notifier.h \
					storage.h device.h network.h

nodist_include_HEADERS = version.h

noinst_HEADERS = driver.h element.h property.h ipv4.h rtnl.h dbus.h \
				resolver.h ipconfig.h service.h option.h

MAINTAINERCLEANFILES = Makefile.in

all-local:
	@if [ ! -e connman ]; then \
	  mkdir connman; \
	  list='$(include_HEADERS) $(noinst_HEADERS)'; for i in $$list; \
	    do $(LN_S) $(abs_top_srcdir)/include/$$i connman/$$i; done; \
	  list='$(nodist_include_HEADERS)'; for i in $$list; \
	    do $(LN_S) $(abs_top_builddir)/include/$$i connman/$$i; done; \
	fi

clean-local:
	@rm -rf connman
