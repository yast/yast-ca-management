# Makefile.am for source/ca_management/src

myincludedir = @yncludedir@/ca-management

myinclude_DATA =		\
	popup.ycp		\
	startup.ycp		\
	wizards.ycp

module_DATA = 	CaMgm.ycp	\
		CaManagement.pm

client_DATA = 		\
	ca_mgm.ycp	\
	ca-mgm.ycp

desktop_DATA = ca_mgm.desktop

EXTRA_DIST =		\
	$(module_DATA)	\
	$(client_DATA)	\
        $(desktop_DATA)	\
	$(myinclude_DATA)

ca_mgm:
	ln -sf . ca_mgm

ycpchook = ca_mgm

YCPCFLAGS=-I.

include $(top_srcdir)/Makefile.am.common
