# Makefile.am for source/ca-management/src

SUBDIRS = YaPI

myincludedir = @yncludedir@/ca-management
camdir = /var/lib/YaST2/CAM

myinclude_DATA =		\
	popup.ycp		\
	startup.ycp		\
	new_cert.ycp		\
	util.ycp		\
	new_cert_items.ycp	\
	new_cert_callbacks.ycp	\
	new_cert_advanced.ycp	\
	new_cert_read_write.ycp \
	ca.ycp			\
	crl.ycp			\
	certificate.ycp		\
	wizards.ycp

module_DATA = 	CaMgm.ycp	

cam_DATA = 	openssl.cnf.tmpl

client_DATA = 		\
	ca_mgm.ycp	\
	ca-mgm.ycp

desktop_DATA = ca_mgm.desktop

EXTRA_DIST =		\
	$(module_DATA)	\
	$(client_DATA)	\
        $(desktop_DATA)	\
	$(myinclude_DATA) \
	$(cam_DATA)

ca-management:
	ln -sf . ca-management

ycpchook = ca-management

YCPCFLAGS =

install-data-local:
	install -d -m 700 $(DESTDIR)/var/lib/YaST2/CAM
	install -d -m 700 $(DESTDIR)/var/lib/YaST2/CAM/.cas

include $(top_srcdir)/Makefile.am.common
