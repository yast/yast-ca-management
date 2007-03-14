# Makefile.am for source/ca-management/src

SUBDIRS = YaPI

myincludedir = @yncludedir@/ca-management

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
	request.ycp		\
	signRequest.ycp		\
	certDefault.ycp		\
	crlDefault.ycp		\
	dialog-ca.ycp		\
	commandline.ycp		\
	wizards.ycp

module_DATA = 	CaMgm.ycp	

client_DATA = 		\
	ca_mgm.ycp	\
	ca_select_proposal.ycp	\
	ca_mgm_proposal.ycp	\
	ca-mgm.ycp		\
	ca_mgm_auto.ycp         \
	common-cert.ycp		\
	common_cert.ycp

desktop_DATA = ca_mgm.desktop	\
	       common_cert.desktop

rncdir = $(schemadir)/autoyast/rnc
rnc_DATA = ca_mgm.rnc

EXTRA_DIST =		\
	$(module_DATA)	\
	$(client_DATA)	\
        $(desktop_DATA)	\
	$(myinclude_DATA) \
	$(cam_DATA) \
	$(rnc_DATA)

ca-management:
	ln -sf . ca-management

ycpchook = ca-management

YCPCFLAGS =

include $(top_srcdir)/Makefile.am.common
