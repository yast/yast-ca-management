# Makefile.am for source/ca-management/src/YaPI

yapidir     = @moduledir@/YaPI/
moduledir   = @moduledir@/
yastdir     = @moduledir@/YaST/

yapi_DATA   = CaManagement.pm

yast_DATA   = caUtils.pm 

module_DATA = YaPI.pm

EXTRA_DIST =		\
	$(yapi_DATA)	\
	$(yast_DATA)	\
	$(module_DATA)

YCPCFLAGS =

include $(top_srcdir)/Makefile.am.common
