# Sources for ca-management

module_DATA = \
  modules/CaMgm.rb

module1dir = @moduledir@/YaPI
module1_DATA = \
  modules/YaPI/CaManagement.pm

module2dir = @moduledir@/YaST
module2_DATA = \
  modules/YaST/caUtils.pm

client_DATA = \
  clients/ca-mgm.rb \
  clients/ca_mgm_auto.rb \
  clients/ca_mgm_proposal.rb \
  clients/ca_mgm.rb \
  clients/ca_select_proposal.rb \
  clients/common-cert.rb \
  clients/common_cert.rb

yncludedir = @yncludedir@/ca-management
ynclude_DATA = \
  include/ca-management/ca.rb \
  include/ca-management/new_cert.rb \
  include/ca-management/new_cert_advanced.rb \
  include/ca-management/wizards.rb \
  include/ca-management/certDefault.rb \
  include/ca-management/new_cert_read_write.rb \
  include/ca-management/commandline.rb \
  include/ca-management/crlDefault.rb \
  include/ca-management/new_cert_callbacks.rb \
  include/ca-management/crl.rb \
  include/ca-management/new_cert_items.rb \
  include/ca-management/crlExport.rb \
  include/ca-management/startup.rb \
  include/ca-management/signRequest.rb \
  include/ca-management/popup.rb \
  include/ca-management/request.rb \
  include/ca-management/certificate.rb \
  include/ca-management/dialog-ca.rb \
  include/ca-management/util.rb

schemafilesdir = $(schemadir)/autoyast/rnc
schemafiles_DATA = \
  autoyast-rnc/ca_mgm.rnc

desktop_DATA = \
  desktop/common_cert.desktop \
  desktop/ca_mgm.desktop

EXTRA_DIST = $(module_DATA) $(module1_DATA) $(module2_DATA) $(client_DATA) $(ynclude_DATA) $(schemafiles_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common