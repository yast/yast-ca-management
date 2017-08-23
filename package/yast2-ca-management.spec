#
# spec file for package yast2-ca-management
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-ca-management
Version:        3.1.10
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2

Group:          System/YaST
License:        GPL-2.0
BuildRequires:  docbook-xsl-stylesheets
BuildRequires:  dosfstools
BuildRequires:  doxygen
BuildRequires:  libxslt
BuildRequires:  perl-Date-Calc
BuildRequires:  perl-URI
BuildRequires:  perl-X500-DN
BuildRequires:  perl-XML-Writer
BuildRequires:  perl-camgm
BuildRequires:  pkg-config
BuildRequires:  update-desktop-files
BuildRequires:  yast2
BuildRequires:  yast2-core
BuildRequires:  yast2-devtools >= 3.1.10
Requires:       perl
Requires:       perl-Config-IniFiles
Requires:       perl-Date-Calc
Requires:       perl-URI
Requires:       perl-X500-DN
Requires:       perl-camgm
Requires:       perl-gettext
# for default TLD definition:
Requires:       yast2 >= 3.1.134
Requires:       yast2-perl-bindings
BuildArch:      noarch
Requires:       yast2-ruby-bindings >= 1.0.0

Summary:        YaST2 - CAs, Certificates and Requests Management

%description
Managing CAs, Certificates and Requests in an understanding way.

%prep
%setup -n %{name}-%{version}

%build
%yast_build

%install
%yast_install


%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/ca-management
%dir %{yast_moduledir}/YaPI
%dir %{yast_moduledir}/YaST
%{yast_yncludedir}/ca-management/*
%{yast_clientdir}/ca-mgm.rb
%{yast_clientdir}/ca_mgm.rb
%{yast_clientdir}/ca_mgm_proposal.rb
%{yast_clientdir}/ca_select_proposal.rb
%{yast_clientdir}/common-cert.rb
%{yast_clientdir}/common_cert.rb
%{yast_clientdir}/ca_mgm_auto.rb
%{yast_moduledir}/CaMgm.rb
%{yast_moduledir}/YaPI/CaManagement.pm
%{yast_moduledir}/YaST/caUtils.pm
%{yast_desktopdir}/ca_mgm.desktop
%{yast_desktopdir}/common_cert.desktop
%{yast_schemadir}/autoyast/rnc/ca_mgm.rnc
%doc %{yast_docdir}
/usr/bin/generateCRL.pl
/usr/bin/exportCRL.pl
%attr(600, root, root) %config(noreplace) /etc/generateCRL.conf

%changelog
