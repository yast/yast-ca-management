###############################################################
# Copyright 2004, Novell, Inc.  All rights reserved.
#
# $Id$
###############################################################
package YaPI::CaManagement;

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

our $VERSION="1.1.0";


=head1 NAME

YaPI::CaManagement

=head1 PREFACE

This package is the public Yast2 API to the CA management.

=head1 VERSION

1.1.0

=head1 SYNOPSIS

use YaPI::CaManagement

$caList = ReadCAList()

  returns a list of available CAs

$bool = AddRootCA($valueMap)

  create a new selfsigned root CA

$certValueMap = ReadCertificateDefaults($valueMap)

  returns a map with defaults for the requested certificate type

$bool = WriteCertificateDefaults($valueMap)

  write the default values for the available certificate types

$ca = ReadCA($valueMap)

  returns a CA certificate as plain text or parsed map

$name = AddRequest($valueMap)

  create a request for a special CA and returns the name
  
$name = IssueCertificate($valueMap)

  issue a certificate and returns the name of the new certificate

$name = AddCertificate($valueMap)

  create a new Certificate and returns the name

$certList = ReadCertificateList($valueMap)

  returns a list of maps with all certificates of a special CA

$bool = UpdateDB($valueMap)

  update the internal openssl database

$cert = ReadCertificate($valueMap)

  returns a certificate as plain text or parsed map
  
$bool = RevokeCertificate($valueMap)

  revoke a certificate

$bool = AddCRL($valueMap)

  create a CRL

$crl = ReadCRL($valueMap)

  returns a CRL as plain text or parsed map

$file = ExportCA($valueMap)

  Export a CA to a file or returns it in different formats

$file = ExportCertificate($valueMap)

  Export a certificate to a file or returns it in different formats

$file = ExportCRL($valueMap)

  Export a CRL to a file or returns it in different formats

$bool = Verify($valueMap)

  verify a certificate

$bool = AddSubCA($valueMap)

  Create a new CA which signed by another CA

$bool = ExportCAToLDAP($valueMap)

  Export a CA to a LDAP directory

$bool = ExportCRLToLDAP($valueMap)

  Export a CRL to a LDAP directory

$bool = ExportCertificateToLDAP($valueMap)

  Export a Certificate in a LDAP Directory.

$defaultsMap = ReadLDAPExportDefaults($valueMap)

  Return the defaults for export CA, CRL or certificates to LDAP.

$bool = InitLDAPcaManagement($valueMap)

  Creates the default configuration structure in LDAP

$bool = DeleteCertificate($valueMap)

  Delete a Certificate. This function removes also
  the request and the private key.

$bool = ImportCommonServerCertificate($valueMap)

  Import a server certificate plus correspondenting CA
  and copy them to a place where other YaST modules look
  for such a common certificate.

$bool = ReadFile($valueMap)

  Returns a certificate or CRL as plain text or parsed map.

$certList = ReadRequestList($valueMap)

  Returns a list of maps with all requests of the defined CA.

$cert = ReadRequest($valueMap)

  Returns a request as plain text or parsed map.

$request = ImportRequest($valueMap)

  Import a request in a CA repository.

$bool = DeleteRequest($valueMap)

  Delete a Request.

$bool = ImportCA($valueMap)

  Import a CA certificate and creates a infrastructure

$bool = DeleteCA($valueMap)

  Delete a Certificate Authority infrastructure

$crlValueMap = ReadCRLDefaults($valueMap)

  Read the default values for a CRL.

$bool = WriteCRLDefaults($valueMap)

  Write the default values for creating a CRL.


=head1 COMMON PARAMETER

Here is a list of common parameter which are often 
used in I<$valueMap>

=over 2

=item *
caName => <directory Name>

=item *
certType => <value>

 allowed values are:

 client, server, ca

=item *
newCaName <directory Name>

=item *
request => <filename> 

 (without suffix)

=item *
certificate => <filename> 

 (without suffix)

=item *
keyPasswd => <String>

=item *
caPasswd => <string>

=item *
commonName => <String> 

 (ascii)

=item *
emailAddress => <email-address>

=item *
keyLength => <integer>

 ( must be greater or equal 512 )

=item *
days => <integer>

=item *
countryName => <two_letter_country_code>

=item *
stateOrProvinceName => <string>

=item *
localityName => <string>

=item *
organizationName => <string>

=item *
organizationalUnitName => <string>

=item *
challengePassword => <string>

=item *
unstructuredName => <string>

=item *
crlReason => <value>

 allowed values are: 

 unspecified, keyCompromise, CACompromise, affiliationChanged, 
 superseded, cessationOfOperation, certificateHold

=back

X509v3 extensions. All values can have the parameter B<critical> as first value.
Combinations can be done via 'B<,>' if they are allowed.

=over 2

=item *
basicConstraints => <values>

 CA:TRUE, CA:FALSE, pathlen:<integer>

=item *
nsComment => <string>

=item *
nsCertType => <values>

 allowed values are:

 client, server, email, objsign, reserved, sslCA, emailCA, objCA

=item *
keyUsage => <values>

 allowed values are:

 digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, 
 keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly

=item *
subjectKeyIdentifier <values>

 allowed values are:

 "hash" or a Hex String

=item *
authorityKeyIdentifier => <values>

 allowed values are:

 issuer[:always], keyid[:always]

=item *
subjectAltName => <values>

 allowed values are:

 email:<email-address>, URI:<URL>, DNS:<domain_name>, 
 RID:<object_identifier>, IP:<ip_address>, email:copy

=item *
issuerAltName => <values>

 allowed values are:

 email:<email-address>, URI:<URL>, DNS:<domain_name>, 
 RID:<object_identifier>, IP:<ip_address>, issuer:copy

=item *
nsBaseUrl => <URL>

=item *
nsRevocationUrl => <URL>

=item *
nsCaRevocationUrl => <URL>

=item *
nsRenewalUrl => <URL>

=item *
nsCaPolicyUrl => <URL>

=item *
nsSslServerName => <domain_name>

=item *
extendedKeyUsage => <values>

 allowed values are:

 serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, 
 msCodeInd, msCodeCom, msCTLSign, msSGC, msEFS, nsSGC, 
 <object_identifier>

 a list of explanation:

 "serverAuth" SSL/TLS Web Server Authentication.
 "clientAuth" SSL/TLS Web Client Authentication.
 "codeSigning" Code signing.
 "emailProtection" E-mail Protection (S/MIME).
 "timeStamping" Trusted Timestamping
 "msCodeInd" Microsoft Individual Code Signing (authenticode)
 "msCodeCom" Microsoft Commercial Code Signing (authenticode)
 "msCTLSign" Microsoft Trust List Signing
 "msSGC" Microsoft Server Gated Crypto
 "msEFS" Microsoft Encrypted File System
 "nsSGC" Netscape Server Gated Crypto

=item *
authorityInfoAccess => <accessOID>;<location>

 accessOID can be: OCSP, caIssuers or a <object_identifier>

 location can be: email:<email-address>, URI:<URL>, DNS:<domain_name>, 
 RID:<object_identifier>, IP:<ip_address>

=item *
crlDistributionPoints URI:<URL>[,URI:<URL>,...]

=back

=head1 DESCRIPTION

=over 2

=cut

use strict;
use vars qw(@ISA);

use YaST::YCP qw(Boolean);
use YaST::caUtils;
use ycp;
use URI::Escape;
use X500::DN;
use MIME::Base64;
use Digest::MD5 qw(md5_hex);
use Date::Calc qw( Date_to_Time Add_Delta_DHMS Today_and_Now);


use YaPI;
textdomain("ca-management");

@YaPI::CaManagement::ISA = qw( YaPI );

YaST::YCP::Import ("SCR");
YaST::YCP::Import ("Hostname");
YaST::YCP::Import ("IP");
YaST::YCP::Import ("Ldap");

our %TYPEINFO;
our @CAPABILITIES = (
                     'SLES9',
                     'REQUEST'
                    );

my $CAM_ROOT = "/var/lib/CAM";

=item *
C<$caList = ReadCAList()>

Returns a list of available CAs

EXAMPLE:

 my $caList = YaPI::CaManagement->ReadCAList();
 if(not defined $caList) {
     #error
 }

 foreach my $ca (@$caList) {
     print $ca."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadCAList} = ["function", ["list", "string"]]; }
sub ReadCAList {
    my $self = shift;
    my $caList = undef;

    my $ret = SCR->Read(".caTools.caList");
    if ( not defined $ret ) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }
    return $ret;
}

=item *
C<$bool = AddRootCA($valueMap)>

Create a new selfsigned root CA and creates the
whole needed infrastructure.

I<$valueMap> supports the following Keys:

* caName (required)

* keyPasswd (required)

* commonName (required)

* emailAddress (depending on CA policy)

* keyLength (default 2048 min: 512 max: 9999)

* days (default 3650)

* countryName (depending on CA policy)

* stateOrProvinceName (depending on CA policy)

* localityName (depending on CA policy)

* organizationName (depending on CA policy)

* organizationalUnitName (depending on CA policy)

* challengePassword

* unstructuredName

* basicConstraints (required)

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* authorityKeyIdentifier

* subjectAltName

* issuerAltName

* nsBaseUrl

* nsRevocationUrl

* nsCaRevocationUrl

* nsRenewalUrl

* nsCaPolicyUrl

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

* crlDistributionPoints

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

EXAMPLE:

 my $data = {
             'caName'                => 'My_CA',
             'keyPasswd'             => 'system',
             'commonName'            => 'My CA',
             'emailAddress'          => 'my@example.com',
             'keyLength'             => '2048',
             'days'                  => '3650',
             'countryName'           => 'US',
             'localityName'          => 'New York',
             'organizationName'      => 'My Inc.',
            };

 my $res = YaPI::CaManagement->AddRootCA($data);
 if( not defined $res ) {
     # error  
 } else {
     print "OK\n";
 }

=cut

BEGIN { $TYPEINFO{AddRootCA} = ["function", "boolean", ["map", "string", "any"]]; }
sub AddRootCA {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};

    if (!defined $data->{"keyPasswd"} ) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'keyPasswd' or password is too short."),
                                code    => "CHECK_PARAM_FAILED");
    }
    if (!defined $data->{"commonName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'commonName'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    if (!defined $data->{"basicConstraints"} || $data->{"basicConstraints"} !~ /CA:TRUE/i) {
                                           # parameter check failed
        return $self->SetError( summary => __("According to 'basicConstraints', this is not a CA."),
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"keyLength"}) {
        $data->{"keyLength"} = 2048;
    }
    if (!defined $data->{"days"}) {
        $data->{"days"} = 3650;
    }
    if (not SCR->Write(".caTools.caInfrastructure", $data->{"caName"})) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    my $retCode = SCR->Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if (! defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }
    # check this values, if they were accepted from the openssl command
    my @DN_Values = ('countryName', 'stateOrProvinceName', 'localityName',
                     'organizationName', 'organizationalUnitName',
                     'commonName', 'emailAddress',
                     'challengePassword', 'unstructuredName');

    foreach my $DN_Part (@DN_Values) {
        my $ret = YaST::caUtils->checkValueWithConfig($DN_Part, $data);
        if (not defined $ret ) {
            YaST::caUtils->cleanCaInfrastructure($caName);
            return $self->SetError(%{YaST::caUtils->Error()});
        }
        push @dn, $data->{$DN_Part};
    }

    if (not SCR->Write(".CAM.openssl_cnf.value.$caName.req.x509_extensions", "v3_ca")) { 
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    #####################################################
    # merge this extentions to the config file
    # some values have defaults
    #
    #             v3 ext. value               default
    #####################################################
    my %v3ext = (
                 'basicConstraints'       => undef,
                 'nsComment'              => undef,
                 'nsCertType'             => undef,
                 'keyUsage'               => undef,
                 'subjectKeyIdentifier'   => undef,
                 'authorityKeyIdentifier' => undef,
                 'subjectAltName'         => undef,
                 'issuerAltName'          => undef,
                 'nsBaseUrl'              => undef,
                 'nsRevocationUrl'        => undef,
                 'nsCaRevocationUrl'      => undef,
                 'nsRenewalUrl'           => undef,
                 'nsCaPolicyUrl'          => undef,
                 'nsSslServerName'        => undef,
                 'extendedKeyUsage'       => undef,
                 'authorityInfoAccess'    => undef,
                 'crlDistributionPoints'  => undef
                );

    foreach my $extName ( keys %v3ext) {
        if (not defined YaST::caUtils->mergeToConfig($extName, 'v3_ca',
                                                     $data, $v3ext{$extName})) {
            YaST::caUtils->cleanCaInfrastructure($caName);
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }

    if (not SCR->Write(".CAM.openssl_cnf", undef)) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    my $hash = {
                OUTFILE  => "$CAM_ROOT/$caName/cacert.key",
                PASSWD   => $data->{"keyPasswd"},
                BITS     => $data->{"keyLength"}
               };
    my $ret = SCR->Execute( ".openssl.genKey", $caName, $hash);

    if (not defined $ret) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.req",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             PASSWD  => $data->{"keyPasswd"},
             DN      => \@dn };
    $ret = SCR->Execute( ".openssl.genReq", $caName, $hash);
    if (not defined $ret) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR->Error(".openssl")});
    }

    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.pem",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             REQFILE => "$CAM_ROOT/$caName/cacert.req",
             PASSWD  => $data->{"keyPasswd"},
             DAYS    => $data->{"days"} 
            };
    $ret = SCR->Execute( ".openssl.genCert", $caName, $hash);
    if (not defined $ret) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR->Error(".openssl")});
    }

    $ret = SCR->Execute(".target.bash", "cp $CAM_ROOT/$caName/cacert.pem $CAM_ROOT/.cas/$caName.pem");
    if (! defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not copy CA certificate",
                                code => "COPY_FAILED");
    }
    $ret = SCR->Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");
    if (! defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not create hash vaules in '$CAM_ROOT/.cas/'",
                                code => "C_REHASH_FAILED");
    }
    
    SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return 1;
}

=item *
C<$certValueMap = ReadCertificateDefaults($valueMap)>

In I<$valueMap> you can define the following keys:

* caName (if not defined, read defaults for a Root CA)

* certType

Returns a map with defaults for the requested certificate type.
The return value is "undef" on an error.

On success the return value is a hash which can contain the following keys:

* basicConstraints

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* authorityKeyIdentifier

* subjectAltName

* issuerAltName

* nsBaseUrl

* nsRevocationUrl

* nsCaRevocationUrl

* nsRenewalUrl

* nsCaPolicyUrl

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

* crlDistributionPoints

* keyLength

* days

* DN

I<DN> is a hash which contains some values of the 
subject of the CA Certificate (if caName is defined)


The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

EXAMPLE:

 use Data::Dumper;

 my $data = {
             'caName'   => 'My_CA',
             'certType' => 'client'
            }
 $certValueMap = YaPI::CaManagement->ReadCertificateDefaults($data) 
 if( not defined $certValueMap ) {
     # error
 } else {
     print Data::Dumper->Dump([$certValueMap])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadCertificateDefaults} = [
                                              "function", 
                                              ["map", "string", "any"],
                                              ["map", "string", "any"]
                                             ]; }
sub ReadCertificateDefaults {
    my $self = shift;
    my $data = shift;
    my $caName   = "";
    my $certType = "";
    my $ret = {};

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (defined $data->{"caName"}) {
        $caName = $data->{"caName"};
    } 
    if (defined $data->{"certType"}) {
        $certType = $data->{"certType"};
    } else {
                                           # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'certType'."),
                               code => "PARAM_CHECK_FAILED");
    }

    $ret = {
            'basicConstraints'       => undef,
            'nsComment'              => undef,
            'nsCertType'             => undef,
            'keyUsage'               => undef,
            'subjectKeyIdentifier'   => undef,
            'authorityKeyIdentifier' => undef,
            'subjectAltName'         => undef,
            'issuerAltName'          => undef,
            'nsBaseUrl'              => undef,
            'nsRevocationUrl'        => undef,
            'nsCaRevocationUrl'      => undef,
            'nsRenewalUrl'           => undef,
            'nsCaPolicyUrl'          => undef,
            'nsSslServerName'        => undef,
            'extendedKeyUsage'       => undef,
            'authorityInfoAccess'    => undef,
            'crlDistributionPoints'  => undef
           };

    foreach my $extName ( keys %{$ret}) {
        if (defined $caName && $caName ne "") {
            $ret->{$extName} = SCR->Read(".CAM.openssl_tmpl.value.$caName.v3_$certType.$extName");
            if (not defined $ret->{$extName}) {
                delete $ret->{$extName};
            }
        } else {
            $ret->{$extName} = SCR->Read(".CAM.opensslroot_tmpl.value.v3_$certType.$extName");
            if (not defined $ret->{$extName}) {
                delete $ret->{$extName};
            }
        }
    }
    if (defined $caName && $caName ne "") {
        $ret->{'keyLength'} = SCR->Read(".CAM.openssl_tmpl.value.$caName.req.default_bits");
        if ($certType ne "ca") {
            $ret->{'days'} = SCR->Read(".CAM.openssl_tmpl.value.$caName.".$certType."_cert.default_days");
        } else {
            $ret->{'days'} = SCR->Read(".CAM.openssl_tmpl.value.$caName.ca.default_days");
        }
    } else {
        $ret->{'keyLength'} = SCR->Read(".CAM.opensslroot_tmpl.value.req.default_bits");
        if ($certType ne "ca") {
            $ret->{'days'} = SCR->Read(".CAM.opensslroot_tmpl.value.".$certType."_cert.default_days");
        } else {
            $ret->{'days'} = SCR->Read(".CAM.opensslroot_tmpl.value.ca.default_days");
        }
        
    }    
    delete $ret->{'keyLength'} if(not defined $ret->{'keyLength'});
    delete $ret->{'days'} if(not defined $ret->{'days'});
    
    # try to get default DN values
    if (defined $caName && $caName ne "") {
        my $hash = {
                    INFILE => "$CAM_ROOT/$caName/cacert.pem",
                    INFORM => "PEM"
                   };
        my $ca = SCR->Read(".openssl.getParsedCert", $caName, $hash);
        if (not defined $ca) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $ca->{'DN_HASH'}) {
            $ret->{'DN'} = $ca->{'DN_HASH'};
            # delete CN and emailAddress; not needed as default
            delete $ret->{'DN'}->{'CN'} if(defined $ret->{'DN'}->{'CN'});
            delete $ret->{'DN'}->{'EMAILADDRESS'} if(defined $ret->{'DN'}->{'EMAILADDRESS'});
        }
    } 
    
    return $ret;
}

=item *
C<$bool = WriteCertificateDefaults($valueMap)>

Write the default values for the available certificate types.
Keys which are not present, will be removed if they are available
in the configuration file.

In I<$valueMap> you can define the following keys:

* caName (required)

* certType (required)

* basicConstraints

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* authorityKeyIdentifier

* subjectAltName

* issuerAltName

* nsBaseUrl

* nsRevocationUrl

* nsCaRevocationUrl

* nsRenewalUrl

* nsCaPolicyUrl

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

* crlDistributionPoints

* days

* keyLength

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

     my $data = {
                 'caName'    => 'My_CA',
                 'certType'  => 'server',
                 'nsComment' => '"My Server Certificate"'
                };
     my $res = YaPI::CaManagement->WriteCertificateDefaults($data);
     if( not defined $res ) {
         # error
     } else {
         print "OK\n";
     }
 }

=cut

BEGIN { $TYPEINFO{WriteCertificateDefaults} = ["function", "boolean", ["map", "string", "any"]]; }
sub WriteCertificateDefaults {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certType   = "";
    my $ret = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }
    
    # checking requires
    if (!defined $data->{"caName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    
    if(! defined $data->{"certType"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'certType'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $certType = $data->{"certType"};

    $ret = SCR->Execute(".target.bash",
                        "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if (! defined $ret || $ret != 0) {
        return $self->SetError( summary => "Can not create backup file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }

    if (not SCR->Write(".CAM.openssl_cnf.value.$caName.".$certType."_cert.x509_extensions", 
                       "v3_".$certType)) { 
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }

    #####################################################
    # merge this extentions to the config file
    #
    #             v3 ext. value               default
    #####################################################
    my %v3ext = (
                 'basicConstraints'       => undef,
                 'nsComment'              => undef,
                 'nsCertType'             => undef,
                 'keyUsage'               => undef,
                 'subjectKeyIdentifier'   => undef,
                 'authorityKeyIdentifier' => undef,
                 'subjectAltName'         => undef,
                 'issuerAltName'          => undef,
                 'nsBaseUrl'              => undef,
                 'nsRevocationUrl'        => undef,
                 'nsCaRevocationUrl'      => undef,
                 'nsRenewalUrl'           => undef,
                 'nsCaPolicyUrl'          => undef,
                 'nsSslServerName'        => undef,
                 'extendedKeyUsage'       => undef,
                 'authorityInfoAccess'    => undef,
                 'crlDistributionPoints'  => undef
                );
    
    foreach my $extName ( keys %v3ext) {
        if (not defined YaST::caUtils->mergeToConfig($extName, "v3_$certType",
                                                     $data, $v3ext{$extName})) {
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }
    
    my $default_bits = SCR->Read(".CAM.openssl_cnf.value.$caName.req.default_bits");
    
    if(defined $data->{keyLength}) {
        # write new default_bits
        if(not SCR->Write(".CAM.openssl_cnf.value.$caName.req.default_bits", $data->{keyLength})) {
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    } elsif(defined $default_bits) {
        # remove default_bits
        if(not SCR->Write(".CAM.openssl_cnf.value.$caName.req.default_bits", undef)) {
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    }
    my $sect = ($certType eq "ca")? $certType : $certType."_cert";
    my $default_days = SCR->Read(".CAM.openssl_cnf.value.$caName.$sect.default_days");
    if(defined $data->{days}) {
        # write new default_days
        
        if(not SCR->Write(".CAM.openssl_cnf.value.$caName.$sect.default_days", $data->{days})) {
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    } elsif(defined $default_days) {
        # remove default_days
        if(not SCR->Write(".CAM.openssl_cnf.value.$caName.$sect.default_days", undef)) {
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    }

    if (not SCR->Write(".CAM.openssl_cnf", undef)) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }

    $ret = SCR->Execute(".target.bash", 
                        "cp $CAM_ROOT/$caName/openssl.cnf $CAM_ROOT/$caName/openssl.cnf.tmpl");
    if (! defined $ret || $ret != 0) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not create new template file '$CAM_ROOT/$caName/openssl.cnf.tmpl'",
                                code => "COPY_FAILED");
    }
    SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return 1;
}


=item *
C<$ca = ReadCA($valueMap)>

Returns a CA certificate as plain text or parsed map.

In I<$valueMap> you can define the following keys:

* caName (required)

* type (required; can be "plain", "parsed", "extended")

The return value is "undef" on an error.

On success and type = "plain" the plain text view of the CA is returned.

If the type = "parsed" or "extended" a complex structure with the single values is returned.


EXAMPLE:

 use Data::Dumper;

 foreach my $type ("parsed", "plain", "extended") {
     my $data = {
                 'caName' => 'My_CA',
                 'type'   => $type
                };
     my $res = YaPI::CaManagement->ReadCA($data);
     if( not defined $res ) {
         # error
     } else {
         print Data::Dumper->Dump([$res])."\n";
     }
 }

=cut

BEGIN { $TYPEINFO{ReadCA} = ["function", "any", ["map", "string", "any"]]; }
sub ReadCA {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $type   = "";
    my $ret = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
     
    if (! defined $data->{"type"} || 
        !grep( ( $_ eq $data->{"type"}), ("parsed", "plain", "extended"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'type'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $type = $data->{"type"};

    my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/cacert.pem");
    if ($size <= 0) {
        return $self->SetError(summary => __("CA certificate not available in")." '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/cacert.pem",
                INFORM => "PEM"
               };
    if ($type eq "parsed") {
        $ret = SCR->Read(".openssl.getParsedCert", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } elsif($type eq "extended") {
        $ret = SCR->Read(".openssl.getExtendedParsedCert", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } else {
        $ret = SCR->Read(".openssl.getTXTCert", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$name = AddRequest($valueMap)>

Create a request for a special CA and returns the name.

The keys in I<$valueMap> are:

* caName (required)

* keyPasswd (required)

* commonName (required)

* emailAddress (depending on CA policy)

* keyLength (required)

* countryName (depending on CA policy)

* stateOrProvinceName (depending on CA policy)

* localityName (depending on CA policy)

* organizationName (depending on CA policy)

* oganizationalUnitName (depending on CA policy)

* challengePassword

* unstructuredName

* basicConstraints

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* subjectAltName

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

The return value is "undef" on an error and the 
filename(without suffix) of the request on success.

The syntax of these values are explained in the
B<COMMON PARAMETER> section.

EXAMPLE:

 my $data = {
             'caName'                => 'My_CA',
             'keyPasswd'             => 'system',
             'commonName'            => 'My New Request',
             'emailAddress'          => 'my@example.com',
             'keyLength'             => '2048',
             'days'                  => '365',
             'countryName'           => 'DE',
             'localityName'          => 'Nuremberg',
             'stateOrProvinceName'   => 'Bavaria',
             'organizationName'      => 'My Linux AG',
             'nsComment'             => "YaST Generated Certificate"
            };
 my $res = YaPI::CaManagement->AddRequest($data);
 if( not defined $res ) {
     # error 
 } else {
     print "OK Name of the request is: '$res'\n";
 }

=cut

BEGIN { $TYPEINFO{AddRequest} = ["function", "string", ["map", "string", "any"] ]; }
sub AddRequest {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $request = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};

    if (!defined $data->{"keyPasswd"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'keyPasswd'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    if (!defined $data->{"commonName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'commonName'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"keyLength"}) {
        $data->{"keyLength"} = 2048;
    }

    # generate the request name
    my $requestString = YaST::caUtils->stringFromDN($data);
    
    if (not defined $requestString) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }
    
    $request = md5_hex($requestString);
    $request = $request."-".time();

    # test if this File already exists
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/keys/".$request.".key") != -1) {
        return $self->SetError(summary => __("Duplicate DN. Request already exists."),
                               description => "'$requestString' already exists.",
                               code => "FILE_ALREADY_EXIST");
    }
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/req/".$request.".req") != -1) {
        return $self->SetError(summary => __("Duplicate DN. Request already exists."),
                               description => "'$requestString' already exists.",
                               code => "FILE_ALREADY_EXIST");
    }    

    my $retCode = SCR->Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if (! defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }
    # check this values, if they were accepted from the openssl command
    my @DN_Values = ('countryName', 'stateOrProvinceName', 'localityName',
                     'organizationName', 'organizationalUnitName',
                     'commonName', 'emailAddress',
                     'challengePassword', 'unstructuredName');

    foreach my $DN_Part (@DN_Values) {
        my $ret = YaST::caUtils->checkValueWithConfig($DN_Part, $data);
        if (not defined $ret ) {
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
        push @dn, $data->{$DN_Part};
    }

    #####################################################
    # merge this extentions to the config file
    # some values have defaults
    #
    #             v3 ext. value               default
    #####################################################
    my %v3ext = (
                 'basicConstraints'       => undef,
                 'nsComment'              => undef,
                 'nsCertType'             => undef,
                 'keyUsage'               => undef,
                 'subjectKeyIdentifier'   => undef,
                 'subjectAltName'         => undef,
                 'nsSslServerName'        => undef,
                 'extendedKeyUsage'       => undef,
                 'authorityInfoAccess'    => undef,
                );

    foreach my $extName ( keys %v3ext) {
        if (not defined YaST::caUtils->mergeToConfig($extName, 'v3_req',
                                                     $data, $v3ext{$extName})) {
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }

    my $reqSect = SCR->Read(".CAM.openssl_cnf.all.$caName.v3_req");
    if(! defined $reqSect) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not read request section",
                                code => "SCR_READ_FAILED");
    }
    if(scalar( @{$reqSect->{value}} ) == 0) {
        # request section is empty => remove req_extension
        
        if (not SCR->Write(".CAM.openssl_cnf.value.$caName.req.req_extensions", undef)) { 
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
        
    } else {
        
        if (not SCR->Write(".CAM.openssl_cnf.value.$caName.req.req_extensions", "v3_req")) { 
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    }

    if (not SCR->Write(".CAM.openssl_cnf", undef)) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    my $hash = {
                OUTFILE  => "$CAM_ROOT/$caName/keys/".$request.".key",
                PASSWD   => $data->{"keyPasswd"},
                BITS     => $data->{"keyLength"}
               };
    my $ret = SCR->Execute( ".openssl.genKey", $caName, $hash);

    if (not defined $ret) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/req/".$request.".req",
             KEYFILE => "$CAM_ROOT/$caName/keys/".$request.".key",
             PASSWD  => $data->{"keyPasswd"},
             DN      => \@dn };
    $ret = SCR->Execute( ".openssl.genReq", $caName, $hash);
    if (not defined $ret) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        return $self->SetError(%{SCR->Error(".openssl")});
    }

    $ret = SCR->Write(".caTools.addCAM", $caName, { MD5 => $request, DN => $requestString});
    if( not $ret) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/req/".$request.".req");
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return $request;
}

=item *
C<$name = IssueCertificate($valueMap)>

Issue a certificate and returns the name of the new certificate.

In I<$valueMap> you can define the following keys: 

* caName (required)

* request (required - the name of the request without suffix)

* certType (required - allowed values are: "client", "server" and "ca")

* caPasswd (required)

* days (required)

* basicConstraints (required)

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* authorityKeyIdentifier

* subjectAltName

* issuerAltName

* nsBaseUrl

* nsRevocationUrl

* nsCaRevocationUrl

* nsRenewalUrl

* nsCaPolicyUrl

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

* crlDistributionPoints

* notext (optional - if set to "1" do not output the 
          text version in the PEM file)

The return value is "undef" on an error and the 
filename(without suffix) of the certificate on success.

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

EXAMPLE:

 my $data = {
             'caName'                => 'My_CA',
             'request'               => $request,
             'certType'              => 'client',
             'caPasswd'              => 'system',
             'days'                  => '365',
             'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=My_CA%2Cou=PKI%2Cdc=example%2Cdc=com",
             'nsComment'             => "YaST Generated Certificate",
            };
 my $res = YaPI::CaManagement->IssueCertificate($data);
 if( not defined $res ) {
     # error
 } else {
     print STDERR "OK: '$res'\n";
 }

=cut

BEGIN { $TYPEINFO{IssueCertificate} = ["function", "string", ["map", "string", "any"] ]; }
sub IssueCertificate {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $request = "";
    my $certificate = "";
    my $certType = "client";
    my $notext = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (defined $data->{notext} && $data->{notext} eq "1") {
        $notext = "1";
    }

    # checking requires
    if (!defined $data->{"caName"} ) {
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    if (!defined $data->{"request"} ) {
        return $self->SetError( summary => __("Missing value 'request'"),
                                code    => "CHECK_PARAM_FAILED");
    }
    $request = $data->{"request"};

    if (!defined $data->{"caPasswd"} ) {
        return $self->SetError( summary => __("Missing value 'caPasswd'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"days"}) {
        $data->{"days"} = 365;
    }
    if (defined $data->{"certType"}) {
        $certType = $data->{"certType"};
    }
    # test if the file already exists
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/req/".$request.".req") == -1) {
        return $self->SetError(summary => __("Request does not exist."),
                               description => "$CAM_ROOT/$caName/req/".$request.".req",
                               code => "FILE_DOES_NOT_EXIST");
    }

    # get next serial number and built the certificate file name
    my $serial = SCR->Read(".caTools.nextSerial", $caName);
    if (not defined $serial) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }
    $certificate = $serial.":".$request;

    # create the configuration file
    my $retCode = SCR->Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if (! defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }

    # check time period of the CA against DAYS to sign this cert
    my $caP = $self->ReadCA({caName => $caName, type => 'parsed'});
    if (not defined $caP) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return undef;
    }
    my $notafter = SCR->Execute(".openssl.getNumericDate", $caName, $caP->{'NOTAFTER'});
    if (not defined $notafter) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR->Error(".openssl")});
    }

    #                     year    month  day  hour   min  sec
    if ( $notafter !~ /^(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not parse CA date string",
                                description => "Date string: '$notafter'",
                                code    => "PARSE_ERROR");
    }
    my @expireCA = ($1, $2, $3, $4, $5, $6);
    my @expireCertDate = Add_Delta_DHMS(Today_and_Now(), $data->{"days"}, 0, 0, 0);

    my $expireCertTime = Date_to_Time(@expireCertDate);
    my $expireCATime   = Date_to_Time(@expireCA);

    if ($expireCertTime > $expireCATime) {
        my $caStr = sprintf("%s-%s-%s %s:%s:%s", @expireCA);
        my $certStr = sprintf("%s-%s-%s %s:%s:%s", @expireCertDate);
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
                                           # parameter check failed
        return $self->SetError( summary => __("CA expires before the certificate should expire."),
                                description => "CA expires:'$caStr', Cert should expire:'$certStr'",
                                code  => 'PARAM_CHECK_FAILED');
    }

    #####################################################
    # merge this extentions to the config file
    # some values have defaults
    #
    #             v3 ext. value               default
    #####################################################
    my %v3ext = (
                 'basicConstraints'       => undef,
                 'nsComment'              => undef,
                 'nsCertType'             => undef,
                 'keyUsage'               => undef,
                 'subjectKeyIdentifier'   => undef,
                 'authorityKeyIdentifier' => undef,
                 'subjectAltName'         => undef,
                 'issuerAltName'          => undef,
                 'nsBaseUrl'              => undef,
                 'nsRevocationUrl'        => undef,
                 'nsCaRevocationUrl'      => undef,
                 'nsRenewalUrl'           => undef,
                 'nsCaPolicyUrl'          => undef,
                 'nsSslServerName'        => undef,
                 'extendedKeyUsage'       => undef,
                 'authorityInfoAccess'    => undef,
                 'crlDistributionPoints'  => undef,
                );

    foreach my $extName ( keys %v3ext) {
        if (not defined YaST::caUtils->mergeToConfig($extName, 'v3_'.$certType,
                                                     $data, $v3ext{$extName})) {
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }

    my $v3Sect = SCR->Read(".CAM.openssl_cnf.all.$caName.v3_".$certType);
    if(! defined $v3Sect) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not read v3 section",
                                code => "SCR_READ_FAILED");
    }
    if(scalar( @{$v3Sect->{value}} ) == 0) {
        # v3 section is empty => remove x509_extension
        
        if (not SCR->Write(".CAM.openssl_cnf.value.$caName.".$certType."_cert.x509_extensions", 
                           undef)) { 
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
        
    } else {
        
        if (not SCR->Write(".CAM.openssl_cnf.value.$caName.".$certType."_cert.x509_extensions", 
                           "v3_".$certType)) { 
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    }

    if (not SCR->Write(".CAM.openssl_cnf", undef)) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    my $hash = {
                REQFILE => "$CAM_ROOT/$caName/req/".$request.".req",
                CAKEY   => "$CAM_ROOT/$caName/cacert.key",
                CACERT  => "$CAM_ROOT/$caName/cacert.pem",
                DAYS    => $data->{'days'},
                PASSWD  => $data->{'caPasswd'},
                EXTS    => 'v3_'.$certType,
                OUTDIR  => "$CAM_ROOT/$caName/certs/",
                OUTFILE => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem"
               };
    if($notext eq "1") {
        $hash->{NOTEXT} = "1";
    }

    my $ret = SCR->Execute( ".openssl.issueCert", $caName, $hash);

    if (not defined $ret) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    
    SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return $certificate;
}

=item *
C<$name = AddCertificate($valueMap)>

Create a new Certificate and returns the name

In I<$valueMap> you can define the following keys: 

* caName (required)

* certType (required - "client", "server" or "ca" )

* keyPasswd (required)

* caPasswd (required)

* commonName (required)

* emailAddress (depending on CA policy)

* keyLength (required)

* days (required)

* countryName (depending on CA policy)

* stateOrProvinceName (depending on CA policy)

* localityName (depending on CA policy)

* organizationName (depending on CA policy)

* organizationalUnitName (depending on CA policy)

* challengePassword

* unstructuredName

* basicConstraints (required)

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* authorityKeyIdentifier

* subjectAltName

* issuerAltName

* nsBaseUrl

* nsRevocationUrl

* nsCaRevocationUrl

* nsRenewalUrl

* nsCaPolicyUrl

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

* crlDistributionPoints

* notext (optional - if set to "1" do not output the
          text version in the PEM file)

The return value is "undef" on an error and the 
filename(without suffix) of the certificate on success.

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

EXAMPLE:

 my $data = {
            'caName'                => 'My_CA',
            'certType'              => 'client',
            'keyPasswd'             => 'system',
            'caPasswd'              => 'system',
            'commonName'            => 'John Doe',
            'emailAddress'          => 'John.Doe@example.com',
            'keyLength'             => '2048',
            'days'                  => '365',
            'countryName'           => 'US',
            'localityName'          => 'New York',
            'organizationalUnitName'=> 'IT',
            'organizationName'      => 'My Inc.',
            'crlDistributionPoints' => "URI:ldap://ldap.example.com/?cn=My_CA%2Cou=PKI%2Cdc=example%2Cdc=com",
            'nsComment'             => "YaST Generated Certificate",
            };

    my $res = YaPI::CaManagement->AddCertificate($data);
    if( not defined $res ) {
        # error
    } else {
        print "OK: '$res'\n";
    }

=cut

BEGIN { $TYPEINFO{AddCertificate} = ["function", "string", ["map", "string", "any"] ]; }
sub AddCertificate {
    my $self = shift;
    my $data = shift;

    my $request = $self->AddRequest($data);
    if (not defined $request) {
        return undef;
    }
    $data->{'request'} = $request;
    my $certificate = $self->IssueCertificate($data);
    if (not defined $certificate) {
        my $caName = $data->{'caName'};
        SCR->Write(".caTools.delCAM", $caName, {MD5 => $request});
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/req/".$request.".req");
        return undef;
    }

    return $certificate;
}

=item *
C<$certList = ReadCertificateList($valueMap)>

Returns a list of maps with all certificates of the defined CA.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (optional)

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error.

On success it returns an array of hashes with all 
certificates of this CA. @ret[0..X] can have the 
following Hash keys:

* certificate (the name of the certificate)

* commonName

* emailAddress

* countryName

* stateOrProvinceName

* localityName

* organizationName

* organizationalUnitName

* status (The status of the certificate: "valid", "revoked", "expired")


EXAMPLE:

 use Data::Dumper;

 my $data = {
             'caName'   => 'My_CA',
             'caPasswd' => 'system'
            };

    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        # error
    } else {
        my $certificateName = $res->[0]->{'certificate'};
        print Data::Dumper->Dump([$res])."\n";
    }

=cut

BEGIN { $TYPEINFO{ReadCertificateList} = ["function", ["list", "any"], ["map", "string", "any"]]; }
sub ReadCertificateList {
    my $self = shift;
    my $data = shift;
    my $ret  = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};
    if ( defined $data->{'caPasswd'} ) { # needed only for UpdateDB
        $ret = $self->UpdateDB($data);
        if ( not defined $ret ) {
            return undef;
        }
    }

    $ret = SCR->Read(".caTools.certificateList", $data->{'caName'});
    if ( not defined $ret ) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }
    return $ret;
}

=item *
C<$bool = UpdateDB($valueMap)>

Update the internal openssl database. 

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

The return value is "undef" on an error and "1" on success.

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

EXAMPLE:

 my $data = {
             'caName'   => 'My_CA',
             'caPasswd' => 'system'
            };

 my $res = YaPI::CaManagement->UpdateDB($data);
 if( not defined $res ) {
     # error
 } else {
     print "OK \n";
 }

=cut

BEGIN { $TYPEINFO{UpdateDB} = ["function", "boolean", ["map", "string", "any"]]; }
sub UpdateDB {
    my $self = shift;
    my $data = shift;
    
    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (! defined $data->{'caName'} ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};
    if (! defined $data->{'caPasswd'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/index.txt");
    if($size < 0) {
        # file does not exist => error
        return $self->SetError(summary => "Database not found.",
                               code => "FILE_DOES_NOT_EXIST");
    } elsif($size == 0) {
        # no certificate created => test only the caPasswd
        if(not defined SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'}, 
                                                                 CACERT => 1})
          ) {
            return $self->SetError(%{SCR->Error(".caTools")});
        }
    } else {
        # test password first, for a better error message
        if(not defined SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'}, 
                                                                 CACERT => 1})
          ) {
            return $self->SetError(%{SCR->Error(".caTools")});
        }

        my $hash = {
                    CAKEY  => "$CAM_ROOT/$caName/cacert.key",
                    CACERT => "$CAM_ROOT/$caName/cacert.pem",
                    PASSWD => $data->{'caPasswd'}
                   };
        my $ret = SCR->Execute(".openssl.updateDB", $data->{'caName'}, $hash);
        if ( not defined $ret ) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    }
    return 1;
}

=item *
C<$cert = ReadCertificate($valueMap)>

Returns a certificate as plain text or parsed map.

In I<$valueMap> you can define the following keys: 

* caName (required)

* certificate (required - name without suffix)

* type (required - allowed values: "parsed", "extended" or "plain") 

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error.

On success and type = plain the plain text view of the Certificate is returned.

If the type is "parsed" or "extended" a complex structure with the single values is returned.

EXAMPLE:

 use Data::Dumper;

 foreach my $type ("parsed", "plain", "extended") {
     my $data = {
                 'caName'      => 'My_CA',
                 'type'        => $type,
                 'certificate' => $certName
                };

     my $res = YaPI::CaManagement->ReadCertificate($data);
     if( not defined $res ) {
         # error
     } else {
         print Data::Dumper->Dump([$res])."\n";
     }
 }

=cut

BEGIN { $TYPEINFO{ReadCertificate} = ["function", "any", ["map", "string", "any"]]; }
sub ReadCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";
    my $type   = "";
    my $ret = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (! defined $data->{"type"} || 
        !grep( ( $_ eq $data->{"type"}), ("parsed", "plain", "extended"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'type'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $type = $data->{"type"};
    
    if (! defined $data->{"certificate"}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'certificate'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};

    my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
    if ($size <= 0) {
        return $self->SetError(summary => __("Certificate not found."),
                               description => "Certificate '$certificate.pem' not available in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem",
                INFORM => "PEM"
               };
    if ($type eq "parsed") {
        $ret = SCR->Read(".openssl.getParsedCert", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } elsif($type eq "extended") {
        $ret = SCR->Read(".openssl.getExtendedParsedCert", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } else {
        $ret = SCR->Read(".openssl.getTXTCert", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$bool = RevokeCertificate($valueMap)>

Revoke a certificate. 

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

* certificate (required)

* crlReason

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             'caName'      => 'My_CA',
             'caPasswd'    => 'system',
             'certificate' => $certName,
             'crlReason'   => 'keyCompromise'
            };

 my $res = YaPI::CaManagement->RevokeCertificate($data);
 if( not defined $res ) {
     # error
 } else {
     print "Revoke successful\n";
 }

=cut

BEGIN { $TYPEINFO{RevokeCertificate} = ["function", "boolean", ["map", "string", "any"]]; }
sub RevokeCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (!defined $data->{"caPasswd"} ) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'caPasswd'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    if (!defined $data->{"certificate"} ) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'certificate'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $certificate = $data->{"certificate"};

    my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
    if ($size <= 0) {
        return $self->SetError(summary => __("Certificate not found."),
                               description => "Certificate '$certificate.pem' not available in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }

    my $hash = {
                CAKEY  => "$CAM_ROOT/$caName/cacert.key",
                CACERT => "$CAM_ROOT/$caName/cacert.pem",
                PASSWD => $data->{'caPasswd'},
                INFILE => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem"
               };
    if (defined $data->{'crlReason'}) {
        $hash->{'CRL_REASON'} = $data->{'crlReason'};
    }
    my $ret = SCR->Execute(".openssl.revoke", $caName, $hash);
    if (not defined $ret) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    return 1;
}

=item *
C<$bool = AddCRL($valueMap)>

Create a new CRL. 

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

* days (required)

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             'caName'      => 'My_CA',
             'caPasswd'    => 'system',
             'days'        => 8
            };

 my $res = YaPI::CaManagement->AddCRL($data);
 if( not defined $res ) {
     # error
 } else {
     print "AddCRL successful\n";
 }

=cut

BEGIN { $TYPEINFO{AddCRL} = ["function", "boolean", ["map", "string", "any"]]; }
sub AddCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (!defined $data->{"caPasswd"} ) {
        return $self->SetError( summary => __("Missing value 'caPasswd'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    if (!defined $data->{"days"} ) {
        return $self->SetError( summary => __("Missing value 'days'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    my $hash = {
                CAKEY   => "$CAM_ROOT/$caName/cacert.key",
                CACERT  => "$CAM_ROOT/$caName/cacert.pem",
                PASSWD  => $data->{'caPasswd'},
                DAYS    => $data->{'days'},
                OUTFORM => "PEM",
                OUTFILE => "$CAM_ROOT/$caName/crl/crl.pem"
               };
    my $ret = SCR->Execute(".openssl.issueCrl", $caName, $hash);
    if (not defined $ret) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }

    $ret = SCR->Execute(".target.bash", 
                        "cp $CAM_ROOT/$caName/crl/crl.pem $CAM_ROOT/.cas/crl_$caName.pem");
    if (! defined $ret || $ret != 0) {
        return $self->SetError( summary => "Can not copy CRL.",
                                code => "COPY_FAILED");
    }
    $ret = SCR->Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");
    if (! defined $ret || $ret != 0) {
        return $self->SetError( summary => "Can not create hash vaules in '$CAM_ROOT/.cas/'",
                                code => "C_REHASH_FAILED");
    }
    return 1;
}

=item *
C<$crl = ReadCRL($valueMap)>

Returns a CRL as plain text or parsed map.

In I<$valueMap> you can define the following keys: 

* caName (required)

* type (required - allowed values: "parsed", "extended" or "plain")

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error.

On success and type = plain the plain text view of the CRL is returned.

If the type is "parsed" or "extended" a complex structure with the single values is returned.

EXAMPLE:

 use Data::Dumper;

 foreach my $type ("parsed", "plain", "extended") {
     my $data = {
                 'caName' => 'My_CA',
                 'type'   => $type,
                };

     my $res = YaPI::CaManagement->ReadCRL($data);
     if( not defined $res ) {
         # error
     } else {
         print Data::Dumper->Dump([$res])."\n";
     }
 }

=cut

BEGIN { $TYPEINFO{ReadCRL} = ["function", "any", ["map", "string", "any"]]; }
sub ReadCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $type   = "";
    my $ret = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (! defined $data->{"type"} || 
        !grep( ($_ eq $data->{"type"}), ("parsed", "plain", "extended"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'type'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $type = $data->{"type"};
    
    my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/crl/crl.pem");
    if ($size <= 0) {
        return $self->SetError(summary => __("CRL not available."),
                               description => "No CRL found in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/crl/crl.pem",
                INFORM => "PEM",
               };
    if ($type eq "parsed") {
        $ret = SCR->Read(".openssl.getParsedCRL", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } elsif($type eq "extended") {
        $ret = SCR->Read(".openssl.getExtendedParsedCRL", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } else {
        $ret = SCR->Read(".openssl.getTXTCRL", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$file = ExportCA($valueMap)>

Export a CA to a file or returns it in different formats.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPassword (required)

* exportFormat <format> (required)

  PEM_CERT (export only the Certificate im PEM format)

  PEM_CERT_KEY (export the Certificate and the Key unencrypted in PEM Format)

  PEM_CERT_ENCKEY (export the Certificate and the Key encrypted in PEM Format)

  DER_CERT (export the Certificate in DER Format)

  PKCS12 (export the Certificate and the Key in PKCS12 Format)

  PKCS12_CHAIN (like PKCS12 + include the CA Chain )

* destinationFile (optional)

* P12Password (only for creating PKCS12 password)

The return value is "undef" on an error and "1" on success if destinationFile is defined.
If destinationFile is not defined, the CA is directly returned. If the exportFormat is
PEM_CERT_KEY or PEM_CERT_ENCKEY the certificate and the key are returned. 
Because of the PEM format it is easy to split them later.


EXAMPLE:

 foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12", "PKCS12_CHAIN") {
     my $data = {
                 'caName'       => 'My_CA',
                 'exportFormat' => $ef,
                 'caPasswd'     => "system",
                };
     if($ef =~ /^PKCS12/) {
         $data->{'P12Password'} = "p12pass";
     }

     my $res = YaPI::CaManagement->ExportCA($data);
     if( not defined $res ) {
         # error
     } else {
         if(! open(OUT, "> /tmp/certs/$ef")) {
             print STDERR "OPEN_FAILED\n";
             exit 1;
         }
         print OUT $res;
         close OUT;
     }
 }

=cut

BEGIN { $TYPEINFO{ExportCA} = ["function", "any", ["map", "string", "any"]]; }
sub ExportCA {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $destinationFile = undef;
    my $format = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};

    if (defined $data->{'destinationFile'}) {
        $data->{'destinationFile'} =~ /^(\/.+\/)[A-Za-z0-9-_.]+$/;
        if (not defined $1) {
                                           # parameter check failed
            return $self->SetError(summary => "Can not parse 'destinationFile' '".
                                               $data->{'destinationFile'}."'",
                                   code => "PARAM_CHECK_FAILED");
        }
        my $ret = SCR->Read(".target.dir", ["$1", undef]);
        if (not defined $ret) {
            return $self->SetError(summary => "Directory does not exist.",
                                   description => "'$1' does not exist.",
                                   code => "DIR_DOES_NOT_EXIST");
        }
        $destinationFile = $data->{'destinationFile'};
    }

    if (!defined $data->{"exportFormat"} || 
        !grep( ( $_ eq $data->{"exportFormat"}), 
               ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY",
                "DER_CERT", "PKCS12", "PKCS12_CHAIN"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'exportFormat'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $format = $data->{"exportFormat"};

    if (! defined $data->{'caPasswd'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                               code => "PARAM_CHECK_FAILED");
    }
    
    if (not defined SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'}, 
                                                              CACERT => 1})) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    if ($format eq "PEM_CERT") {
        my $file = SCR->Read(".target.string", "$CAM_ROOT/$caName/cacert.pem");
        if(! defined $file) {
            return $self->SetError(summary => "Can not read CA certificate.",
                                   description => "'$CAM_ROOT/$caName/cacert.pem': Read failed.",
                                   code => "OPEN_FAILED");
        }

        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "PEM_CERT_KEY") {

        my $file1 = SCR->Read(".target.string", "$CAM_ROOT/$caName/cacert.pem");
        if(! defined $file1) {
            return $self->SetError(summary => "Can not read CA certificate.",
                                   description => "'$CAM_ROOT/$caName/cacert.pem': Read failed.",
                                   code => "OPEN_FAILED");
        }

        my $hash = {
                    DATATYPE => "KEY",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/cacert.key",
                    OUTFORM  => "PEM",
                    INPASSWD => $data->{'caPasswd'},
                   };

        my $file2 = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file2) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file1."\n".$file2)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif ($format eq "PEM_CERT_ENCKEY") {
        my $file1 = SCR->Read(".target.string", "$CAM_ROOT/$caName/cacert.pem");
        if(! defined $file1) {
            return $self->SetError(summary => "Can not read CA certificate.",
                                   description => "'$CAM_ROOT/$caName/cacert.pem': Read failed.",
                                   code => "OPEN_FAILED");
        }

        my $file2 = SCR->Read(".target.string", "$CAM_ROOT/$caName/cacert.key");
        if(! defined $file2) {
            return $self->SetError(summary => "Can not read CA private key.",
                                   description => "'$CAM_ROOT/$caName/cacert.key': Read failed.",
                                   code => "OPEN_FAILED");
        }

        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file1."\n".$file2)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif ($format eq "DER_CERT") {

        my $hash = {
                    DATATYPE => "CERTIFICATE",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/cacert.pem",
                    OUTFORM  => "DER"
                   };

        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }
        
        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "PKCS12") {
        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        my $hash = {
                    DATATYPE  => "CERTIFICATE",
                    INFORM    => "PEM",
                    INFILE    => "$CAM_ROOT/$caName/cacert.pem",
                    KEYFILE   => "$CAM_ROOT/$caName/cacert.key",
                    OUTFORM   => "PKCS12",
                    INPASSWD  => $data->{'caPasswd'},
                    OUTPASSWD => $data->{'P12Password'}
                   };

        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "PKCS12_CHAIN") {

        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        my $hash = {
                    DATATYPE  => "CERTIFICATE",
                    INFORM    => "PEM",
                    INFILE    => "$CAM_ROOT/$caName/cacert.pem",
                    KEYFILE   => "$CAM_ROOT/$caName/cacert.key",
                    OUTFORM   => "PKCS12",
                    CHAIN     => 1,
                    CAPATH    => "$CAM_ROOT/.cas",
                    INPASSWD  => $data->{'caPasswd'},
                    OUTPASSWD => $data->{'P12Password'}
                   };

        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    }
}

=item *
C<$file = ExportCertificate($valueMap)>

Export a certificate to a file or returns it in different formats.

In I<$valueMap> you can define the following keys: 

* caName (required)

* keyPassword (required)

* certificate (required)

* exportFormat <format> (required)

  PEM_CERT (export only the Certificate im PEM format)

  PEM_CERT_KEY (export the Certificate and the Key unencrypted in PEM Format)

  PEM_CERT_ENCKEY (export the Certificate and the Key encrypted in PEM Format)

  DER_CERT (export the Certificate in DER Format)

  PKCS12 (export the Certificate and the Key in PKCS12 Format)

  PKCS12_CHAIN (like PKCS12 + include the CA Chain )

* destinationFile (optional)

* P12Password (only for creating PKCS12 password)

The return value is "undef" on an error and "1" on success if destinationFile is defined.
If destinationFile is not defined, the certificate is directly returned. If the exportFormat is
PEM_CERT_KEY or PEM_CERT_ENCKEY the certificate and the key are returned. 
Because of the PEM format it is easy to split them later.


EXAMPLE:

 foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12", "PKCS12_CHAIN") {
     my $data = {
                 'caName'       => 'My_CA',
                 'certificate'  => $certName,
                 'exportFormat' => $ef,
                 'keyPasswd'    => "system",
                };
     if($ef =~ /^PKCS12/) {
         $data->{'P12Password'} = "p12pass";
     }

     my $res = YaPI::CaManagement->ExportCertificate($data);
     if( not defined $res ) {
         # error
     } else {
         if(! open(OUT, "> /tmp/certs/$ef")) {
             print STDERR "OPEN_FAILED\n";
             exit 1;
         }
         print OUT $res;
         close OUT;
     }
 }

=cut

BEGIN { $TYPEINFO{ExportCertificate} = ["function", "any", ["map", "string", "any"]]; }
sub ExportCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";
    my $destinationFile = undef;
    my $format = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};

    if (! defined $data->{'certificate'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'certificate'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};
    $certificate =~ /^[[:xdigit:]]+:([[:xdigit:]]+[\d-]*)$/;
    if (not defined $1) {
                                           # parameter check failed
        return $self->SetError(summary => "Can not parse certificate name",
                               code => "PARSING_ERROR");
    }
    my $keyname = $1;
    
    if (defined $data->{'destinationFile'}) {
        $data->{'destinationFile'} =~ /^(\/.+\/)[A-Za-z0-9-_.]+$/;
        if (not defined $1) {
                                           # parameter check failed
            return $self->SetError(summary => "Can not parse 'destinationFile' '".
                                   $data->{'destinationFile'}."'",
                                   code => "PARAM_CHECK_FAILED");
        }
        my $ret = SCR->Read(".target.dir", ["$1", undef] );
        if (not defined $ret) {
            return $self->SetError(summary => "Directory does not exist.",
                                   description => "'$1' does not exist.",
                                   code => "DIR_DOES_NOT_EXIST");
        }
        $destinationFile = $data->{'destinationFile'};
    }

    if (! defined $data->{"exportFormat"} || 
        !grep( ( $_ eq $data->{"exportFormat"}),
               ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY",
                "DER_CERT", "PKCS12", "PKCS12_CHAIN"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'exportFormat'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $format = $data->{"exportFormat"};

    if (! defined $data->{'keyPasswd'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'keyPasswd'."),
                               code => "PARAM_CHECK_FAILED");
    }
    
    if (not defined SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'keyPasswd'}, 
                                                              CERT => $certificate})) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    if ($format eq "PEM_CERT") {
        my $file = SCR->Read(".target.string",
                             "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        if(! defined $file) {
            return $self->SetError(summary => "Can not read certificate.",
                                   description => "'$CAM_ROOT/$caName/newcerts/".$certificate.".pem': Read failed.",
                                   code => "OPEN_FAILED");
        }
        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "PEM_CERT_KEY") {
        if (SCR->Read(".target.size", "$CAM_ROOT/$caName/keys/".$keyname.".key") == -1) {
            return $self->SetError(summary => "Keyfile does not exist",
                                   description => "'$CAM_ROOT/$caName/keys/$keyname.key' does not exist.",
                                   code => "FILE_DOES_NOT_EXIST");
        }

        my $file1 = SCR->Read(".target.string", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        if(! defined $file1) {
            return $self->SetError(summary => "Can not read certificate.",
                                   description => "'$CAM_ROOT/$caName/newcerts/".$certificate.".pem': Read failed.",
                                   code => "OPEN_FAILED");
        }
        
        my $hash = {
                    DATATYPE => "KEY",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/keys/".$keyname.".key",
                    OUTFORM  => "PEM",
                    INPASSWD => $data->{'keyPasswd'},
                   };

        my $file2 = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file2) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file1."\n".$file2)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif ($format eq "PEM_CERT_ENCKEY") {
        my $file1 = SCR->Read(".target.string", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        if(! defined $file1) {
            return $self->SetError(summary => "Can not read certificate.",
                                   description => "'$CAM_ROOT/$caName/newcerts/".$certificate.".pem': Read failed.",
                                   code => "OPEN_FAILED");
        }

        my $file2 = SCR->Read(".target.string", "$CAM_ROOT/$caName/keys/".$keyname.".key");
        if(! defined $file2) {
            return $self->SetError(summary => "Can not read private key.",
                                   description => "'$CAM_ROOT/$caName/keys/".$keyname.".key': Read failed.",
                                   code => "OPEN_FAILED");
        }

        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file1."\n".$file2)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif ($format eq "DER_CERT") {

        my $hash = {
                    DATATYPE => "CERTIFICATE",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem",
                    OUTFORM  => "DER"
                   };

        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }
        
        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "PKCS12") {
        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        my $hash = {
                    DATATYPE  => "CERTIFICATE",
                    INFORM    => "PEM",
                    INFILE    => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem",
                    KEYFILE   => "$CAM_ROOT/$caName/keys/".$keyname.".key",
                    OUTFORM   => "PKCS12",
                    INPASSWD  => $data->{'keyPasswd'},
                    OUTPASSWD => $data->{'P12Password'}
                   };

        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "PKCS12_CHAIN") {
        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        my $hash = {
                    DATATYPE  => "CERTIFICATE",
                    INFORM    => "PEM",
                    INFILE    => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem",
                    KEYFILE   => "$CAM_ROOT/$caName/keys/".$keyname.".key",
                    OUTFORM   => "PKCS12",
                    CHAIN     => 1,
                    CAPATH    => "$CAM_ROOT/.cas",
                    INPASSWD  => $data->{'keyPasswd'},
                    OUTPASSWD => $data->{'P12Password'}
                   };

        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    }
}

=item *
C<$file = ExportCRL($valueMap)>

Export a CRL to a file or returns it in different formats.

In I<$valueMap> you can define the following keys: 

* caName (required)

* exportFormat <format> (required)

  PEM - Export the CRL in PEM format

  DER - Export the CRL in DER format

* destinationFile (optional)

The return value is "undef" on an error and "1" on success,
if 'destinationFile' is defined. 
If 'destinationFile' is not defined the CRL is returned.

EXAMPLE:

 foreach my $ef ("PEM", "DER") {
     my $data = {
                 'caName'       => 'My_CA',
                 'exportFormat' => $ef,
                };
     
     my $res = YaPI::CaManagement->ExportCRL($data);
     if( not defined $res ) {
         # error
     } else {
         if(! open(OUT, "> /tmp/certs/CRL_$ef")) {
             print STDERR "OPEN_FAILED\n";
         }
         print OUT $res;
         close OUT;
     }
 }

=cut

BEGIN { $TYPEINFO{ExportCRL} = ["function", "any", ["map", "string", "any"]]; }
sub ExportCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $destinationFile = undef;
    my $format = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
 
    if (!defined $data->{"exportFormat"} || 
        !grep( ( $_ eq $data->{"exportFormat"}), ("PEM", "DER"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'exportFormat'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $format = $data->{"exportFormat"};

    if (defined $data->{'destinationFile'}) {
        $data->{'destinationFile'} =~ /^(\/.+\/)[A-Za-z0-9-_.]+$/;
        if (not defined $1) {
                                           # parameter check failed
            return $self->SetError(summary => "Can not parse 'destinationFile' '".
                                   $data->{'destinationFile'}."'",
                                   code => "PARAM_CHECK_FAILED");
        }
        my $ret = SCR->Read(".target.dir", ["$1", undef] );
        if (not defined $ret) {
            return $self->SetError(summary => "Directory does not exist.",
                                   description => "'$1' does not exist",
                                   code => "DIR_DOES_NOT_EXIST");
        }
        $destinationFile = $data->{'destinationFile'};
    }

    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/crl/crl.pem") == -1) {
        return $self->SetError(summary => __("CRL does not exist."),
                               code => "FILE_DOES_NOT_EXIST");
    }

    if ($format eq "PEM") {

        my $file = SCR->Read(".target.string", "$CAM_ROOT/$caName/crl/crl.pem");
        if(! defined $file) {
            return $self->SetError(summary => "Can not read CRL.",
                                   description => "'$CAM_ROOT/$caName/crl/crl.pem': Read failed.",
                                   code => "OPEN_FAILED");
        }
        if (defined $destinationFile) {
            if(! SCR->Write(".target.string", $destinationFile, $file)) {
                return $self->SetError(summary => "Can not write to destination file.",
                                       description => "'$destinationFile'",
                                       code => "OPEN_FAILED");
            }
            return 1;
        } else {
            return $file;
        }
    } elsif ($format eq "DER") {
        my $hash = {
                    DATATYPE => "CRL",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/crl/crl.pem",
                    OUTFORM  => "DER"
                   };
        
        if (defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }
        
        my $file = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (not defined $file) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        if (defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } else {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'exportFormat'."),
                               code => "PARAM_CHECK_FAILED");
    }
}

=item *
C<$bool = Verify($valueMap)>

Verify a certificate.

In I<$valueMap> you can define the following keys: 

* caName (required)

* certificate (required)

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" if the verification failed.
On success it returns "1".

EXAMPLE:

 $data = {
           'caName'      => 'My_CA',
           'certificate' => $certName
         };

 my $Vret = YaPI::CaManagement->Verify($data);
 if(not defined $Vret) {
     # verification failed
 } else {
     print "OK \n";
 }

=cut

BEGIN { $TYPEINFO{Verify} = ["function", "boolean", ["map", "string", "any"]]; }
sub Verify {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};

    if (!defined $data->{'certificate'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'certificate'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};
    
    my $hash = { 
                CERT => "$CAM_ROOT/$caName/newcerts/$certificate.pem",
                CAPATH => "$CAM_ROOT/.cas/",
                CRLCHECK => 1
               };
    my $ret = SCR->Execute(".openssl.verify", $caName, $hash);
    if ( not defined $ret ) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    return $ret;
}

=item *
C<$bool = AddSubCA($valueMap)>

create a new CA signed by another CA.

In I<$valueMap> you can define the following keys: 

* newCaName (required - the name of the new CA)

* caName (required - the name of the CA which should issue the new CA)

* keyPasswd (required - password for the new CA)

* caPasswd (required - password for the CA which should issue the new CA)

* commonName (required)

* emailAddress (depending on CA policy)

* keyLength (required)

* days (required)

* countryName (depending on CA policy)

* stateOrProvinceName (depending on CA policy)

* localityName (depending on CA policy)

* organizationName (depending on CA policy)

* organizationalUnitName (depending on CA policy)

* challengePassword

* unstructuredName

* basicConstraints (required)

* nsComment

* nsCertType

* keyUsage

* subjectKeyIdentifier

* authorityKeyIdentifier

* subjectAltName

* issuerAltName

* nsBaseUrl

* nsRevocationUrl

* nsCaRevocationUrl

* nsRenewalUrl

* nsCaPolicyUrl

* nsSslServerName

* extendedKeyUsage

* authorityInfoAccess

* crlDistributionPoints

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             'caName'                => 'My_CA',
             'newCaName'             => 'My_New_Sub_CA',
             'keyPasswd'             => 'newPasswd',
             'caPasswd'              => 'system',
             'commonName'            => 'My CA New Sub CA',
             'emailAddress'          => 'my@example.com',
             'keyLength'             => '2048',
             'days'                  => '3000',
             'countryName'           => 'US',
             'localityName'          => 'New York',
             'organizationName'      => 'My Inc.',
             'basicConstraints'      => 'CA:TRUE',
             'crlDistributionPoints' => 'URI:http://my.example.com/',
            };

 my $res = YaPI::CaManagement->AddSubCA($data);
 if( not defined $res ) {
     # error    
 } else {
     print "OK\n";
 }

=cut

BEGIN { $TYPEINFO{AddSubCA} = ["function", "boolean", ["map", "string", "any"] ]; }
sub AddSubCA {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $newCaName  = "";
    
    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};

    if (!defined $data->{"newCaName"}) {
        return $self->SetError( summary => __("Missing value 'newCaName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $newCaName = $data->{"newCaName"};
    
    if (!defined $data->{"keyPasswd"}) {
        return $self->SetError( summary => __("Missing value 'keyPasswd'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    if (!defined $data->{'caPasswd'} ) {
        return $self->SetError( summary => __("Missing value 'caPasswd'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    if (!defined $data->{"commonName"}) {
        return $self->SetError( summary => __("Missing value 'commonName'."),
                                code    => "CHECK_PARAM_FAILED");
    }

    if (!defined $data->{"basicConstraints"} || $data->{"basicConstraints"} !~ /CA:TRUE/i) {
        return $self->SetError( summary => __("According to 'basicConstraints', this is not a CA."),
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"keyLength"}) {
        $data->{"keyLength"} = 2048;
    }
    if (!defined $data->{"days"}) {
        $data->{"days"} = 3650;
    }
    my $request = $self->AddRequest($data);
    if (not defined $request) {
        return undef;
    }
    $data->{'request'} = $request;
    my $certificate = $self->IssueCertificate($data);
    if (! defined $certificate) {
        my $caName = $data->{'caName'};
        SCR->Write(".caTools.delCAM", $caName, {MD5 => $request});
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/req/".$request.".req");
        return undef;
    }

    if (not SCR->Write(".caTools.caInfrastructure", $data->{"newCaName"})) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    my $retCode = SCR->Execute(".target.bash", "cp ".
                               "$CAM_ROOT/$caName/keys/".$request.".key ".
                               "$CAM_ROOT/$newCaName/cacert.key");
    if (! defined $retCode || $retCode != 0) {
        YaST::caUtils->cleanCaInfrastructure($newCaName);
        return $self->SetError(summary => "Can not copy the private key.",
                               code => "COPY_FAILED");
    }

    $retCode = SCR->Execute(".target.bash", "cp ".
                            "$CAM_ROOT/$caName/newcerts/".$certificate.".pem ".
                            "$CAM_ROOT/$newCaName/cacert.pem");
    if (! defined $retCode || $retCode != 0) {
        YaST::caUtils->cleanCaInfrastructure($newCaName);
        return $self->SetError(summary => "Can not copy the certificate.",
                               code => "COPY_FAILED");
    }

    $retCode = SCR->Execute(".target.bash", "cp $CAM_ROOT/$newCaName/cacert.pem $CAM_ROOT/.cas/$newCaName.pem");
    if (!defined $retCode || $retCode != 0) {
        #        YaST::caUtils->cleanCaInfrastructure($newCaName);
        return $self->SetError( summary => "Can not copy CA certificate",
                                code => "COPY_FAILED");
    }
    $retCode = SCR->Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");
    if (!defined $retCode || $retCode != 0) {
        #        YaST::caUtils->cleanCaInfrastructure($newCaName);
        return $self->SetError( summary => "Can not create hash vaules in '$CAM_ROOT/.cas/'",
                                code => "C_REHASH_FAILED");
    }
    
    return 1;
}

=item *
C<$bool = ExportCAToLDAP($valueMap)>

Export a CA in a LDAP Directory.

In I<$valueMap> you can define the following keys: 

* caName (required)

* ldapHostname (required - hostname or IP address)

* ldapPort (default: 389)

* destinationDN (required)

* bindDN (required)

* ldapPasswd (required)

B<destinationDN> is the DN to the entry where to store 
the CA. The following objectclasses are used:

* cRLDistributionPoint

* pkiCA

The first attribute type of the DN must be 'cn'.


The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             ldapHostname  => 'myhost.example.com',
             ldapPort      => 389,
             destinationDN => "cn=My_CA,ou=PKI,dc=suse,dc=de",
             BindDN        => "cn=Admin,dc=example,dc=com",
             ldapPasswd    => "system"
            };

    my $res = YaPI::CaManagement->ExportCAToLDAP($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{ExportCAToLDAP} = ["function", "boolean", ["map", "string", "any"] ]; }
sub ExportCAToLDAP {
    my $self = shift;
    my $data = shift;
    my $caName  = "";
    my $action = "add";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};
    
    if (! defined $data->{'ldapHostname'} ||
        !(IP->Check4($data->{'ldapHostname'}) || 
          IP->Check6($data->{'ldapHostname'}) || 
          Hostname->CheckFQ($data->{'ldapHostname'}))
       ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapHostname'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'ldapPort'} ||
        $data->{'ldapPort'} eq "") {
        # setting default value 
        $data->{'ldapPort'} = 389;
    }

    if ($data->{'ldapPort'} !~ /^\d+$/ ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapPort'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    my $object = X500::DN->ParseRFC2253($data->{'destinationDN'});
    if (! defined $data->{'destinationDN'} || 
        $data->{'destinationDN'} eq "" ||
        ! defined $object) {
        # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'destinationDN'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if($data->{'destinationDN'} !~ /^cn=/) {
        # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'destinationDN'."),
                               description => "First attribute type must be 'cn'",
                               code    => "PARAM_CHECK_FAILED");
    }

    my $container = "";
    for(my $i = scalar($object->getRDNs())-2; $i >= 0; $i--) {
        
        my @a = $object->getRDN($i)->getAttributeTypes();
        
        if($container eq "") {
            $container = $a[0]."=".$object->getRDN($i)->getAttributeValue($a[0]);
        } else {
            $container = $container.",".$a[0]."=".$object->getRDN($i)->getAttributeValue($a[0]);
        }        
    }

    if (! defined $data->{'BindDN'} || 
        $data->{'BindDN'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'BindDN'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'ldapPasswd'} || 
        $data->{'ldapPasswd'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    # test if this File already exists
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/cacert.pem") == -1) {
        return $self->SetError(summary => __("CA certificate does not exist."),
                               code => "FILE_DOES_NOT_EXIST");
    }

    my $ca = SCR->Read(".openssl.getParsedCert", $caName, 
                       {
                        INFILE => "$CAM_ROOT/$caName/cacert.pem",  INFORM => "PEM"});
    if (not defined $ca) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    my ($body) = ($ca->{'BODY'} =~ /-----BEGIN[\s\w]+-----\n([\S\s\n]+)\n-----END[\s\w]+-----/);

    if (! defined $body || $body eq "") {
        return $self->SetError(summary => "Can not parse the CA certificate",
                               code => "PARSE_ERROR");
    }
    
    # default is try; disable only, if ldap client says no
    my $use_tls = "try";

    if(Ldap->Read()) {
        my $ldapMap = Ldap->Export();
        if(defined $ldapMap->{ldap_tls}) {
            if($ldapMap->{ldap_tls} == 1) {
                $use_tls = "yes" 
            } else {
                $use_tls = "no";
            }
        }
    }

    if (! SCR->Execute(".ldap", {"hostname" => $data->{'ldapHostname'},
                                 "port"     => $data->{'ldapPort'},
                                 "use_tls"  => $use_tls })) {
        return $self->SetError(summary => "LDAP init failed",
                               code => "SCR_INIT_FAILED");
    }

    if (! SCR->Execute(".ldap.bind", {"bind_dn" => $data->{'BindDN'},
                                      "bind_pw" => $data->{'ldapPasswd'}}) ) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "LDAP bind failed",
                               code => "SCR_INIT_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    my $dnList = SCR->Read(".ldap.search", {
                                            "base_dn" => $container,
                                            "filter" => 'objectclass=*',
                                            "scope" => 0,
                                            "dn_only" => 1
                                           });
    if (! defined $dnList) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "Container '$container' is not available in the LDAP directory.",
                               code => "LDAP_SEARCH_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    $dnList = SCR->Read(".ldap.search", {
                                         "base_dn" => $data->{'destinationDN'},
                                         "filter"  => 'objectclass=*',
                                         "scope"   => 0,
                                         "dn_only" => 1
                                        });
    if (! defined $dnList) {
        my $ldapERR = SCR->Read(".ldap.error");
        if ($ldapERR->{'code'} == 32) {
            # code 32 is 'no such object => we have to add a new entry
            $action = "add";
        } else {
            return $self->SetError(summary => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                   code => "LDAP_SEARCH_FAILED");
        }
    } else {
        # entry exists => we have to modify it
        $action = "modify";
    }
    
    if($action eq "add") {

        my $entry = {
                     'objectClass'          => [ 'cRLDistributionPoint', 'pkiCA' ],
                     'cn'                   => $caName,
                     'cACertificate;binary' => YaST::YCP::Byteblock(decode_base64($body))
                    };

        if (not SCR->Write(".ldap.add", { dn => $data->{'destinationDN'}} , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not add CA certificate to LDAP directory.",
                                   code => "LDAP_ADD_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }

    } elsif($action eq "modify") {

        my $entry = {
                     'cACertificate;binary' => YaST::YCP::Byteblock(decode_base64($body))
                    };
        if (not SCR->Write(".ldap.modify", { dn => $data->{'destinationDN'}} , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not modify CA certificate in LDAP directory.",
                                   code => "LDAP_MODIFY_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
        
    } else {
        #this should never happen :-)
    }
    
    return 1;
}

=item *
C<$bool = ExportCRLToLDAP($valueMap)>

Export a CRL in a LDAP Directory

In I<$valueMap> you can define the following keys: 

* caName (required)

* ldapHostname (required - hostname or IP address)

* ldapPort (default: 389)

* destinationDN (required)

* bindDN (required)

* ldapPasswd (required)

B<destinationDN> is the DN to the entry where to store 
the CA. The following objectclasses are used:

* cRLDistributionPoint

* pkiCA

The first attribute type of the DN must be 'cn'.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             ldapHostname  => 'myhost.example.com',
             ldapPort      => 389,
             destinationDN => "cn=My_CA,ou=PKI,dc=suse,dc=de",
             BindDN        => "cn=Admin,dc=example,dc=com",
             ldapPasswd    => "system"
            };

    my $res = YaPI::CaManagement->ExportCRLToLDAP($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{ExportCRLToLDAP} = ["function", "boolean", ["map", "string", "any"] ]; }
sub ExportCRLToLDAP {
    my $self = shift;
    my $data = shift;
    my $caName  = "";
    my $action  = "add";
    my $doCRLdp = 0;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};
    
    if (! defined $data->{'ldapHostname'} ||
        !(IP->Check4($data->{'ldapHostname'}) || 
          IP->Check6($data->{'ldapHostname'}) || 
          Hostname->CheckFQ($data->{'ldapHostname'}))
       ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapHostname'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'ldapPort'} ||
        $data->{'ldapPort'} eq "") {
        # setting default value 
        $data->{'ldapPort'} = 389;
    }

    if ($data->{'ldapPort'} !~ /^\d+$/ ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapPort'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    my $object = X500::DN->ParseRFC2253($data->{'destinationDN'});
    if (! defined $data->{'destinationDN'} || 
        $data->{'destinationDN'} eq "" ||
        ! defined $object) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'destinationDN'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    if($data->{'destinationDN'} !~ /^cn=/) {
        # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'destinationDN'."),
                               description => "First attribute type must be 'cn'",
                               code    => "PARAM_CHECK_FAILED");
    }

    my $container = "";
    for(my $i = scalar($object->getRDNs())-2; $i >= 0; $i--) {
        
        my @a = $object->getRDN($i)->getAttributeTypes();
        
        if($container eq "") {
            $container = $a[0]."=".$object->getRDN($i)->getAttributeValue($a[0]);
        } else {
            $container = $container.",".$a[0]."=".$object->getRDN($i)->getAttributeValue($a[0]);
        }
    }

    if (! defined $data->{'BindDN'} || 
        $data->{'BindDN'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'BindDN'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'ldapPasswd'} || 
        $data->{'ldapPasswd'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    # test if this File already exists
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/crl/crl.pem") == -1) {
        return $self->SetError(summary => __("CRL does not exist."),
                               code => "FILE_DOES_NOT_EXIST");
    }

    my $crl = SCR->Read(".openssl.getParsedCRL", $caName, 
                        {
                         INFILE => "$CAM_ROOT/$caName/crl/crl.pem",  INFORM => "PEM"});
    if (not defined $crl) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    my ($body) = ($crl->{'BODY'} =~ /-----BEGIN[\s\w]+-----\n([\S\s\n]+)\n-----END[\s\w]+-----/);

    if (! defined $body || $body eq "") {
        return $self->SetError(summary => "Can not parse the CRL",
                               code => "PARSE_ERROR");
    }

    # default is try; disable only, if ldap client says no
    my $use_tls = "try";

    if(Ldap->Read()) {
        my $ldapMap = Ldap->Export();
        if(defined $ldapMap->{ldap_tls} && $ldapMap->{ldap_tls} == 0) {
            if($ldapMap->{ldap_tls} == 1) {
                $use_tls = "yes" 
            } else {
                $use_tls = "no";
            }
        }
    }

    if (! SCR->Execute(".ldap", {"hostname" => $data->{'ldapHostname'},
                                 "port"     => $data->{'ldapPort'},
                                 "use_tls"  => $use_tls })) {
        return $self->SetError(summary => "LDAP init failed",
                               code => "SCR_INIT_FAILED");
    }

    if (! SCR->Execute(".ldap.bind", {"bind_dn" => $data->{'BindDN'},
                                      "bind_pw" => $data->{'ldapPasswd'}}) ) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "LDAP bind failed",
                               code => "SCR_INIT_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    my $dnList = SCR->Read(".ldap.search", {
                                            "base_dn" => $container,
                                            "filter" => 'objectclass=*',
                                            "scope" => 0,
                                            "dn_only" => 1
                                           });
    if (! defined $dnList) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "Container '$container' is not available in the LDAP directory.",
                               code => "LDAP_SEARCH_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    $dnList = SCR->Read(".ldap.search", {
                                         "base_dn" => $data->{'destinationDN'},
                                         "filter" => 'objectclass=*',
                                         "scope" => 0,
                                         "dn_only" => 1
                                        });
    if (! defined $dnList) {
        my $ldapERR = SCR->Read(".ldap.error");
        if ($ldapERR->{'code'} == 32) {
            # code 32 is 'no such object => we have to add a new entry
            $action = "add";
            $doCRLdp = 1;
        } else {
            return $self->SetError(summary => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                   code => "LDAP_SEARCH_FAILED");
        }
    } else {
        # entry exists => we have to modify it
        $action = "modify";

        my $attr = SCR->Read(".ldap.search", {
                                              "base_dn" => $data->{'destinationDN'},
                                              "filter" => 'objectclass=cRLDistributionPoint',
                                              "scope" => 0,
                                              "attrs" => [ "certificateRevocationList" ],
                                             });

        if (! defined $attr) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                   code => "LDAP_SEARCH_FAILED");
        }
        if (! defined $attr->[0]->{"certificateRevocationList;binary"} || 
            $attr->{"certificateRevocationList;binary"} eq "") {
            $doCRLdp = 1;
        }

    }

    if ($action eq "add") {

        my $entry = {
                     'objectClass'          => [ 'cRLDistributionPoint', 'pkiCA' ],
                     'cn'                   => $caName,
                     'certificateRevocationList;binary' => YaST::YCP::Byteblock(decode_base64($body))
                    };

        if (not SCR->Write(".ldap.add", { dn => $data->{'destinationDN'}} , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not add CRL certificate to LDAP directory.",
                                   code => "LDAP_ADD_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }

    
    } elsif ($action eq "modify") {

        my $entry = {
                     'certificateRevocationList;binary' => YaST::YCP::Byteblock(decode_base64($body))
                    };
        if (not SCR->Write(".ldap.modify", { dn => $data->{'destinationDN'}} , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not modify CRL certificate in LDAP directory.",
                                   code => "LDAP_MODIFY_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
        
    } else {
        #this should never happen :-)
    }


    if ( $doCRLdp ) {
        # seems to be the first export, so
        # check for crlDistributionPoint in config template
        
        my $crlDP_client = SCR->Read(".CAM.openssl_tmpl.value.$caName.v3_client.crlDistributionPoints");
        my $crlDP_server = SCR->Read(".CAM.openssl_tmpl.value.$caName.v3_server.crlDistributionPoints");
        my $crlDP_ca     = SCR->Read(".CAM.openssl_tmpl.value.$caName.v3_ca.crlDistributionPoints");
        
        if ( (! defined $crlDP_client || $crlDP_client eq "") &&
             (! defined $crlDP_server || $crlDP_server eq "") &&
             (! defined $crlDP_ca     || $crlDP_ca     eq "") 
           ) {
            # if all crlDP are not defined or empty, than we can add it automaticaly
            
            my $crlDP = "URI:";
            $crlDP   .= "ldap://".$data->{'ldapHostname'}.":".$data->{'ldapPort'}."/";
            $crlDP   .= uri_escape($data->{'destinationDN'});
            
            if ( !SCR->Write(".CAM.openssl_tmpl.value.$caName.v3_client.crlDistributionPoints", $crlDP) ||
                 !SCR->Write(".CAM.openssl_tmpl.value.$caName.v3_server.crlDistributionPoints", $crlDP) ||
                 !SCR->Write(".CAM.openssl_tmpl.value.$caName.v3_ca.crlDistributionPoints", $crlDP)
               ) {
                y2warning("Writing crlDistributionPoints to openssl.cnf.tmpl failed.");
                # the main action was successful. So we return 1 and not "undef"
                return 1; 
            }
        }
    }
    
    return 1;
}

=item *
C<$defaultsMap = ReadLDAPExportDefaults($valueMap)>

Return the defaults for export CA, CRL or certificates to
LDAP. If an error ocured with I<code = LDAP_CONFIG_NEEDED>,
you have to call B<InitLDAPcaManagement()> first.

In I<$valueMap> you can define the following keys:

* type (required - allowed values are: "ca", "crl", "certificate")

* caName (optional)

* commonName (required - only if 'type' is 'certificate')

* emailAddress (optional - only if 'type' is 'certificate')

* subjectAltName (optional - only if 'type' is 'certificate')

The return value is "undef" on an error.

On success a map is returned with the following keys:

* ldapHostname

* ldapPort

* BindDN

* destinationDN

The value of I<destinationDN> is an array.

EXAMPLE:

 use Data::Dumper;

 my $data = {
             'caName' => 'My_CA',
             'type'   => 'ca'
            };

 my $res = YaPI::CaManagement->ReadLDAPExportDefaults($data);

if( not defined $res ) {
     # error
 } else {
     print Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadLDAPExportDefaults} = ["function", 
                                             ["map", "string", "any"], 
                                             ["map", "string", "any"] ]; }
sub ReadLDAPExportDefaults {
    my $self = shift;
    my $data = shift;
    my $caName = undef;
    my $type = "ca";
    my $ldapMap = {};
    my $retMap = {};
    my $ldapret = undef;
    my $commonName = undef;
    my @emailAddresses = ();

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (defined $data->{'caName'} ) {
        $caName = $data->{'caName'};
    }
    
    if(!defined $data->{'type'} ||
       !grep( ($_ eq $data->{'type'}), ("ca", "crl", "certificate"))) {
        return $self->SetError(summary => __("Invalid value for parameter 'type'."),
                               description => "'type' must be 'ca', 'crl' or 'certificate'.\n".
                                              "'type' is '".$data->{'type'}."'",
                               code    => "PARAM_CHECK_FAILED");
    }
    $type = $data->{'type'};

    if($type eq "certificate") {
        if(!defined $data->{'commonName'} || $data->{'commonName'} eq "") {
            return $self->SetError(summary => __("Missing parameter 'commonName'."),
                                   code => "PARAM_CHECK_FAILED");
        }
        $commonName = $data->{'commonName'};
        if(defined $data->{'emailAddress'} && $data->{'emailAddress'} ne "") {
            push(@emailAddresses, $data->{'emailAddress'});
        }
        
        # get other email addresses from subject alt name
        if(defined $data->{'subjectAltName'} && 
           $data->{'subjectAltName'} =~ /email/)
          {
              my @eaddr = split(/\s*,\s*/, $data->{'subjectAltName'});
              foreach my $item (@eaddr) {
                  if($item =~ /email:([^@]+@[^@]+)/ && defined $1 && $1 ne "") {
                      push(@emailAddresses, $1);
                  }
              }
          }
    }

    # default is try; disable only, if ldap client says no
    my $use_tls = "try";

    if(Ldap->Read()) {
        $ldapMap = Ldap->Export();

        if(defined $ldapMap->{'ldap_server'} && $ldapMap->{'ldap_server'} ne "") {
            my $dummy = $ldapMap->{'ldap_server'};
            $ldapMap->{'ldap_server'} = Ldap->GetFirstServer("$dummy");
            $ldapMap->{'ldap_port'} = Ldap->GetFirstPort("$dummy");
        } else {
            return $self->SetError( summary => "No LDAP Server configured",
                                    code => "HOST_NOT_FOUND");
        } 
        if(defined $ldapMap->{ldap_tls} ) {
            if($ldapMap->{ldap_tls} == 1) {
                $use_tls = "yes" 
            } else {
                $use_tls = "no";
            }
        }
    }

    if (! SCR->Execute(".ldap", {"hostname" => $ldapMap->{'ldap_server'},
                                 "port"     => $ldapMap->{'ldap_port'},
                                 "use_tls"  => $use_tls })) {
        return $self->SetError(summary => "LDAP init failed",
                               code => "SCR_INIT_FAILED");
    }
    
    # anonymous bind
    if (! SCR->Execute(".ldap.bind", {}) ) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "LDAP bind failed",
                               code => "SCR_INIT_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    if(defined $type && ($type eq "ca" || $type eq "crl")) {
        # Is there already a ldapconfig object?
  
        if(defined $caName && $caName ne "") {
            $ldapret = SCR->Read(".ldap.search", {
                                                  "base_dn" => $ldapMap->{'base_config_dn'},
                                                  "filter" => "(& (objectclass=suseCaConfiguration) (cn=$caName))",
                                                  "scope" => 2,
                                                  "not_found_ok" => 1,
                                                  "attrs" => [ 'suseDefaultBase' ]
                                                 });
            if (! defined $ldapret) {
                my $ldapERR = SCR->Read(".ldap.error");
                return $self->SetError(summary => "LDAP search failed!",
                                       description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                       code => "LDAP_SEARCH_FAILED");
            }
            if(@$ldapret > 0) {
                $retMap->{'destinationDN'} = $ldapret->[0]->{susedefaultbase};
            }
        }
        
        if(!exists $retMap->{'destinationDN'} || $retMap->{'destinationDN'} eq "") {
            $ldapret = SCR->Read(".ldap.search", {
                                                  "base_dn" => $ldapMap->{'base_config_dn'},
                                                  "filter" => '(& (objectclass=suseCaConfiguration) (cn=defaultCA))',
                                                  "scope" => 2,
                                                  "not_found_ok" => 1
                                                 });
            if (! defined $ldapret) {
                my $ldapERR = SCR->Read(".ldap.error");
                return $self->SetError(summary => "LDAP search failed!",
                                       description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                       code => "LDAP_SEARCH_FAILED");
            }
            if(@$ldapret > 0) {
                $retMap->{'destinationDN'} = $ldapret->[0]->{susedefaultbase};
            }
        }
        
        if(!exists $retMap->{'destinationDN'} || $retMap->{'destinationDN'} eq "") {
            return $self->SetError(summary => __("No configuration available in LDAP."),
                                   code => "LDAP_CONFIG_NEEDED");
        }
       
        # complete the destinationDN 
        for(my $i = 0; $i < scalar(@{$retMap->{'destinationDN'}}); $i++) {
            $retMap->{'destinationDN'}->[$i] = "cn=$caName,".$retMap->{'destinationDN'}->[$i];
        }

    } else {
        # type is certificate
        
        my $filter = undef;

        if(defined $emailAddresses[0]) {

            $filter =  "(& (objectclass=inetOrgPerson) (| (cn=$commonName) ";
            foreach my $em (@emailAddresses) {
                $filter .= "(mail=$em) ";
            }
            $filter .= "))";

        } else {
            $filter =  "(& (objectclass=inetOrgPerson) (cn=$commonName))";
        }

        $ldapret = SCR->Read(".ldap.search", {
                                              "base_dn" => $ldapMap->{'ldap_domain'},
                                              "filter" => $filter,
                                              "scope" => 2,
                                              "not_found_ok" => 1,
                                              "dn_only" => 1
                                             });
        if (! defined $ldapret) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "LDAP search failed!",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                   code => "LDAP_SEARCH_FAILED");
        }
        if(@$ldapret > 0) {
            $retMap->{'destinationDN'} = $ldapret;
        }
        
    }
    $retMap->{'ldapHostname'} = $ldapMap->{'ldap_server'};
    $retMap->{'ldapPort'} = $ldapMap->{'ldap_port'};
    $retMap->{'BindDN'} = $ldapMap->{'bind_dn'};

    return $retMap;
}

=item *
C<$bool = InitLDAPcaManagement($valueMap)>

Creates the default configuration structure in LDAP

In I<$valueMap> you can define the following keys: 

* ldapPasswd (required)

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             'ldapPasswd' => 'system'
            };

 my $res = YaPI::CaManagement->InitLDAPcaManagement($data);
 if( not defined $res ) {
     # error
 } else {
     print "OK\n";
 }

=cut

BEGIN { $TYPEINFO{InitLDAPcaManagement} = ["function", "boolean", 
                                             ["map", "string", "any"] ]; }

sub InitLDAPcaManagement {
    my $self = shift;
    my $data = shift;
    my $addConfigDN = 0;
    my $addDefaultConfig = 0;
    my $ldapMap = undef;
    my $ldapret = undef;

    if(!defined $data->{ldapPasswd} || $data->{ldapPasswd} eq "") {
        return $self->SetError( summary => __("LDAP password required."),
                                code => "PARAM_CHECK_FAILED");
    }

    # default is try; disable only, if ldap client says no
    my $use_tls = "try";

    if(Ldap->Read()) {
        $ldapMap = Ldap->Export();
        if(defined $ldapMap->{'ldap_server'} && $ldapMap->{'ldap_server'} ne "") {
            my $dummy = $ldapMap->{'ldap_server'};
            $ldapMap->{'ldap_server'} = Ldap->GetFirstServer("$dummy");
            $ldapMap->{'ldap_port'} = Ldap->GetFirstPort("$dummy");
        } else {
            return $self->SetError( summary => "No LDAP Server configured",
                                    code => "HOST_NOT_FOUND");
        } 
    }
    
    my $ret = Ldap->LDAPInit ();
    if ($ret ne "") {
        
        return $self->SetError(summary => "LDAP init failed",
                               code => "SCR_INIT_FAILED");
    }
    
    # bind
    if (! SCR->Execute(".ldap.bind", { bind_dn => $ldapMap->{'bind_dn'},
                                       bind_pw => $data->{ldapPasswd}
                                     }) ) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "LDAP bind failed",
                               code => "SCR_INIT_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    # search for base_config_dn
    $ldapret = SCR->Read(".ldap.search", 
                         {
                          "base_dn" => $ldapMap->{'base_config_dn'},
                          "filter" => 'objectclass=*',
                          "scope" => 0,
                          "dn_only" => 1
                         });
    if (! defined $ldapret) {
        my $ldapERR = SCR->Read(".ldap.error");
        if ($ldapERR->{'code'} == 32) {
            # code 32 is 'no such object => we have to add a new entry

            Ldap->SetGUI(YaST::YCP::Boolean(0));
            Ldap->SetBindPassword($data->{ldapPasswd});
            
            if(! Ldap->CheckBaseConfig($ldapMap->{'base_config_dn'})) {
                Ldap->SetGUI(YaST::YCP::Boolean(1));
                return $self->SetError(summary => "Can not add base configuration entry!",
                                       code => "LDAP_ADD_FAILED");
            }
            Ldap->SetGUI(YaST::YCP::Boolean(1));
            
        } else {
            return $self->SetError(summary => "LDAP search failed!",
                                   code => "LDAP_SEARCH_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
    }
    
    # search for default Config entry
    $ldapret = SCR->Read(".ldap.search", 
                         {
                          "base_dn" => $ldapMap->{'base_config_dn'},
                          "filter" => '(& (objectclass=suseCaConfiguration) (cn=defaultCA))',
                          "scope" => 2,
                          "not_found_ok" => 1
                         });
    if (! defined $ldapret) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "LDAP search failed!",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                               code => "LDAP_SEARCH_FAILED");
    }
    if(@$ldapret <= 0) {
        my $defaultCAcontainer = "ou=PKI,".$ldapMap->{'ldap_domain'};

        # search for the default CA container 
        $ldapret = SCR->Read(".ldap.search", {
                                              "base_dn" => $defaultCAcontainer,
                                              "filter" => 'objectclass=*',
                                              "scope" => 0,
                                              "dn_only" => 1
                                             });
        if (! defined $ldapret) {
            my $ldapERR = SCR->Read(".ldap.error");
            if ($ldapERR->{'code'} == 32) {

                # create default CA container
                my $entry = {
                             "objectClass" => [ "organizationalUnit" ],
                             "ou" => "PKI",
                            };
                
                $ldapret = SCR->Write(".ldap.add", { dn => $defaultCAcontainer }, $entry);
            
                if(! defined $ldapret) {
                    my $ldapERR = SCR->Read(".ldap.error");
                    return $self->SetError(summary => "Can not add CA configuration entry!",
                                           code => "LDAP_ADD_FAILED",
                                           description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
                }
            } else {
                return $self->SetError(summary => "LDAP search failed!",
                                       description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'},
                                       code => "LDAP_SEARCH_FAILED");
            }
        }

        # create default CA config entry
        $ldapret = SCR->Write(".ldap.add", 
                              { dn => "cn=defaultCA,".$ldapMap->{'base_config_dn'}},
                              { 
                               "objectClass" => [ "suseCaConfiguration"],
                               "cn" => "defaultCA",
                               "suseDefaultBase", $defaultCAcontainer
                              }
                             );
        if(! defined $ldapret) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not add CA configuration entry!",
                                   code => "LDAP_ADD_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
    }
    return 1;    
}


=item *
C<$bool = ExportCertificateToLDAP($valueMap)>

Export a Certificate in a LDAP Directory. This function
is designed for exporting user certificates. The destination
entry must have the objectclass 'inetOrgPerson'.

In I<$valueMap> you can define the following keys: 

* caName (required)

* certificate (required)

* keyPasswd (optional - if defined, then p12Passwd is required)

* p12Passwd (optional)

* ldapHostname (required - hostname or IP address)

* ldapPort (default: 389)

* destinationDN (required)

* bindDN (required)

* ldapPasswd (required)

If the private key of the certificate is available and the
parameter 'keyPasswd' and 'p12Passwd' are defined, an export 
in PKCS12 format is also done.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             certificate   => $certificateName,
             ldapHostname  => 'myhost.example.com',
             ldapPort      => 389,
             destinationDN => "uid=me,ou=people,dc=suse,dc=de",
             BindDN        => "cn=Admin,dc=example,dc=com",
             ldapPasswd    => "system"
            };

    my $res = YaPI::CaManagement->ExportCertificateToLDAP($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{ExportCertificateToLDAP} = ["function", "boolean", ["map", "string", "any"] ]; }
sub ExportCertificateToLDAP {
    my $self = shift;
    my $data = shift;
    my $caName  = "";
    my $certificate = "";
    my $key = "";
    my $exportPKCS12 = 0;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};

    if (!defined $data->{'certificate'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'certificate'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{'certificate'};

    $certificate =~ /^[[:xdigit:]]+:([[:xdigit:]]+[\d-]*)$/;
    if(defined $1 && $1 ne "") {
        $key = $1;
    }
    
    if (! defined $data->{'ldapHostname'} ||
        !(IP->Check4($data->{'ldapHostname'}) || 
          IP->Check6($data->{'ldapHostname'}) || 
          Hostname->CheckFQ($data->{'ldapHostname'}))
       ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapHostname'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'ldapPort'} ||
        $data->{'ldapPort'} eq "") {
        # setting default value 
        $data->{'ldapPort'} = 389;
    }

    if ($data->{'ldapPort'} !~ /^\d+$/ ) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapPort'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'destinationDN'} || 
        $data->{'destinationDN'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'destinationDN'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'BindDN'} || 
        $data->{'BindDN'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'BindDN'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'ldapPasswd'} || 
        $data->{'ldapPasswd'} eq "") {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'ldapPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    # test if this File already exists
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/newcerts/$certificate.pem") == -1) {
        return $self->SetError(summary => __("Certificate does not exist."),
                               code => "FILE_DOES_NOT_EXIST");
    }

    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/keys/$key.key") > 0) {
        if(defined $data->{'keyPasswd'} && $data->{'keyPasswd'} ne "") {
            my $check = SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'keyPasswd'},
                                                                  CERT => $certificate});
            if(not defined $check) {
                return $self->SetError(%{SCR->Error(".caTools")});
            }
            if(!defined $data->{'p12Passwd'} || $data->{'p12Passwd'} eq "") {
                return $self->SetError(summary => "Missing parameter 'p12Passwd'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            $exportPKCS12 = 1;
        }
    }

    my $crt = SCR->Read(".openssl.getParsedCert", $caName, 
                        {
                         INFILE => "$CAM_ROOT/$caName/newcerts/$certificate.pem",
                         INFORM => "PEM"
                        });
    if (not defined $crt) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    my ($body) = ($crt->{'BODY'} =~ /-----BEGIN[\s\w]+-----\n([\S\s\n]+)\n-----END[\s\w]+-----/);

    if (! defined $body || $body eq "") {
        return $self->SetError(summary => "Can not parse the certificate",
                               code => "PARSE_ERROR");
    }

    # default is try; disable only, if ldap client says no
    my $use_tls = "try";

    if(Ldap->Read()) {
        my $ldapMap = Ldap->Export();
        if(defined $ldapMap->{ldap_tls}) {
            if($ldapMap->{ldap_tls} == 1) {
                $use_tls = "yes" 
            } else {
                $use_tls = "no";
            }
        }
    }
    
    if (! SCR->Execute(".ldap", {"hostname" => $data->{'ldapHostname'},
                                 "port"     => $data->{'ldapPort'},
                                 "use_tls"  => $use_tls })) {
        return $self->SetError(summary => "LDAP init failed",
                               code => "SCR_INIT_FAILED");
    }

    if (! SCR->Execute(".ldap.bind", {"bind_dn" => $data->{'BindDN'},
                                      "bind_pw" => $data->{'ldapPasswd'}}) ) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "LDAP bind failed",
                               code => "SCR_INIT_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }

    my $dnList = SCR->Read(".ldap.search", {
                                            "base_dn" => $data->{'destinationDN'},
                                            "filter" => 'objectclass=inetOrgPerson',
                                            "scope" => 0,
                                            "dn_only" => 1
                                           });
    if (! defined $dnList) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "'destinationDN' is not available in the LDAP directory.",
                               code => "LDAP_SEARCH_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }
    
    my $entry = {
                 'userCertificate;binary' => YaST::YCP::Byteblock(decode_base64($body))
                };
    if (not SCR->Write(".ldap.modify", { dn => $data->{'destinationDN'}} , $entry)) {
        my $ldapERR = SCR->Read(".ldap.error");
        return $self->SetError(summary => "Can not modify 'userCertificate' in LDAP directory.",
                               code => "LDAP_MODIFY_FAILED",
                               description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
    }
    
    if ( $exportPKCS12 ) {
        
        my $p12 = SCR->Execute(".openssl.dataConvert", $caName, 
                        {
                         DATATYPE  => "CERTIFICATE",
                         INFILE    => "$CAM_ROOT/$caName/newcerts/$certificate.pem",
                         KEYFILE   => "$CAM_ROOT/$caName/keys/$key.key",
                         INFORM    => "PEM",
                         OUTFORM   => "PKCS12",
                         INPASSWD  => $data->{'keyPasswd'},
                         OUTPASSWD => $data->{'p12Passwd'}, 
                        });
        if (not defined $p12) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }

        my $entry = {
                     'userPKCS12' => YaST::YCP::Byteblock($p12)
                    };
        if (not SCR->Write(".ldap.modify", { dn => $data->{'destinationDN'}} , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not modify 'userPKCS12' in LDAP directory.",
                                   code => "LDAP_MODIFY_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
    }
    
    return 1;
    
}

=item *
C<$bool = DeleteCertificate($valueMap)>

Delete a Certificate. This function removes also
the request and the private key.

In I<$valueMap> you can define the following keys: 

* caName (required)

* certificate (required)

* caPasswd (required)

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             certificate   => $certificateName,
             caPasswd      => 'system'
            };

    my $res = YaPI::CaManagement->DeleteCertificate($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{DeleteCertificate} = ["function", "boolean", ["map", "string", "any"] ]; }
sub DeleteCertificate {
    my $self = shift;
    my $data = shift;
    my $caName  = "";
    my $certificate = "";
    my $req = "";
    my $serial = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'} ) {
                                    # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};
    
    if (!defined $data->{'certificate'}) {
        # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'certificate'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{'certificate'};
    
    $certificate =~ /^([[:xdigit:]]+):([[:xdigit:]]+[\d-]*)$/;
    if(defined $1 && defined $2 && $1 ne "" && $2 ne "") {
        $serial = $1;
        $req = $2;
    }
    
    my $check = SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'},
                                                          CACERT => 1});
    if(not defined $check) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }
    
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/newcerts/$certificate.pem") == -1) {
        return $self->SetError(summary => __("Certificate does not exist."),
                               code => "FILE_DOES_NOT_EXIST");
    }
    
    my $st = SCR->Execute(".openssl.status", $caName, {SERIAL => "$serial"});
    if(! defined $st) {
        return $self->SetError(%{SCR->Error(".openssl")});
    } elsif( $st eq "Revoked" || $st eq "Expired" ) {

        if( not SCR->Write(".caTools.delCAM", $caName, { MD5 => $req })) {
            my $desc = "Can not remove the certificate from the database.\n";
            my $err .= SCR->Error(".caTools");
            if(defined $err && defined $err->{summary}) {
                $desc .= $err->{summary}."\n";
            }
            if(defined $err && defined $err->{description}) {
                $desc .= $err->{description}."\n";
            }
            return $self->SetError(summary => __("Removing the certificate failed."),
                                   description => $desc,
                                   code => "SCR_WRITE_FAILED");
        }

        if(! SCR->Execute(".target.remove", "$CAM_ROOT/$caName/newcerts/$certificate.pem")) {
            return $self->SetError(summary => __("Removing the certificate failed."),
                                   description => "Can not remove '$CAM_ROOT/$caName/keys/$req.key'",
                                   code => "SCR_EXECUTE_ERROR");
        }
        
        if (SCR->Read(".target.size", "$CAM_ROOT/$caName/keys/$req.key") >= 0) {
            if(! SCR->Execute(".target.remove", "$CAM_ROOT/$caName/keys/$req.key")) {
                y2error("Removing key failed. '$CAM_ROOT/$caName/keys/$req.key'");
            }
        }
        if (SCR->Read(".target.size", "$CAM_ROOT/$caName/req/$req.req") >= 0) {
            if(!SCR->Execute(".target.remove", "$CAM_ROOT/$caName/req/$req.req")) {
                y2error("Removing request failed. '$CAM_ROOT/$caName/keys/$req.key'");
            }
        }
    } else {
        return $self->SetError( summary => __("Only revoked or expired certificates can be deleted."),
                                description => "The status of the certificate is '$st'",
                                code => "PARAM_CHECK_FAILED");
    }
    return 1;    
}


=item *
C<$bool = ImportCommonServerCertificate($valueMap)>

Import a server certificate plus correspondenting CA
and copy them to a place where other YaST modules look
for such a common certificate.

The CA(s) are copied to '/etc/ssl/certs/YaST-CA.pem'.

The server certificate is copied to '/etc/ssl/servercerts/servercert.pem' .

The private key is copied to '/etc/ssl/servercerts/serverkey.pem' .
The private key is unencrypted and only for B<root> readable.

In I<$valueMap> you can define the following keys: 

* inFile (required)

* passwd (required)

B<inFile> is the path to a certificate in PKCS12 format.

B<passwd> is the password which is needed to decrypt the PKCS12
certificate. A second password is not needed, because the private 
key will be unencrypted.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             inFile        => '/media/floppy/YaST-Servercert.p12',
             passwd        => 'system'
            };

    my $res = YaPI::CaManagement->ImportCommonServerCertificate($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{ImportCommonServerCertificate} = [
                                                    "function", 
                                                    "boolean", 
                                                    ["map", "string", "any"] 
                                                   ]; }
sub ImportCommonServerCertificate {
    my $self = shift;
    my $data = shift;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if(! defined $data->{inFile} || $data->{inFile} eq "") {
        # parameter check
        return $self->SetError(summary => __("Path to certificate file is needed."),
                               description => "Parameter 'inFile' is missing",
                               code => "PARAM_CHECK_FAILED");
    }

    my $size = SCR->Read(".target.size", $data->{inFile});
    if ($size <= 0) {
        return $self->SetError(summary => __("Certificate not found in")." '$data->{inFile}'",
                               code => "FILE_DOES_NOT_EXIST");
    }

    if(!defined $data->{passwd}) {
        # parameter check
        return $self->SetError(summary => __("Password is required."),
                               description => "Parameter 'passwd' is missing",
                               code => "PARAM_CHECK_FAILED");
    }

    my $hash = {
                DATATYPE => "CERTIFICATE",
                INFILE   => $data->{inFile},
                INFORM   => 'PKCS12',
                OUTFROM  => 'PEM',
                INPASSWD => $data->{passwd},
                OUTPASS  => ""
               };

    my $certs = SCR->Execute(".openssl.dataConvert", "/", $hash);
    if(! defined $certs) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }

    my @list = ();
    my $info = undef;
    my $crt = undef;
    my $subject = undef;
    my $issuer = undef;
    my $keyID = undef;

    foreach my $line (split(/\n/, $certs)) {
        if(defined($info)) {
            $crt .= "$line\n";
            if($line =~ /^[-]{5}END[ ]([A-Z0-9 ]+)+[-]{5}$/) {
                if($info eq $1) {
                    push(@list, {
                                 info    => $info,
                                 data    => $crt,
                                 keyID   => $keyID,
                                 subject => $subject,
                                 issuer  => $issuer
                                });
                }
                $info = undef;
                $crt = undef;
                $keyID = undef;
                $subject = undef;
                $issuer = undef;
            }
        } else {
            if($line =~ /^[-]{5}BEGIN[ ]([A-Z0-9 ]+)+[-]{5}$/) {
                $info = "$1";
                $crt = "$line\n";
            } else {
                if($line =~ /^\s+localKeyID:\s*([0-9a-fA-F\s]+)\s*$/) {
                    $keyID = "$1";
                } elsif($line =~ /^subject=(.*)\s*$/) {
                    $subject = "$1";
                } elsif($line =~ /^issuer=(.*)\s*$/) {
                    $issuer = "$1";
                }
            }
        }
    }

    $keyID = undef;
    my $serverCertIssuer = undef;

    my $serverCert = undef;
    my $serverKey = undef;
    my $srvIssuer = undef;
    my @restCA = ();

    # search for the server certificate
    foreach my $certHash (@list) {
        if(defined $certHash->{keyID} && $certHash->{keyID} ne "" &&
           defined $certHash->{subject} && $certHash->{subject} ne "") 
          {
              $keyID = $certHash->{keyID};
              $serverCertIssuer = $certHash->{issuer};
              $serverCert = $certHash->{data};
              $certHash->{data} = undef;
              $certHash->{keyID} = undef;
              last;
          }
    }

    # search for the private key
    foreach my $certHash (@list) {
        if(defined $certHash->{keyID} && $certHash->{keyID} eq $keyID) 
          {
              $serverKey = $certHash->{data};
              $certHash->{data} = undef;
              last;
          }
    }

    # search for the ca which issuered the server certificate 
    foreach my $certHash (@list) {
        if(defined $certHash->{subject} && $certHash->{subject} eq $serverCertIssuer) 
          {
              $srvIssuer = $certHash->{data};
              $certHash->{data} = undef;
              last;
          }
    }

    # collect the rest CAs
    foreach my $certHash (@list) {
        if(defined $certHash->{data} && $certHash->{info} =~ /CERTIFICATE/) 
          {
              push @restCA, $certHash->{data};
          }
    }
     
    if(defined $serverCert && defined $serverKey) {

        if(! defined SCR->Read(".target.dir", "/etc/ssl/servercerts")) {
            if(! SCR->Execute(".target.mkdir", "/etc/ssl/servercerts")) {
                return $self->SetError(summary => "Can not create 'servercerts' directory",
                                       code => "SCR_EXECUTE_FAILED");
            }
        }
        
        if(! SCR->Write(".target.string", "/etc/ssl/servercerts/servercert.pem", $serverCert)) {
            return $self->SetError(summary => "Can not write 'servercert.pem'",
                                   code => "SCR_WRITE_FAILED");
        }

        if(-1 == SCR->Read(".target.size", "/etc/ssl/servercerts/serverkey.pem")) {

            # create empty file
            if(! SCR->Write(".target.string", "/etc/ssl/servercerts/serverkey.pem", "")) {
                return $self->SetError(summary => "Can not write 'serverkey.pem'",
                                       code => "SCR_WRITE_FAILED");
            }
            
            # set the right mode
            if(0 != SCR->Execute(".target.bash", "chmod 0600 /etc/ssl/servercerts/serverkey.pem")) {
                return $self->SetError(summary => "Can not change the permissions for 'serverkey.pem'",
                                       code => "SCR_EXECUTE_FAILED");
            }
        }

        if(! SCR->Write(".target.string", "/etc/ssl/servercerts/serverkey.pem", $serverKey)) {
            return $self->SetError(summary => "Can not write 'serverkey.pem'",
                                   code => "SCR_WRITE_FAILED");
        }

        if(defined $srvIssuer) {
            if(! SCR->Write(".target.string", "/etc/ssl/certs/YaST-CA.pem", $srvIssuer)) {
                return $self->SetError(summary => "Can not write 'YaST-CA.pem'",
                                       code => "SCR_WRITE_FAILED");
            }
        }
        
        my $i = 1;
        foreach my $ca (@restCA) {
            if(! SCR->Write(".target.string", "/etc/ssl/certs/YaST-CA-$i.pem", $ca)) {
                return $self->SetError(summary => "Can not write 'YaST-CA-$i.pem'",
                                       code => "SCR_WRITE_FAILED");
            }
            $i++;
        }
        
        # call c_rehash for /etc/ssl/certs/
        my $ret = SCR->Execute(".target.bash", "c_rehash /etc/ssl/certs/");
        if (! defined $ret || $ret != 0) {
            return $self->SetError( summary => "Can not create hash vaules in '/etc/ssl/certs/'",
                                    description => "'c_rehash /etc/ssl/certs/' failed",
                                    code => "C_REHASH_FAILED");
        }
    } else {
        return $self->SetError(summary => __("Invalid certificate file."),
                               description => "Can not find a server certificate or the private key.",
                               code => "PARSING_ERROR");
    }    
    return 1;
}



=item *
C<$bool = ReadFile($valueMap)>

Returns a certificate or CRL as plain text or parsed map.

In I<$valueMap> you can define the following keys:

* inFile (required)

* type (required; can be "plain", "parsed" or "extended")

* datatype (can be "CERTIFICATE", "REQUEST" or "CRL")

* inForm (required; "PEM", "DER")

The return value is "undef" on an error.

On success and type = "plain" the plain text view of the CA is returned.

If the type = "parsed" or "extended" a complex structure with the single values is returned.

EXAMPLE:

 use Data::Dumper;

 foreach my $type ("parsed", "plain", "extended") {
     my $data = {
                 'datatype' => "CERTIFICATE",
                 'inFile' => '/path/to/a/certificate.pem',
                 'inForm' => "PEM"
                 'type'   => $type,
                };

     my $res = YaPI::CaManagement->ReadFile($data);
     if( not defined $res ) {
         # error
     } else {
         print Data::Dumper->Dump([$res])."\n";
     }
 }

=cut

BEGIN { $TYPEINFO{ReadFile} = ["function", "any", ["map", "string", "any"] ]; }
sub ReadFile {
    my $self = shift;
    my $data = shift;
    my $ret  = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if(! defined $data->{inFile} || $data->{inFile} eq "") {
        return $self->SetError(summary => "Missing parameter 'inFile'",
                               code => "PARAM_CHECK_FAILED");
    }
    my $size = SCR->Read(".target.size", $data->{inFile});
    if ($size <= 0) {
        return $self->SetError(summary => __("File not found."),
                               description => "File '".$data->{inFile}."' does not exist.",
                               code => "FILE_DOES_NOT_EXIST");
    }

    if(! defined $data->{type} || $data->{type} eq "") {
        return $self->SetError(summary => "Missing parameter 'type'",
                               code => "PARAM_CHECK_FAILED");
    }
    if(! grep( ($_ eq $data->{type}), ("parsed", "plain", "extended"))) {
        return $self->SetError(summary => "Unknown value '".$data->{type}."' in 'type'",
                               code => "PARAM_CHECK_FAILED");
    }

    if(! defined $data->{datatype} || $data->{datatype} eq "") {
        return $self->SetError(summary => "Missing parameter 'datatype'",
                               code => "PARAM_CHECK_FAILED");
    }
    if(! grep( ($_ eq $data->{datatype}), ("CERTIFICATE", "CRL"))) {
        return $self->SetError(summary => "Unknown value '".$data->{datatype}."' in 'datatype'",
                               code => "PARAM_CHECK_FAILED");
    }

    if(! defined $data->{inForm} || $data->{inForm} eq "") {
        return $self->SetError(summary => "Missing parameter 'inForm'",
                               code => "PARAM_CHECK_FAILED");
    }
    if(! grep( ($_ eq $data->{inForm}), ("PEM", "DER"))) {
        return $self->SetError(summary => "Unknown value '".$data->{inForm}."' in 'inForm'",
                               code => "PARAM_CHECK_FAILED");
    }

    my $hash = {
                INFILE => $data->{inFile},
                INFORM => $data->{inForm}
               };

    if($data->{datatype} eq "CERTIFICATE") {
        
        if ($data->{type} eq "parsed") {
            $ret = SCR->Read(".openssl.getParsedCert", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        } elsif($data->{type} eq "extended") {
            $ret = SCR->Read(".openssl.getExtendedParsedCert", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        } else {
            $ret = SCR->Read(".openssl.getTXTCert", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        }
    } elsif($data->{datatype} eq "CRL") {
        if ($data->{type} eq "parsed") {
            $ret = SCR->Read(".openssl.getParsedCRL", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        } elsif($data->{type} eq "extended") {
            $ret = SCR->Read(".openssl.getExtendedParsedCRL", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        } else {
            $ret = SCR->Read(".openssl.getTXTCRL", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        }
    } elsif($data->{datatype} eq "REQUEST") {
        if ($data->{type} eq "parsed") {
            $ret = SCR->Read(".openssl.getParsedREQ", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        } elsif($data->{type} eq "extended") {
            $ret = SCR->Read(".openssl.getExtendedParsedREQ", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        } else {
            $ret = SCR->Read(".openssl.getTXTREQ", "/", $hash);
            if (not defined $ret) {
                return $self->SetError(%{SCR->Error(".openssl")});
            }
        }
    }
    return $ret;
}


=item *
C<$cert = ReadRequest($valueMap)>

Returns a request as plain text or parsed map.

In I<$valueMap> you can define the following keys: 

* caName (required)

* request (required - name without suffix)

* type (required - allowed values: "parsed", "extended" or "plain") 

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error.

On success and type = plain the plain text view of the Certificate is returned.

If the type is "parsed" or "extended" a complex structure with the single values is returned.

EXAMPLE:

 use Data::Dumper;

 foreach my $type ("parsed", "plain", "extended") {
     my $data = {
                 'caName'      => 'My_CA',
                 'type'        => $type,
                 'request'     => $certName
                };

     my $res = YaPI::CaManagement->ReadRequest($data);
     if( not defined $res ) {
         # error
     } else {
         print Data::Dumper->Dump([$res])."\n";
     }
 }

=cut

BEGIN { $TYPEINFO{ReadRequest} = ["function", "any", ["map", "string", "any"]]; }
sub ReadRequest {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $request = "";
    my $type   = "";
    my $ret = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (! defined $data->{"type"} || 
        !grep( ( $_ eq $data->{"type"}), ("parsed", "plain", "extended"))) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'type'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $type = $data->{"type"};
    
    if (! defined $data->{"request"}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'request'."),
                               code => "PARAM_CHECK_FAILED");
    }
    $request = $data->{"request"};

    my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/req/".$request.".req");
    if ($size <= 0) {
        return $self->SetError(summary => __("Request not found."),
                               description => "Request '$request.req' not available in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/req/".$request.".req",
                INFORM => "PEM"
               };
    if ($type eq "parsed") {
        $ret = SCR->Read(".openssl.getParsedREQ", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } elsif($type eq "extended") {
        $ret = SCR->Read(".openssl.getExtendedParsedREQ", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } else {
        $ret = SCR->Read(".openssl.getTXTREQ", $caName, $hash);
        if (not defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$certList = ReadRequestList($valueMap)>

Returns a list of maps with all requests of the defined CA.

In I<$valueMap> you can define the following keys: 

* caName (required)

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error.

On success it returns an array of hashes with all 
requests of this CA. @ret[0..X] can have the 
following Hash keys:

* request (the name of the certificate)

* commonName

* emailAddress

* countryName

* stateOrProvinceName

* localityName

* organizationName

* organizationalUnitName

* date

EXAMPLE:

 use Data::Dumper;

 my $data = {
             'caName'   => 'My_CA'
            };

    my $res = YaPI::CaManagement->ReadRequestList($data);
    if( not defined $res ) {
        # error
    } else {
        my $requestName = $res->[0]->{'request'};
        print Data::Dumper->Dump([$res])."\n";
    }

=cut

BEGIN { $TYPEINFO{ReadRequestList} = ["function", ["list", "any"], ["map", "string", "any"]]; }
sub ReadRequestList {
    my $self = shift;
    my $data = shift;
    my $ret  = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};

    $ret = SCR->Read(".caTools.requestList", $data->{'caName'});
    if ( not defined $ret ) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }
    return $ret;
}


=item *
C<$request = ImportRequest($valueMap)>

Import a request in a CA repository.

In I<$valueMap> you can define the following keys: 

* caName (required)

* inFile 

* data

* importFormat (default PEM)

B<inFile> is the path to a request.
B<data> the request data directly 

One of B<inFile> or B<data> is required.

B<importFormat> can be "PEM" or "DER". Default is PEM.

The return value is "undef" on an error and the request name on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             inFile        => '/media/floppy/my_request.pem',
             importFormat  => 'PEM'
            };

    my $res = YaPI::CaManagement->ImportRequest($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "$res\n";
    }

=cut

BEGIN { $TYPEINFO{ImportRequest} = [
                                    "function", 
                                    "string", 
                                    ["map", "string", "any"] 
                                   ]; }
sub ImportRequest {
    my $self = shift;
    my $data = shift;
    my $pemReq = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (! defined $data->{'caName'}) {
                                          # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};

    if(defined $data->{inFile} && $data->{inFile} ne "") {
        my $size = SCR->Read(".target.size", $data->{inFile});
        if ($size <= 0) {
            return $self->SetError(summary => __("Request not found in")." '$data->{inFile}'",
                                   code => "FILE_DOES_NOT_EXIST");
        }
        
        $data->{data} = SCR->Read(".target.string",$data->{inFile});
        if(! defined $data->{data}) {
            return $self->SetError(summary => "Can not read the request.",
                                   code => "OPEN_FAILED");
        }
    }

    if(! defined $data->{data} || $data->{data} eq "") {
        return $self->SetError(summary => "No request data found.",
                               code => "OPEN_FAILED");
    }
    
    if(defined $data->{importFormat} && $data->{importFormat} eq "DER") {
        
        $pemReq = SCR->Execute(".openssl.dataConvert", $caName, { DATATYPE => "REQ",
                                                                  INFORM   => "DER",
                                                                  OUTFORM  => "PEM",
                                                                  DATA     => $data->{data}
                                                                });
        if(! defined $pemReq) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    } else {
        my $beginReq = "-----BEGIN[\\w\\s]+[-]{5}";
        my $endReq   = "-----END[\\w\\s]+[-]{5}";
        ( $pemReq ) = ( $data->{'data'} =~ /($beginReq[\S\s\n]+$endReq)/ );
        
        if(! defined $pemReq || $pemReq eq "") {
            return $self->SetError(summary => "Invalid request data.",
                                   code => "PARSING_ERROR");
        }
    }

    my $hash = {
                DATA   => $pemReq,
                INFORM => "PEM"
               };

    my $parsed = SCR->Read(".openssl.getParsedREQ", $caName, $hash);
    if (not defined $parsed) {
        return $self->SetError(%{SCR->Error(".openssl")});
    }
    my $dnHash = {};

    if(exists  $parsed->{DN_HASH}->{CN}->[0] &&
       defined $parsed->{DN_HASH}->{CN}->[0] &&
       $parsed->{DN_HASH}->{CN}->[0] ne "")
      {
          $dnHash->{'commonName'} = $parsed->{DN_HASH}->{CN}->[0];
      }
    if(exists  $parsed->{DN_HASH}->{C}->[0] &&
       defined $parsed->{DN_HASH}->{C}->[0] &&
       $parsed->{DN_HASH}->{C}->[0] ne "")
      {
          $dnHash->{'country'} = $parsed->{DN_HASH}->{C}->[0];
      }
    if(exists  $parsed->{DN_HASH}->{OU}->[0] &&
       defined $parsed->{DN_HASH}->{OU}->[0] &&
       $parsed->{DN_HASH}->{OU}->[0] ne "")
      {
          $dnHash->{'organizationalUnitName'} = $parsed->{DN_HASH}->{OU}->[0];
      }
    if(exists  $parsed->{DN_HASH}->{ST}->[0] &&
       defined $parsed->{DN_HASH}->{ST}->[0] &&
       $parsed->{DN_HASH}->{ST}->[0] ne "")
      {
          $dnHash->{'stateOrProvinceName'} = $parsed->{DN_HASH}->{ST}->[0];
      }
    if(exists  $parsed->{DN_HASH}->{O}->[0] &&
       defined $parsed->{DN_HASH}->{O}->[0] &&
       $parsed->{DN_HASH}->{O}->[0] ne "")
      {
          $dnHash->{'organizationName'} = $parsed->{DN_HASH}->{O}->[0];
      }
    if(exists  $parsed->{DN_HASH}->{EMAILADDRESS}->[0] &&
       defined $parsed->{DN_HASH}->{EMAILADDRESS}->[0] &&
       $parsed->{DN_HASH}->{EMAILADDRESS}->[0] ne "")
      {
          $dnHash->{'emailAddress'} = $parsed->{DN_HASH}->{EMAILADDRESS}->[0];
      }
    if(exists  $parsed->{DN_HASH}->{L}->[0] &&
       defined $parsed->{DN_HASH}->{L}->[0] &&
       $parsed->{DN_HASH}->{L}->[0] ne "")
      {
          $dnHash->{'localityName'} = $parsed->{DN_HASH}->{L}->[0];
      }
    
    my $subject = YaST::caUtils->stringFromDN($dnHash);
    if(!defined $subject) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }
    my $md5 = md5_hex($subject);
    $md5    = $md5."-".time();

    my $dummy = SCR->Read(".target.size", "$CAM_ROOT/$caName/req/$md5.req");
    if ($dummy != -1) {
        return $self->SetError(summary => __("Duplicate DN. Request already exists."),
                               description => "'$subject' already exists.",
                               code => "FILE_ALREADY_EXIST");
    }

    if(!SCR->Write(".target.string", "$CAM_ROOT/$caName/req/$md5.req", $pemReq)) {
        return $self->SetError( summary => "Can not write the request.",
                                code => "SCR_WRITE_FAILED");
    }

    if(! SCR->Write(".caTools.addCAM", $caName, { MD5 => $md5, DN => $subject})) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/req/$md5.req");
        return $self->SetError(%{SCR->Error(".caTools")});
    }
    return $md5;
}


=item *
C<$bool = DeleteRequest($valueMap)>

Delete a Request. This function removes also
the private key if one is available.

In I<$valueMap> you can define the following keys: 

* caName (required)

* request (required)

* caPasswd (required)

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             request       => $requestName,
             caPasswd      => 'system'
            };

    my $res = YaPI::CaManagement->DeleteRequest($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{DeleteRequest} = ["function", "boolean", ["map", "string", "any"] ]; }
sub DeleteRequest {
    my $self = shift;
    my $data = shift;
    my $caName  = "";
    my $request = "";

    my $req = "";

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'} ) {
                                    # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};
    
    if (!defined $data->{'request'}) {
        # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'request'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $req = $data->{'request'};
    
    my $check = SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'},
                                                          CACERT => 1});
    if(not defined $check) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    if( not SCR->Write(".caTools.delCAM", $caName, { MD5 => $req })) {
        my $desc = "Can not remove the request from the database.\n";
        my $err .= SCR->Error(".caTools");
        if(defined $err && defined $err->{summary}) {
            $desc .= $err->{summary}."\n";
        }
        if(defined $err && defined $err->{description}) {
            $desc .= $err->{description}."\n";
        }
        return $self->SetError(summary => __("Removing the request failed."),
                               description => $desc,
                               code => "SCR_WRITE_FAILED");
    }

    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/keys/$req.key") >= 0) {
        if(! SCR->Execute(".target.remove", "$CAM_ROOT/$caName/keys/$req.key")) {
            y2error("Removing key failed. '$CAM_ROOT/$caName/keys/$req.key'");
        }
    }
    if (SCR->Read(".target.size", "$CAM_ROOT/$caName/req/$req.req") >= 0) {
        if(!SCR->Execute(".target.remove", "$CAM_ROOT/$caName/req/$req.req")) {
            return $self->SetError(summary => __("Removing the request failed."),
                                   code => "SCR_EXECUTE_FAILED");
        }
    }
    return 1;    
}


=item *
C<$bool = ImportCA($valueMap)>

Import a CA certificate and private key and creates a 
infrastructure.

In I<$valueMap> you can define the following keys: 

* caName (required - A name for this CA)

* caCertificate (required - path to certificate file in PEM format)

* caKey (required - path to private key in PEM format)

* caPasswd (required, if the private key is unencrypted)

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName        => 'My_CA',
             caCertificate => /path/to/cacert.pem,
             caKey         => /path/to/cacert.key
            };

    my $res = YaPI::CaManagement->ImportCA($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{ImportCA} = ["function", "boolean", ["map", "string", "any"] ]; }
sub ImportCA {
    my $self   = shift;
    my $data   = shift;
    
    my $caName = "";
    
    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'}) {
                                    # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};

    if (!defined $data->{caCertificate} || $data->{caCertificate} eq "") {
        return $self->SetError(summary => __("Invalid value for parameter 'caCertificate'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    my $hash = {
                'datatype' => "CERTIFICATE",
                'inFile' => $data->{caCertificate},
                'inForm' => "PEM",
                'type'   => 'parsed',
               };
    my $res = $self->ReadFile($hash);
    if (! defined $res) {
        return $self->SetError(summary => __("CA certificate not available in").
                               " '$data->{caCertificate}'",
                               code => "FILE_DOES_NOT_EXIST");
        return undef;
    }
    
    if (!defined $res->{"IS_CA"} ||
        $res->{"IS_CA"} != 1) {
                                           # parameter check failed
        return $self->SetError( summary => __("According to 'basicConstraints', this is not a CA."),
                                code    => "CHECK_PARAM_FAILED");
    }
    
    if (!defined $data->{caKey} || $data->{caKey} eq "") {
        return $self->SetError(summary => __("Invalid value for parameter 'caKey'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    
    my $size = SCR->Read(".target.size", $data->{caKey});
    if ($size <= 0) {
        return $self->SetError(summary => __("CA key not available in")." '$data->{caKey}'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    
    my $pem = SCR->Read(".target.string", $data->{caKey});
    if (!defined $pem) {
        return $self->SetError(summary => __("CA key not available in")." '$data->{caKey}'",
                               code => "SCR_READ_FAILED");
    }

    my $beginKey = "-----BEGIN[\\w\\s]+KEY[-]{5}";
    my $endKey   = "-----END[\\w\\s]+KEY[-]{5}";
    my ( $pemKey ) = ( $pem =~ /($beginKey[\S\s\n]+$endKey)/ );
    
    if(! defined $pemKey || $pemKey eq "") {
        return $self->SetError(summary => "Invalid Key data.",
                               code => "PARSING_ERROR");
    }

    if($pemKey !~ /ENCRYPTED/si) {
        if(! defined $data->{caPasswd}) {
            return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                                   code    => "PASSWD_REQUIRED");
        }
    }
    
    # END OF CHECKS

    if (not SCR->Write(".caTools.caInfrastructure", $caName)) {
        return $self->SetError(%{SCR->Error(".caTools")});
    }

    my $ret = SCR->Execute(".target.bash", "cp $data->{caCertificate} $CAM_ROOT/$caName/cacert.pem");
    if (! defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not copy CA certificate",
                                code => "COPY_FAILED");
    }

    if($pemKey =~ /ENCRYPTED/si) {
        $ret = SCR->Execute(".target.bash", "cp $data->{caKey} $CAM_ROOT/$caName/cacert.key");
        if (! defined $ret || $ret != 0) {
            YaST::caUtils->cleanCaInfrastructure($caName);
            return $self->SetError( summary => "Can not copy CA Key",
                                    code => "COPY_FAILED");
        }
    } else {
        my $hash = {
                    DATATYPE  => "KEY",
                    INFORM    => "PEM",
                    INFILE    => $data->{caKey},
                    OUTFORM   => "PEM",
                    OUTPASSWD => $data->{'caPasswd'},
                    OUTFILE   => "$CAM_ROOT/$caName/cacert.key",
                   };

        $ret = SCR->Execute(".openssl.dataConvert", $caName, $hash);
        if (! defined $ret) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
    }

    $ret = SCR->Execute(".target.bash", "cp $CAM_ROOT/$caName/cacert.pem $CAM_ROOT/.cas/$caName.pem");
    if (! defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not copy CA certificate",
                                code => "COPY_FAILED");
    }
    $ret = SCR->Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");
    if (! defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not create hash vaules in '$CAM_ROOT/.cas/'",
                                code => "C_REHASH_FAILED");
    }    

    return 1;
}


=item *
C<$bool = DeleteCA($valueMap)>

  Delete a Certificate Authority infrastructure

In I<$valueMap> you can define the following keys: 

* caName (required - A name for this CA)

* caPasswd (required)

* force (0/1 default is 0)

Normaly you can only delete a CA if the CA certificate is expired or
you have never signed a certificate with this CA. In all other cases 
you have to set the force parameter to 1 if you realy want to delete 
the CA and you know what you are doing.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

 my $data = {
             caName      => 'My_CA',
             caPasswd    => 'system,
            };

    my $res = YaPI::CaManagement->DeleteCA($data);
    if( not defined $res ) {
        # error
    } else {
        print STDERR "OK\n";
    }

=cut

BEGIN { $TYPEINFO{DeleteCA} = ["function", "boolean", ["map", "string", "any"] ]; }
sub DeleteCA {
    my $self   = shift;
    my $data   = shift;
    
    my $caName = "";
    my $doDelete = 0;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (!defined $data->{'caName'}) {
                                    # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};

    if (! defined $data->{'caPasswd'}) {
                               # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if(! defined SCR->Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'},
                                                           CACERT => 1})) 
      {
          return $self->SetError(%{SCR->Error(".caTools")});
      }
    
    if(exists $data->{force} && defined $data->{force} && $data->{force} == 1) {
        # force delete
        $doDelete = 1;
    } else {

        my $size = SCR->Read(".target.size", "$CAM_ROOT/$caName/index.txt");
        if($size <= 0) {
            # no certificate signed with this CA or broken infrastucture
            # delete is OK
            $doDelete = 1;
        }

        my $OSSLexpDate = $self->ReadCA({ caName => "$caName",
                                          type   => 'parsed'})->{NOTAFTER};
        my $expDate = SCR->Execute(".openssl.getNumericDate", $caName, $OSSLexpDate);
        if (not defined $expDate) {
            return $self->SetError(%{SCR->Error(".openssl")});
        }
        my ($year,$month,$day, $hour,$min,$sec) = Today_and_Now();
        my $now = $year.$month.$day.$hour.$min.$sec;
        
        if($now > $expDate) {
            # CA is expired
            # delete is ok
            $doDelete = 1;
        }
    }

    if($doDelete) {
        if(! defined YaST::caUtils->cleanCaInfrastructure($caName)) {
            return $self->SetError( summary => __("Deleting the CA failed."),
                                    code    => "DELETE_FAILED");
        }

        SCR->Execute(".target.bash", "rm -f $CAM_ROOT/.cas/$caName.pem");
        SCR->Execute(".target.bash", "rm -f $CAM_ROOT/.cas/crl_$caName.pem");
        SCR->Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");

    } else {
        return $self->SetError( summary => __("Deleting the CA is not allowed."),
                                description => "The CA must be expired or no certificate was signed with this CA",
                                code    => "CA_STILL_IN_USE");
    }
}




=item *
C<$crlValueMap = ReadCRLDefaults($valueMap)>

Read the default values for a CRL.
In I<$valueMap> you can define the following keys:

* caName (if not defined, read defaults for new Root CAs)

Returns a map with defaults for CRLs in this CA.
The return value is "undef" on an error.

On success the return value is a hash which can contain the following keys:

* days

* authorityKeyIdentifier

* issuerAltName


The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

EXAMPLE:

 use Data::Dumper;

 my $data = {
             'caName'   => 'My_CA'
            }
 $crlValueMap = YaPI::CaManagement->ReadCRLDefaults($data) 
 if( not defined $crlValueMap ) {
     # error
 } else {
     print Data::Dumper->Dump([$crlValueMap])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadCRLDefaults} = [
                                      "function", 
                                      ["map", "string", "any"],
                                      ["map", "string", "any"]
                                     ]; }
sub ReadCRLDefaults {
    my $self = shift;
    my $data = shift;
    my $caName   = "";
    my $ret = {};

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if(defined $data->{caName}) {
        $caName = $data->{caName};
    }

    $ret = {
            'authorityKeyIdentifier' => undef,
            'issuerAltName'          => undef,
           };

    foreach my $extName ( keys %{$ret}) {
        if (defined $caName && $caName ne "") {
            $ret->{$extName} = SCR->Read(".CAM.openssl_tmpl.value.$caName.v3_crl.$extName");
            if (not defined $ret->{$extName}) {
                delete $ret->{$extName};
            }
        } else {
            $ret->{$extName} = SCR->Read(".CAM.opensslroot_tmpl.value.v3_crl.$extName");
            if (not defined $ret->{$extName}) {
                delete $ret->{$extName};
            }
        }
    }
    if (defined $caName && $caName ne "") {
        $ret->{'days'} = SCR->Read(".CAM.openssl_tmpl.value.$caName.ca.default_crl_days");
    } else {
        $ret->{'days'} = SCR->Read(".CAM.opensslroot_tmpl.value.ca.default_crl_days");
    }
    delete $ret->{'days'} if(not defined $ret->{'days'});
    
    return $ret;
}



=item *
C<$bool = WriteCRLDefaults($valueMap)>

Write the default values for creating a CRL.
Keys which are not present, will be removed if they are available
in the configuration file except for the 'days' key.

In I<$valueMap> you can define the following keys:

* caName (required)

* days

* authorityKeyIdentifier

* issuerAltName

The syntax of these values are explained in the 
B<COMMON PARAMETER> section.

The return value is "undef" on an error and "1" on success.

EXAMPLE:

     my $data = {
                 'caName'    => 'My_CA',
                 'days'      => '7'                 
                };
     my $res = YaPI::CaManagement->WriteCRLDefaults($data);
     if( not defined $res ) {
         # error
     } else {
         print "OK\n";
     }
 }

=cut

BEGIN { $TYPEINFO{WriteCRLDefaults} = ["function", "boolean", ["map", "string", "any"]]; }
sub WriteCRLDefaults {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $ret = undef;

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }
    
    # checking requires
    if (!defined $data->{"caName"}) {
                                           # parameter check failed
        return $self->SetError( summary => __("Missing value 'caName'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    
    $ret = SCR->Execute(".target.bash",
                        "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if (! defined $ret || $ret != 0) {
        return $self->SetError( summary => "Can not create backup file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }

    if (not SCR->Write(".CAM.openssl_cnf.value.$caName.ca.crl_extensions", 
                       "v3_crl")) { 
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }

    #####################################################
    # merge this extentions to the config file
    #
    #             v3 ext. value               default
    #####################################################
    my %v3ext = (
                 'authorityKeyIdentifier' => undef,
                 'issuerAltName'          => undef,
                );
    
    foreach my $extName ( keys %v3ext) {
        if (not defined YaST::caUtils->mergeToConfig($extName, "v3_crl",
                                                     $data, $v3ext{$extName})) {
            SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }
    
    if(defined $data->{days}) {
        if(not SCR->Write(".CAM.openssl_cnf.value.$caName.ca.default_crl_days", $data->{days})) {
            return $self->SetError( summary => "Can not write to config file",
                                    code => "SCR_WRITE_FAILED");
        }
    }

    if (not SCR->Write(".CAM.openssl_cnf", undef)) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    
    $ret = SCR->Execute(".target.bash", 
                        "cp $CAM_ROOT/$caName/openssl.cnf $CAM_ROOT/$caName/openssl.cnf.tmpl");
    if (! defined $ret || $ret != 0) {
        SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not create new template file '$CAM_ROOT/$caName/openssl.cnf.tmpl'",
                                code => "COPY_FAILED");
    }
    SCR->Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return 1;
}

1;

