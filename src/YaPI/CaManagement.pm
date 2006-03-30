###############################################################
# Copyright 2004,2005 Novell, Inc.  All rights reserved.
#
# $Id$
###############################################################
package YaPI::CaManagement;

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';

    use LIMAL;

    #eval {

    #    my $comp = new LIMAL::StringArray();
    #    $comp->push_back("*");
        
    #    my $cat = new LIMAL::StringArray();
    #    $cat->push_back("FATAL");
    #    $cat->push_back("ERROR");
    #    $cat->push_back("INFO");
        

    #    my $logref = LIMAL::Logger::createFileLogger("YaPI::CaManagement", $comp, $cat,
    #                                                 "[%d] %p %c %l - %m", 
    #                                                 "/var/log/YaST2/limal-ca-mgm.log",
    #                                                 2048, 2);
    #    LIMAL::Logger::setDefaultLogger($logref);
    #};
    # ignore errors here; If we run as none root this happens
    

}

our $VERSION="1.2.0";


=head1 NAME

YaPI::CaManagement

=head1 PREFACE

This package is the public Yast2 API to the CA management.

=head1 VERSION

1.2.0

=head1 SYNOPSIS

use YaPI::CaManagement

$caList = ReadCAList()

  returns a list of available CAs

$caList = ReadCATree()

  returns a list of lists of the available CAs containing the issuer caName

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

use LIMAL::CaMgm;
use YaST::YCP qw(Boolean);
use YaST::caUtils;
use ycp;
use URI::Escape;
use X500::DN;
use MIME::Base64;
#use Digest::MD5 qw(md5_hex);
#use Date::Calc qw( Date_to_Time Add_Delta_DHMS Today_and_Now);


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
    my $repository = shift || undef;

    my @ret;

    eval {
        my $list = undef;
        if(defined $repository) {

            $list = LIMAL::CaMgm::CA::getCAList($repository);
        
        } else {

            $list = LIMAL::CaMgm::CA::getCAList();
        }
        for(my $it = $list->begin();
            !$list->iterator_equal($it, $list->end());
            $list->iterator_incr($it))
          {
              push(@ret, $list->iterator_value($it));
          }
    };
    if($@) {
        return $self->SetError( summary     => __("Cannot read CA list."), 
                                description => "$@",
                                code        => "LIMAL_CALL_FAILED");
    }
    return \ @ret;
}

=item *
C<$caList = ReadCATree()>

Returns a list of lists of the available CAs 
containing the issuer caName.

* $caList->[$x]->[0] is the caName

* $caList->[$x]->[1] is the issuer caName 

If the issuer caName is empty caName is a root CA.
The list is sorted by the first element.

The function return undef on an error.

EXAMPLE:

 my $caList = YaPI::CaManagement->ReadCATree();
 if(not defined $caList) {
     #error
 }

 print Data::Dumper->Dump([$ca])."\n";

=cut

BEGIN { $TYPEINFO{ReadCATree} = ["function", ["list", ["list", "string"]]]; }
sub ReadCATree {
    my $self = shift;
    my $repository = shift || undef;
    my @result ;

    eval {
        my $tree = undef;

        if(defined $repository) {
            
            $tree = LIMAL::CaMgm::CA::getCATree($repository);
        
        } else {

            $tree = LIMAL::CaMgm::CA::getCATree();

        }
        for(my $it1 = $tree->begin();
            !$tree->iterator_equal($it1, $tree->end());
            $tree->iterator_incr($it1))
          {
              my $pair = $tree->iterator_value($it1);
              my @in_list = ($pair->getitem(0), $pair->getitem(1));
              push(@result, \@in_list);
          }
    };
    if($@) {
        return $self->SetError( summary     => __("Cannot read CA tree."), 
                                description => "$@",
                                code        => "LIMAL_CALL_FAILED");
    }

    return \@result;
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
    my $rgd = undef;
    eval {
        
        if( defined $data->{'repository'}) {
            
            $rgd = LIMAL::CaMgm::CA::getRootCARequestDefaults($data->{'repository'});
            
        } else {
            
            $rgd = LIMAL::CaMgm::CA::getRootCARequestDefaults();
            
        }
        my $dnl = $rgd->getSubjectDN()->getDN();
        my @DN_Values = ('countryName', 'stateOrProvinceName', 'localityName',
                         'organizationName', 'organizationalUnitName',
                         'commonName', 'emailAddress');
        
        for(my $dnit = $dnl->begin();
            !$dnl->iterator_equal($dnit, $dnl->end());
            $dnl->iterator_incr($dnit))
        {
            foreach my $v (@DN_Values) {

                if($dnl->iterator_value($dnit)->getType() =~ /^$v$/i) {

                    if(defined $data->{$v}) {
                        
                        $dnl->iterator_value($dnit)->setRDNValue($data->{$v});

                    } else {

                        $dnl->iterator_value($dnit)->setRDNValue("");
                    }
                }
            }
        }

        my $dnObject = new LIMAL::CaMgm::DNObject($dnl);
        $rgd->setSubjectDN($dnObject);

        if( defined $data->{'challengePassword'} ) {

            $rgd->setChallengePassword($data->{'challengePassword'});

        } else {

            $rgd->setChallengePassword("");

        }

        if( defined $data->{'unstructuredName'} ) {

            $rgd->setUnstructuredName($data->{'unstructuredName'});

        } else {

            $rgd->setUnstructuredName("");

        }

        $rgd->setKeysize($data->{"keyLength"} +0);

        my $exts = $rgd->getExtensions();

        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $rgd->setExtensions($exts);

    };
    if($@) {
        
        return $self->SetError( summary => __("Modifying RequestGenerationData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    
    
    my $cid = undef;
    eval {

        if( defined $data->{'repository'}) {
            
            $cid = LIMAL::CaMgm::CA::getRootCAIssueDefaults($data->{'repository'});
            
        } else {
            
            $cid = LIMAL::CaMgm::CA::getRootCAIssueDefaults();
            
        }

        my $start = time();
        my $end   = $start +($data->{"days"} * 24 * 60 * 60);

        $cid->setCertifyPeriode($start, $end);

        my $exts = $cid->getExtensions();
        
        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsBaseUrl",
                                                     $data->{'nsBaseUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRevocationUrl",
                                                     $data->{'nsRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaRevocationUrl",
                                                     $data->{'nsCaRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRenewalUrl",
                                                     $data->{'nsRenewalUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaPolicyUrl",
                                                     $data->{'nsCaPolicyUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityKeyIdentifier($exts,
                                                            $data->{'authorityKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformIssuerAltName($exts,
                                                   $data->{'issuerAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityInfoAccess($exts,
                                                         $data->{'authorityInfoAccess'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformCrlDistributionPoints($exts,
                                                           $data->{'crlDistributionPoints'});
        if(!defined $e) {
            return undef;
        }

        $cid->setExtensions($exts);

    };
    if($@) {

        return $self->SetError( summary => __("Modifying CertificateIssueData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    eval {

        if( defined $data->{'repository'}) {
            
            LIMAL::CaMgm::CA::createRootCA($data->{'caName'},
                                           $data->{'keyPasswd'},
                                           $rgd, $cid, 
                                           $data->{'repository'});
        } else {

            LIMAL::CaMgm::CA::createRootCA($data->{'caName'},
                                           $data->{'keyPasswd'},
                                           $rgd, $cid);

        }

    };
    if($@) {

        return $self->SetError( summary => __("Creating Root CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

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
    
    my $ca  = undef;
    my $rgd = undef;
    my $cid = undef;
    
    my $rType = 0;
    my $cType = 0;

    eval {

        if($data->{'certType'} eq "ca") {
            $rType = $LIMAL::CaMgm::E_CA_Req;
            $cType = $LIMAL::CaMgm::E_CA_Cert;
        } elsif($data->{'certType'} eq "client") {
            $rType = $LIMAL::CaMgm::E_Client_Req;
            $cType = $LIMAL::CaMgm::E_Client_Cert;
        } elsif($data->{'certType'} eq "server") {
            $rType = $LIMAL::CaMgm::E_Server_Req;
            $cType = $LIMAL::CaMgm::E_Server_Cert;
        }

        if(defined $data->{'caName'} && $data->{'caName'} ne "") {
        
            if(defined $data->{'repository'}) {
                
                $ca = new LIMAL::CaMgm::CA($data->{'caName'}, "",
                                           $data->{'repository'});
            } else {
                
                $ca = new LIMAL::CaMgm::CA($data->{'caName'}, "");
                
            }

            $rgd = $ca->getRequestDefaults($rType);
            $cid = $ca->getIssueDefaults($cType);

        } else {

            if( defined $data->{'repository'}) {
                
                $rgd = LIMAL::CaMgm::CA::getRootCARequestDefaults($data->{'repository'});
                $cid = LIMAL::CaMgm::CA::getRootCAIssueDefaults($data->{'repository'});
                
            } else {
                
                $rgd = LIMAL::CaMgm::CA::getRootCARequestDefaults();
                $cid = LIMAL::CaMgm::CA::getRootCAIssueDefaults();
                
            }
        }

        my $rext = $rgd->getExtensions();
        my $cext = $cid->getExtensions();

        my $e = YaST::caUtils->extractBasicConstraits($cext->getBasicConstraints(),
                                                      $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsComment(), 
                                                   "nsComment", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsBaseUrl(), 
                                                   "nsBaseUrl", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsRevocationUrl(), 
                                                   "nsRevocationUrl", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsCaRevocationUrl(),
                                                   "nsCaRevocationUrl", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsRenewalUrl(),
                                                   "nsRenewalUrl", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsSslServerName(), 
                                                   "nsSslServerName", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractStringExtension($cext->getNsCaPolicyUrl(), 
                                                   "nsCaPolicyUrl", $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractNsCertType($cext->getNsCertType(),
                                              $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractKeyUsage($cext->getKeyUsage(),
                                            $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractSubjectKeyIdentifier($cext->getSubjectKeyIdentifier(),
                                                        $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractAuthorityKeyIdentifier($cext->getAuthorityKeyIdentifier(),
                                                          $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractSubjectAltName($cext->getSubjectAlternativeName(),
                                                  $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractIssuerAltName($cext->getIssuerAlternativeName(),
                                                 $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractExtendedKeyUsage($cext->getExtendedKeyUsage(),
                                                    $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractAuthorityInfoAccess($cext->getAuthorityInfoAccess(),
                                                       $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractCrlDistributionPoints($cext->getCRLDistributionPoints(),
                                                         $ret);
        if(!defined $e) {
            return undef;
        }

        $ret->{'keyLength'} = $rgd->getKeysize();
        $ret->{'days'} = ($cid->getEndDate() - $cid->getStartDate()) / (60*60*24);

        my $list = $rgd->getSubjectDN()->getDN();

        for(my $it = $list->begin();
            !$list->iterator_equal($it, $list->end());
            $list->iterator_incr($it)) 
          {
              my $type  = $list->iterator_value($it)->getType();
              my $value = $list->iterator_value($it)->getValue();

              $type = "C" if($type eq "countryName");
              $type = "ST" if($type eq "stateOrProvinceName");
              $type = "L" if($type eq "localityName");
              $type = "O" if($type eq "organizationName");
              $type = "OU" if($type eq "organizationalUnitName");
              next if($type eq "commonName");
              next if($type eq "emailAddress");

              push(@{$ret->{'DN'}->{$type}}, $value) if(defined $value && $value ne "");
          }
    };
    if($@) {

        return $self->SetError( summary => __("Getting defaults failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");

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

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "",
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "");

        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $type = 0;
    my $rtype = 0;
    if($certType eq "client") {
        $type = $LIMAL::CaMgm::E_Client_Cert;
        $rtype = $LIMAL::CaMgm::E_Client_Req;
    } elsif($certType eq "server") {
        $type = $LIMAL::CaMgm::E_Server_Cert;
        $rtype = $LIMAL::CaMgm::E_Server_Req;
    } elsif($certType eq "ca") {
        $type = $LIMAL::CaMgm::E_CA_Cert;
        $rtype = $LIMAL::CaMgm::E_CA_Req;
    }

    my $cid = undef;
    eval {

        $cid = $ca->getIssueDefaults($type);

        if(defined $data->{"days"}) {

            my $start = time();
            my $end   = $start +($data->{"days"} * 24 * 60 * 60);

            $cid->setCertifyPeriode($start, $end);
        }
            
        my $exts = $cid->getExtensions();
        
        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsBaseUrl",
                                                     $data->{'nsBaseUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRevocationUrl",
                                                     $data->{'nsRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaRevocationUrl",
                                                     $data->{'nsCaRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRenewalUrl",
                                                     $data->{'nsRenewalUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaPolicyUrl",
                                                     $data->{'nsCaPolicyUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityKeyIdentifier($exts,
                                                            $data->{'authorityKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformIssuerAltName($exts,
                                                   $data->{'issuerAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityInfoAccess($exts,
                                                         $data->{'authorityInfoAccess'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformCrlDistributionPoints($exts,
                                                           $data->{'crlDistributionPoints'});
        if(!defined $e) {
            return undef;
        }

        $cid->setExtensions($exts);

    };
    if($@) {

        return $self->SetError( summary => __("Modifying CertificateIssueData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $rgd = undef;
    eval {
        
        $rgd = $ca->getRequestDefaults($rtype);

        if( defined $data->{"keyLength"}) {

            $rgd->setKeysize($data->{"keyLength"} +0);
        }

        my $exts = $rgd->getExtensions();

        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $rgd->setExtensions($exts);

    };
    if($@) {
        
        return $self->SetError( summary => __("Modifying RequestGenerationData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }


    eval {

        $ca->setRequestDefaults($rtype, $rgd);
        $ca->setIssueDefaults($type, $cid);

    };
    if($@) {

        my $Varray = $rgd->verify();
        if(!$Varray->empty()) {

            for(my $i = 0; $i < $Varray->size(); ++$i) {

                y2error($Varray->getitem($i));
            }
        }
        $Varray = $cid->verify();
        if(!$Varray->empty()) {

            for(my $i = 0; $i < $Varray->size(); ++$i) {

                y2error($Varray->getitem($i));
            }
        }
        
        return $self->SetError( summary => __("Writing the defaults failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    
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

    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                       "",
                                       $data->{'repository'});
            
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "");
            
        }

        my $cert = $ca->getCA();

        if ($type eq "parsed" || $type eq "extended") {
            
            $ret = YaST::caUtils->getParsed($cert);
            my $repos = "$CAM_ROOT";
            if(defined $data->{repository}) {
                $repos = $data->{repository};
            }
            my $bod = LIMAL::CaMgm::LocalManagement::readFile("$repos/$caName/cacert.pem");
            my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
            my $endT   = "-----END[\\w\\s]+[-]{5}";
            ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );

            if($type eq "extended") {

                $ret = YaST::caUtils->extensionParsing($ret);
            }

        } else {
            $ret = $cert->getCertificateAsText();
        }
        
    };
    if($@) {
        
        return $self->SetError( summary => __("Parsing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "",
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "");

        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $rgd = undef;
    eval {
        
        $rgd = $ca->getRequestDefaults($LIMAL::CaMgm::E_Client_Req);
            
        my $dnl = $rgd->getSubjectDN()->getDN();
        my @DN_Values = ('countryName', 'stateOrProvinceName', 'localityName',
                         'organizationName', 'organizationalUnitName',
                         'commonName', 'emailAddress');
        
        for(my $dnit = $dnl->begin();
            !$dnl->iterator_equal($dnit, $dnl->end());
            $dnl->iterator_incr($dnit))
        {
            foreach my $v (@DN_Values) {

                if($dnl->iterator_value($dnit)->getType() =~ /^$v$/i) {

                    if(defined $data->{$v}) {
                        
                        $dnl->iterator_value($dnit)->setRDNValue($data->{$v});

                    } else {

                        $dnl->iterator_value($dnit)->setRDNValue("");
                    }
                }
            }
        }

        my $dnObject = new LIMAL::CaMgm::DNObject($dnl);
        $rgd->setSubjectDN($dnObject);

        if( defined $data->{'challengePassword'} ) {

            $rgd->setChallengePassword($data->{'challengePassword'});

        } else {

            $rgd->setChallengePassword("");

        }

        if( defined $data->{'unstructuredName'} ) {

            $rgd->setUnstructuredName($data->{'unstructuredName'});

        } else {

            $rgd->setUnstructuredName("");

        }

        $rgd->setKeysize($data->{"keyLength"} +0);

        my $exts = $rgd->getExtensions();

        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $rgd->setExtensions($exts);

    };
    if($@) {
        
        return $self->SetError( summary => __("Modifying RequestGenerationData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $requestName = "";
    eval {

        $requestName = $ca->createRequest($data->{'keyPasswd'},
                                          $rgd, $LIMAL::CaMgm::E_Client_Req);

    };
    if($@) {
        
        return $self->SetError( summary => __("Creating request failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    return $requestName;
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

    if (!defined $data->{"certType"}) {
        return $self->SetError( summary => __("Missing value 'certType'."),
                                code    => "CHECK_PARAM_FAILED");
    }
    $certType = $data->{"certType"};

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"days"}) {
        $data->{"days"} = 365;
    }

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'});

        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $type = 0;
    if($certType eq "client") {
        $type = $LIMAL::CaMgm::E_Client_Cert;
    } elsif($certType eq "server") {
        $type = $LIMAL::CaMgm::E_Server_Cert;
    } elsif($certType eq "ca") {
        $type = $LIMAL::CaMgm::E_CA_Cert;
    }

    my $cid = undef;
    eval {

        $cid = $ca->getIssueDefaults($type);

        my $start = time();
        my $end   = $start +($data->{"days"} * 24 * 60 * 60);

        $cid->setCertifyPeriode($start, $end);

        my $exts = $cid->getExtensions();
        
        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsBaseUrl",
                                                     $data->{'nsBaseUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRevocationUrl",
                                                     $data->{'nsRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaRevocationUrl",
                                                     $data->{'nsCaRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRenewalUrl",
                                                     $data->{'nsRenewalUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaPolicyUrl",
                                                     $data->{'nsCaPolicyUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityKeyIdentifier($exts,
                                                            $data->{'authorityKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformIssuerAltName($exts,
                                                   $data->{'issuerAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityInfoAccess($exts,
                                                         $data->{'authorityInfoAccess'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformCrlDistributionPoints($exts,
                                                           $data->{'crlDistributionPoints'});
        if(!defined $e) {
            return undef;
        }

        $cid->setExtensions($exts);

    };
    if($@) {

        return $self->SetError( summary => __("Modifying CertificateIssueData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $certName = "";
    eval {

        $certName = $ca->issueCertificate($data->{'request'},
                                          $cid, $type);

    };
    if($@) {
        
        return $self->SetError( summary => __("Creating request failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    return $certName;
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
        my $ca = undef;
        eval {

            if(defined $data->{'repository'}) {

                $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                           $data->{'caPasswd'},
                                           $data->{'repository'});

            } else {

                $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                           $data->{'caPasswd'});

            }

            $ca->deleteRequest($request);
        };
        if($@) {
            
            # ignore error
        }
        return undef;
    }
    
    return $certificate;
}

=item *
C<$certList = ReadCertificateList($valueMap)>

Returns a list of maps with all certificates of the defined CA.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

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
    my $ret  = [];

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    if (! defined $data->{'caPasswd'} ) {
        
        return $self->SetError(summary => __("Missing parameter 'caPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    my $ca = undef;

    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                       $data->{'caPasswd'},
                                       $data->{'repository'});
            
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       $data->{'caPasswd'});
            
        }
        
        my $list = $ca->getCertificateList();
        
        for(my $listIT = $list->begin();
            !$list->iterator_equal($listIT, $list->end());
            $list->iterator_incr($listIT))
        {
            
            my $hash = undef;
            my $map = $list->iterator_value($listIT);
            
            for(my $mapIT = $map->begin();
                !$map->iterator_equal($mapIT, $map->end());
                $map->iterator_incr($mapIT))
            {
                $hash->{$map->iterator_key($mapIT)} = $map->iterator_value($mapIT);
            }
            push @$ret, $hash;
        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Getting the certificate list failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    if (! defined $data->{'caPasswd'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }

    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                       $data->{'caPasswd'},
                                       $data->{'repository'});
            
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       $data->{'caPasswd'});
            
        }
        
        my $list = $ca->updateDB();
    };
    if($@) {
        
        if($@ =~ /invalid\s+password/i) 
        {
            # error message; displayed in an popup dialog
            return $self->SetError( summary => __("Invalid password."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
        else 
        {
            # error message; displayed in an popup dialog
            return $self->SetError( summary => __("UpdateDB failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
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

    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                       "",
                                       $data->{'repository'});
            
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "");
            
        }

        my $cert = $ca->getCertificate($certificate);

        if ($type eq "parsed" || $type eq "extended") {
            
            $ret = YaST::caUtils->getParsed($cert);
            my $repos = "$CAM_ROOT";
            if(defined $data->{repository}) {
                $repos = $data->{repository};
            }
            my $bod = LIMAL::CaMgm::LocalManagement::readFile("$repos/$caName/newcerts/$certificate".".pem");
            my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
            my $endT   = "-----END[\\w\\s]+[-]{5}";
            ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );

            if($type eq "extended") {

                $ret = YaST::caUtils->extensionParsing($ret);
            }

        } else {
            $ret = $cert->getCertificateAsText();
        }
        
    };
    if($@) {
        
        return $self->SetError( summary => __("Parsing the certificate failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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


    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                       $data->{'caPasswd'},
                                       $data->{'repository'});
            
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       $data->{'caPasswd'});
            
        }

        my $reason = new LIMAL::CaMgm::CRLReason();

        if (defined $data->{'crlReason'}) {
            $reason->setReason($data->{'crlReason'});
        }
        
        $ca->revokeCertificate($certificate, $reason);
    };
    if($@) {
        
        return $self->SetError( summary => __("Revoking the certificate failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'});

        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $cgd = undef;
    eval {

        $cgd = $ca->getCRLDefaults();

        my $hours   = $data->{"days"} * 24;

        $cgd->setCRLLifeTime($hours);
#
######   we use only the default extensions
#
#         my $exts = $cgd->getExtensions();
        
#         my $e = YaST::caUtils->transformAuthorityKeyIdentifier($exts,
#                                     $data->{'authorityKeyIdentifier'});
#         if(!defined $e) {
#             return undef;
#         }

#         $e = YaST::caUtils->transformIssuerAltName($exts,
#                                                    $data->{'issuerAltName'});
#         if(!defined $e) {
#             return undef;
#         }
#         $cgd->setExtensions($exts);

    };
    if($@) {

        return $self->SetError( summary => __("Modifying CRLGenerationData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    eval {

        $ca->createCRL($cgd);

    };
    if($@) {
        
        return $self->SetError( summary => __("Creating the CRL failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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
    
    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "",
                                       $data->{'repository'});
            
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "");
            
        }

        my $crl = $ca->getCRL();


        if ($type eq "parsed" || $type eq "extended") {

            $ret = YaST::caUtils->getParsedCRL($crl);
            my $repos = "$CAM_ROOT";
            if(defined $data->{repository}) {
                $repos = $data->{repository};
            }
            my $bod = LIMAL::CaMgm::LocalManagement::readFile("$repos/$caName/crl/crl.pem");
            my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
            my $endT   = "-----END[\\w\\s]+[-]{5}";
            ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );

            if($type eq "extended") {

                $ret = YaST::caUtils->extensionParsing($ret);
            }

        } else {
         
            $ret = $crl->getCRLAsText();
   
        }
    };
    if($@) {
        
        if($@ =~ /RuntimeException: File not found/) {

            return $self->SetError( summary => __("No CRL available."),
                                    code => "LIMAL_CALL_FAILED");
        } else {

            return $self->SetError( summary => __("Parsing the CRL failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
    }
    
    return $ret;
}

=item *
C<$file = ExportCA($valueMap)>

Export a CA to a file or returns it in different formats.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

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

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'});

        }
    };
    if($@) {

        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    my $ret = undef;

    if ($format eq "PEM_CERT") {

        eval {
            
            my $buffer = $ca->exportCACert($LIMAL::CaMgm::E_PEM);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
    } elsif ($format eq "PEM_CERT_KEY") {

        eval {
            
            my $buffer1 = $ca->exportCACert($LIMAL::CaMgm::E_PEM);
            my $buffer2 = $ca->exportCAKeyAsPEM("");

            $buffer1->append("\n", 1);
            $buffer1->append($buffer2->data(), $buffer2->size());
            
            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer1,
                                                         $destinationFile);
                $ret = 1;
            } else {
                
                $ret = $buffer1->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
    } elsif ($format eq "PEM_CERT_ENCKEY") {

        eval {
            
            my $buffer1 = $ca->exportCACert($LIMAL::CaMgm::E_PEM);
            my $buffer2 = $ca->exportCAKeyAsPEM($data->{'caPasswd'});
            
            $buffer1->append("\n", 1);
            $buffer1->append($buffer2->data(), $buffer2->size());

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer1,
                                                         $destinationFile);
                $ret = 1;
            } else {

                $ret = $buffer1->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "DER_CERT") {

        eval {
            
            my $buffer = $ca->exportCACert($LIMAL::CaMgm::E_DER);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "PKCS12") {
        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        eval {
            
            my $buffer = $ca->exportCAasPKCS12($data->{'P12Password'},
                                               0);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "PKCS12_CHAIN") {

        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }


        eval {
            
            my $buffer = $ca->exportCAasPKCS12($data->{'P12Password'},
                                               1);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
    }
    return $ret;
}

=item *
C<$file = ExportCertificate($valueMap)>

Export a certificate to a file or returns it in different formats.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPassword (required)

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

    if (!defined $data->{'caPasswd'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }
 
    if (! defined $data->{'certificate'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'certificate'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};

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
    my $keyPasswd = $data->{'keyPasswd'};

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'});

        }
    };
    if($@) {

        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    my $ret = undef;

    if ($format eq "PEM_CERT") {
        eval {
            
            my $buffer = $ca->exportCertificate($certificate,
                                                $LIMAL::CaMgm::E_PEM);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
    } elsif ($format eq "PEM_CERT_KEY") {

        eval {
            
            my $buffer1 = $ca->exportCertificate($certificate,
                                                 $LIMAL::CaMgm::E_PEM);
            my $buffer2 = $ca->exportCertificateKeyAsPEM($certificate,
                                                         $keyPasswd,
                                                         "");
            
            $buffer1->append("\n", 1);
            $buffer1->append($buffer2->data(), $buffer2->size());

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer1,
                                                         $destinationFile);
                $ret = 1;
            } else {

                $ret = $buffer1->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "PEM_CERT_ENCKEY") {

        eval {
            
            my $buffer1 = $ca->exportCertificate($certificate,
                                                 $LIMAL::CaMgm::E_PEM);
            my $buffer2 = $ca->exportCertificateKeyAsPEM($certificate,
                                                         $keyPasswd,
                                                         $keyPasswd);
            
            $buffer1->append("\n", 1);
            $buffer1->append($buffer2->data(), $buffer2->size());

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer1,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer1->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "DER_CERT") {

        eval {
            
            my $buffer = $ca->exportCACert($LIMAL::CaMgm::E_DER);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "PKCS12") {

        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        eval {
            
            my $buffer = $ca->exportCertificateAsPKCS12($certificate,
                                                        $keyPasswd,
                                                        $data->{'P12Password'},
                                                        0);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "PKCS12_CHAIN") {
        if (!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
                                           # parameter check failed
            return $self->SetError(summary => __("Parameter 'P12Password' missing."),
                                   code => "PARAM_CHECK_FAILED");
        }

        eval {
            
            my $buffer = $ca->exportCertificateAsPKCS12($certificate,
                                                        $keyPasswd,
                                                        $data->{'P12Password'},
                                                        1);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }
    }
    return $ret;
}

=item *
C<$file = ExportCRL($valueMap)>

Export a CRL to a file or returns it in different formats.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

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
                 'caPasswd'     => 'system',
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
 
    if (!defined $data->{'caPasswd'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caPasswd'."),
                               code    => "PARAM_CHECK_FAILED");
    }
 
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

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, $data->{'caPasswd'});

        }
    };
    if($@) {

        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    my $ret = undef;


    if ($format eq "PEM") {

        eval {
            
            my $buffer = $ca->exportCRL($LIMAL::CaMgm::E_PEM);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } elsif ($format eq "DER") {

        eval {
            
            my $buffer = $ca->exportCRL($LIMAL::CaMgm::E_DER);

            if (defined $destinationFile) {

                LIMAL::CaMgm::LocalManagement::writeFile($buffer,
                                                         $destinationFile);
                $ret = 1;
            } else {
                $ret = $buffer->data();
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Export failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
        }

    } else {
                                           # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'exportFormat'."),
                               code => "PARAM_CHECK_FAILED");
    }
    return $ret;
}

=item *
C<$bool = Verify($valueMap)>

Verify a certificate.

In I<$valueMap> you can define the following keys: 

* caName (required)

* certificate (required)

* disableCRLcheck (optional)

* purpose (optional)

The parameter B<purpose> could be one of the following values:

* sslclient    (SSL client)

* sslserver    (SSL server)

* nssslserver  (Netscape SSL server)

* smimesign    (S/MIME signing)

* smimeencrypt (S/MIME encryption)

* crlsign      (CRL signing)

* any          (Any Purpose)

* ocsphelper   (OCSP helper)

The syntax of the other values are explained in the 
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
    my $enableCRLcheck = 1;

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

    if(defined $data->{'disableCRLcheck'} && $data->{'disableCRLcheck'} ) {
        $enableCRLcheck = 0;
    }

    my $ca = undef;
    my $ret = undef;
    eval {

        if( defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "",
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "");

        }

        my $purpose = "any";
        if(defined $data->{'purpose'} && $data->{'purpose'} ne "") {
            if(!grep( ($_ eq $data->{'purpose'}), 
                      ("sslclient", "sslserver", "nssslserver",
                       "smimesign", "smimeencrypt", "crlsign",
                       "any", "ocsphelper"))) {
                # parameter check failed
                return $self->SetError(summary => __("Invalid value for parameter 'purpose'."),
                                       description => "Value '".$data->{'purpose'}.
                                       "' for 'purpose' is not allowed",
                                       code    => "PARAM_CHECK_FAILED");
            } else {
                $purpose = $data->{'purpose'};
            }
        }

        $ret = $ca->verifyCertificate($certificate, $enableCRLcheck, $purpose);

    };
    if($@) {

        return $self->SetError( summary => __("Verification failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

The return value is "undef" on an the 
filename(without suffix) of the certificate on success.

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
     print "OK '$res'\n";
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

    if (!defined $data->{"basicConstraints"} ||
        $data->{"basicConstraints"} !~ /CA:TRUE/i) {
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

    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, 
                                       $data->{"caPasswd"},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, 
                                       $data->{"caPasswd"});

        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $rgd = undef;
    eval {
        
        $rgd = $ca->getRequestDefaults($LIMAL::CaMgm::E_CA_Req);
            
        my $dnl = $rgd->getSubjectDN()->getDN();
        my @DN_Values = ('countryName', 'stateOrProvinceName', 'localityName',
                         'organizationName', 'organizationalUnitName',
                         'commonName', 'emailAddress');
        
        for(my $dnit = $dnl->begin();
            !$dnl->iterator_equal($dnit, $dnl->end());
            $dnl->iterator_incr($dnit))
        {
            foreach my $v (@DN_Values) {

                if($dnl->iterator_value($dnit)->getType() =~ /^$v$/i) {

                    if(defined $data->{$v}) {
                        
                        $dnl->iterator_value($dnit)->setRDNValue($data->{$v});

                    } else {

                        $dnl->iterator_value($dnit)->setRDNValue("");
                    }
                }
            }
        }

        my $dnObject = new LIMAL::CaMgm::DNObject($dnl);
        $rgd->setSubjectDN($dnObject);

        if( defined $data->{'challengePassword'} ) {

            $rgd->setChallengePassword($data->{'challengePassword'});

        } else {

            $rgd->setChallengePassword("");

        }

        if( defined $data->{'unstructuredName'} ) {

            $rgd->setUnstructuredName($data->{'unstructuredName'});

        } else {

            $rgd->setUnstructuredName("");

        }

        $rgd->setKeysize($data->{"keyLength"} +0);

        my $exts = $rgd->getExtensions();

        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $rgd->setExtensions($exts);

    };
    if($@) {
        
        return $self->SetError( summary => __("Modifying RequestGenerationData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $cid = undef;
    eval {

        $cid = $ca->getIssueDefaults($LIMAL::CaMgm::E_CA_Cert);

        my $start = time();
        my $end   = $start +($data->{"days"} * 24 * 60 * 60);

        $cid->setCertifyPeriode($start, $end);

        my $exts = $cid->getExtensions();
        
        my $e = YaST::caUtils->transformBasicConstaints($exts, 
                                                        $data->{'basicConstraints'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsComment",
                                                     $data->{'nsComment'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsBaseUrl",
                                                     $data->{'nsBaseUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRevocationUrl",
                                                     $data->{'nsRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaRevocationUrl",
                                                     $data->{'nsCaRevocationUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsRenewalUrl",
                                                     $data->{'nsRenewalUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsSslServerName",
                                                     $data->{'nsSslServerName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformStringExtension($exts, 
                                                     "nsCaPolicyUrl",
                                                     $data->{'nsCaPolicyUrl'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformNsCertType($exts,
                                                $data->{'nsCertType'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformKeyUsage($exts,
                                              $data->{'keyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectKeyIdentifier($exts,
                                                          $data->{'subjectKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityKeyIdentifier($exts,
                                                            $data->{'authorityKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformSubjectAltName($exts,
                                                    $data->{'subjectAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformIssuerAltName($exts,
                                                   $data->{'issuerAltName'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformExtendedKeyUsage($exts,
                                                      $data->{'extendedKeyUsage'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformAuthorityInfoAccess($exts,
                                                         $data->{'authorityInfoAccess'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformCrlDistributionPoints($exts,
                                                           $data->{'crlDistributionPoints'});
        if(!defined $e) {
            return undef;
        }

        $cid->setExtensions($exts);

    };
    if($@) {

        return $self->SetError( summary => __("Modifying CertificateIssueData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $certName = "";
    eval {

        $certName = $ca->createSubCA($newCaName,
                                     $data->{'keyPasswd'},
                                     $rgd, $cid);
        
    };
    if($@) {
        
        return $self->SetError( summary => __("Creating the SubCA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    
    return $certName;
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

    my $ca = undef;
    eval {
        $ca = LIMAL::CaMgm::LocalManagement::readFile("$CAM_ROOT/$caName/cacert.pem");

    };
    if($@) {
        return $self->SetError( summary     => __("Cannot read the CA."),
                                description => "$@",
                                code        => "LIMAL_CALL_FAILED");
    }

    my ($body) = ($ca->data() =~ /-----BEGIN[\s\w]+-----\n([\S\s\n]+)\n-----END[\s\w]+-----/);

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

    my $crl = undef;
    eval {
        $crl = LIMAL::CaMgm::LocalManagement::readFile("$CAM_ROOT/$caName/crl/crl.pem");

    };
    if($@) {
        return $self->SetError( summary     => __("Cannot read the CRL."),
                                description => "$@",
                                code        => "LIMAL_CALL_FAILED");
    }

    my ($body) = ($crl->data() =~ /-----BEGIN[\s\w]+-----\n([\S\s\n]+)\n-----END[\s\w]+-----/);

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
        
        my $ca = undef;
        eval {
            my $crlDP_client = "";
            my $crlDP_server = "";
            my $crlDP_ca     = "";

            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "");

            my $defClient = $ca->getIssueDefaults($LIMAL::CaMgm::E_Client_Cert);

            if($defClient->getExtensions()->getCRLDistributionPoints()->isPresent() &&
               !$defClient->getExtensions()->getCRLDistributionPoints()->getCRLDistributionPoints()->empty()) {

                $crlDP_client = "found";
            }
            
            my $defServer = $ca->getIssueDefaults($LIMAL::CaMgm::E_Server_Cert);

            if($defServer->getExtensions()->getCRLDistributionPoints()->isPresent() &&
               !$defServer->getExtensions()->getCRLDistributionPoints()->getCRLDistributionPoints()->empty()) {

                $crlDP_server = "found";
            }

            my $defCA = $ca->getIssueDefaults($LIMAL::CaMgm::E_CA_Cert);

            if($defCA->getExtensions()->getCRLDistributionPoints()->isPresent() &&
               !$defCA->getExtensions()->getCRLDistributionPoints()->getCRLDistributionPoints()->empty()) {

                $crlDP_ca = "found";
            }

        
            if ( (! defined $crlDP_client || $crlDP_client eq "") &&
                 (! defined $crlDP_server || $crlDP_server eq "") &&
                 (! defined $crlDP_ca     || $crlDP_ca     eq "") 
               ) {
                # if all crlDP are not defined or empty, than we can add it automaticaly
                
                #my $crlDP = "URI:";
                my $crlDP   .= "ldap://".$data->{'ldapHostname'}.":".$data->{'ldapPort'}."/";
                $crlDP   .= uri_escape($data->{'destinationDN'});
                
                my $list = new LIMAL::CaMgm::LiteralValueList();
                $list->push_back(new LIMAL::CaMgm::LiteralValue("URI", $crlDP));
                
                # client
                
                my $cdp = $defClient->getExtensions()->getCRLDistributionPoints();
                $cdp->setCRLDistributionPoints($list);
                
                my $ext = $defClient->getExtensions();
                $ext->setCRLDistributionPoints($cdp);
                
                $defClient->setExtensions($ext);
                
                # server 
                
                $cdp = $defServer->getExtensions()->getCRLDistributionPoints();
                $cdp->setCRLDistributionPoints($list);
                
                $ext = $defServer->getExtensions();
                $ext->setCRLDistributionPoints($cdp);
                
                $defServer->setExtensions($ext);
                
                # ca
                
                $cdp = $defCA->getExtensions()->getCRLDistributionPoints();
                $cdp->setCRLDistributionPoints($list);
                
                $ext = $defCA->getExtensions();
                $ext->setCRLDistributionPoints($cdp);
                
                $defCA->setExtensions($ext);
                
                $ca->setIssueDefaults($LIMAL::CaMgm::E_Client_Cert,
                                      $defClient);
                
                $ca->setIssueDefaults($LIMAL::CaMgm::E_Server_Cert,
                                      $defServer);
                
                $ca->setIssueDefaults($LIMAL::CaMgm::E_CA_Cert,
                                      $defCA);
                
            }
        };
        if($@) {
            
            return $self->SetError( summary => __("Checking for new CRL Distribution Point failed."),
                                    description => "$@",
                                    code => "LIMAL_CALL_FAILED");
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
parameter 'caPasswd', 'keyPasswd' and 'p12Passwd' are defined, 
an export in PKCS12 format is also done.

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
        if(defined $data->{'keyPasswd'} && $data->{'keyPasswd'} ne "" &&
           defined $data->{'caPasswd'}  && $data->{'caPasswd'} ne "" &&
           defined $data->{'p12Passwd'} && $data->{'p12Passwd'} eq "")
          {
              $exportPKCS12 = 1;
          }
    }

    my $crt = undef;
    eval {
        $crt = LIMAL::CaMgm::LocalManagement::readFile("$CAM_ROOT/$caName/newcerts/$certificate.pem");

    };
    if($@) {
        return $self->SetError( summary     => __("Cannot read the certificate."),
                                description => "$@",
                                code        => "LIMAL_CALL_FAILED");
    }
    my ($body) = ($crt->data() =~ /-----BEGIN[\s\w]+-----\n([\S\s\n]+)\n-----END[\s\w]+-----/);
    
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

        my $ca = undef;
        my $p12 = "";
        eval {

            $ca = new LIMAL::CaMgm::CA($caName, $data->{caPasswd});

            $p12 = $ca->exportCertificateAsPKCS12($certificate,
                                                  $data->{'keyPasswd'},
                                                  $data->{'p12Passwd'});
        };
        if($@) {
            return $self->SetError( summary     => __("Exporting the certificate failed."),
                                    description => "$@",
                                    code        => "LIMAL_CALL_FAILED");
        }
        
        my $entry = {
                     'userPKCS12' => YaST::YCP::Byteblock($p12->data())
                    };
        if (not SCR->Write(".ldap.modify",
                           { dn => $data->{'destinationDN'}} , $entry)) {
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
    
    my $ca = undef;
    eval {

        if( defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"},
                                       $data->{"caPasswd"},
                                       $data->{"repository"});
        } else {

            $ca = new LIMAL::CaMgm::CA($data->{"caName"},
                                       $data->{"caPasswd"});

        }
    };
    if($@) {

        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    eval {

        $ca->deleteCertificate($certificate);

    };
    if($@) {

        return $self->SetError( summary => __("Deleting the certificate failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    eval {

        LIMAL::CaMgm::LocalManagement::importCommonServerCertificate($data->{inFile},
                                                                     $data->{passwd});

    };
    if($@) {
        return $self->SetError( summary => __("Importing the certificate failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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
    my $type = $data->{type};

    if(! defined $data->{datatype} || $data->{datatype} eq "") {
        return $self->SetError(summary => "Missing parameter 'datatype'",
                               code => "PARAM_CHECK_FAILED");
    }
    if(! grep( ($_ eq $data->{datatype}), ("CERTIFICATE", "CRL", "REQUEST"))) {
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

    eval {
        my $inForm = $LIMAL::CaMgm::E_PEM;

        if($data->{inForm} eq "DER") {
            $inForm = $LIMAL::CaMgm::E_DER;
        }

        if($data->{datatype} eq "CERTIFICATE") {
            
            my $cert = LIMAL::CaMgm::LocalManagement::getCertificate($data->{inFile},
                                                                     $inForm);

            if ($type eq "parsed" || $type eq "extended") {

                $ret = YaST::caUtils->getParsed($cert);

                #
                # FIXME: convert DER to PEM
                #
                if($data->{inForm} eq "PEM") {

                    my $bod = LIMAL::CaMgm::LocalManagement::readFile($data->{inFile});

                    my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
                    my $endT   = "-----END[\\w\\s]+[-]{5}";
                    ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );
                }

                if($type eq "extended") {
                    
                    $ret = YaST::caUtils->extensionParsing($ret);
                }
                
            } else {
                $ret = $cert->getCertificateAsText();
            }
        } elsif($data->{datatype} eq "CRL") {

            my $crl = LIMAL::CaMgm::LocalManagement::getCRL($data->{inFile},
                                                            $inForm);

            if ($type eq "parsed" || $type eq "extended") {
                
                $ret = YaST::caUtils->getParsedCRL($crl);


                #
                # FIXME: convert DER to PEM
                #
                if($data->{inForm} eq "PEM") {

                    my $bod = LIMAL::CaMgm::LocalManagement::readFile($data->{inFile});
                    my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
                    my $endT   = "-----END[\\w\\s]+[-]{5}";
                    ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );
                }

                if($type eq "extended") {
                    
                    $ret = YaST::caUtils->extensionParsing($ret);
                }
                
            } else {
                
                $ret = $crl->getCRLAsText();
                
            }
            
        } elsif($data->{datatype} eq "REQUEST") {

            my $req = LIMAL::CaMgm::LocalManagement::getRequest($data->{inFile},
                                                                $inForm);

            if ($type eq "parsed" || $type eq "extended") {

                $ret = YaST::caUtils->getParsedRequest($req);

                #
                # FIXME: convert DER to PEM
                #
                if($data->{inForm} eq "PEM") {

                    my $bod = LIMAL::CaMgm::LocalManagement::readFile($data->{inFile});
                    my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
                    my $endT   = "-----END[\\w\\s]+[-]{5}";
                    ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );
                }

                if($type eq "extended") {
                    
                    $ret = YaST::caUtils->extensionParsing($ret);
                }
                
            } else {
                $ret = $req->getRequestAsText();
            }
        }
    };
    if($@) {
        
        return $self->SetError( summary => __("Parsing failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "",
                                       $data->{'repository'});

        } else {

            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "");

        }

        my $req = $ca->getRequest($request);

        if ($type eq "parsed" || $type eq "extended") {

            $ret = YaST::caUtils->getParsedRequest($req);
            my $repos = "$CAM_ROOT";
            if(defined $data->{repository}) {
                $repos = $data->{repository};
            }
            my $bod = LIMAL::CaMgm::LocalManagement::readFile("$repos/$caName/req/$request".".req");
            my $beginT = "-----BEGIN[\\w\\s]+[-]{5}";
            my $endT   = "-----END[\\w\\s]+[-]{5}";
            ( $ret->{BODY} ) = ( $bod->data() =~ /($beginT[\S\s\n]+$endT)/ );

            if($type eq "extended") {

                $ret = YaST::caUtils->extensionParsing($ret);
            }

        } else {
            $ret = $req->getRequestAsText();
        }

    };
    if($@) {

        return $self->SetError( summary => __("Parsing the request failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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
    my $ret  = [];

    if (not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    if (! defined $data->{'caName'}) {
                                           # parameter check failed
        return $self->SetError(summary => __("Missing parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};

    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, 
                                       "",
                                       $data->{'repository'});
            
        } else {
            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "");
            
        }

        my $list = $ca->getRequestList();

        for(my $listIT = $list->begin();
            !$list->iterator_equal($listIT, $list->end());
            $list->iterator_incr($listIT))
        {

            my $hash = undef;
            my $map = $list->iterator_value($listIT);

            for(my $mapIT = $map->begin();
                !$map->iterator_equal($mapIT, $map->end());
                $map->iterator_incr($mapIT))
            {
                $hash->{$map->iterator_key($mapIT)} = $map->iterator_value($mapIT);
            }
            push @$ret, $hash;
        }
    };
    if($@) {

        return $self->SetError( summary => __("Getting the request list failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    if(defined $data->{inFile} && $data->{inFile} ne "") {
        my $size = SCR->Read(".target.size", $data->{inFile});
        if ($size <= 0) {
            return $self->SetError(summary => sprintf(
	                                              __("Request not found in %s."),
                                                      $data->{inFile}),
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

    my $ca = undef;

    eval {
        if(defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "",
                                       $data->{'repository'});

        } else {

            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       "");

        }
    };
    if($@) {

        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    
    eval {
        my $byteBuffer = new LIMAL::ByteBuffer($data->{data}, length($data->{data}));
        
        if(defined $data->{importFormat} && $data->{importFormat} eq "DER") {
            
            $ret = $ca->importRequestData($byteBuffer, 
                                          $LIMAL::CaMgm::E_DER);
            
        } else {
            
            $ret = $ca->importRequestData($byteBuffer, 
                                          $LIMAL::CaMgm::E_PEM);
            
        }
    };
    if($@) {

        return $self->SetError( summary => __("Importing the request failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    
    return $ret;
}


=item *
C<$bool = DeleteRequest($valueMap)>

Delete a Request. This function removes also
the private key if one is available.

In I<$valueMap> you can define the following keys: 

* caName (required)

* caPasswd (required)

* request (required)

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
    
    my $ca = undef;
    eval {
        if(defined $data->{'repository'}) {

            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       $data->{'caPasswd'},
                                       $data->{'repository'});

        } else {

            $ca = new LIMAL::CaMgm::CA($data->{'caName'},
                                       $data->{'caPasswd'});

        }

        $ca->deleteRequest($req);
    };
    if($@) {

        return $self->SetError( summary => __("Deleting the request failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    if (!defined $data->{caKey} || $data->{caKey} eq "") {
        return $self->SetError(summary => __("Invalid value for parameter 'caKey'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    
    my $size = SCR->Read(".target.size", $data->{caKey});
    if ($size <= 0) {
        return $self->SetError(summary => sprintf(
                                                  __("CA key not available in %s."),
                                                  $data->{caKey}),
                               code => "FILE_DOES_NOT_EXIST");
    }

    eval {

        my $cert = LIMAL::CaMgm::LocalManagement::readFile($data->{caCertificate});
        my $key  = LIMAL::CaMgm::LocalManagement::readFile($data->{caKey});

        if(!exists $data->{caPasswd} || !defined $data->{caPasswd}) {
            $data->{caPasswd} = "";
        }

        if( defined $data->{'repository'}) {

            LIMAL::CaMgm::CA::importCA($caName, $cert, $key,
                                       $data->{caPasswd},
                                       $data->{"repository"});

        } else {

            LIMAL::CaMgm::CA::importCA($caName, $cert, $key,
                                       $data->{caPasswd});
        }
    };
    if($@) {

        return $self->SetError( summary => __("Importing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
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

    if(exists $data->{force}  && 
       defined $data->{force} &&
       $data->{force} == 1) {
        # force delete
        $doDelete = 1;
    } else {
        $doDelete = 0;
    }

    eval {

        if( defined $data->{'repository'}) {

            LIMAL::CaMgm::CA::deleteCA($caName, 
                                       $data->{caPasswd},
                                       $doDelete,
                                       $data->{"repository"});

        } else {

            LIMAL::CaMgm::CA::deleteCA($caName,
                                       $data->{caPasswd},
                                       $doDelete);
        }
    };
    if($@) {

        return $self->SetError( summary => __("Deleting the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    return 1;
}




=item *
C<$crlValueMap = ReadCRLDefaults($valueMap)>

Read the default values for a CRL.
In I<$valueMap> you can define the following keys:

* caName (required)

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

    if (!defined $data->{'caName'}) {
                                    # parameter check failed
        return $self->SetError(summary => __("Invalid value for parameter 'caName'."),
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{'caName'};

    $ret = {
            'authorityKeyIdentifier' => undef,
            'issuerAltName'          => undef,
           };

    my $ca  = undef;
    my $cgd = undef;

    eval {

        if(defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, "",
                                       $data->{'repository'});
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{'caName'}, "");
            
        }
        
        $cgd = $ca->getCRLDefaults();
        
        my $crlExt = $cgd->getExtensions();

        
        my $e = YaST::caUtils->extractAuthorityKeyIdentifier($crlExt->getAuthorityKeyIdentifier(),
                                                             $ret);
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->extractIssuerAltName($crlExt->getIssuerAlternativeName(),
                                                 $ret);
        if(!defined $e) {
            return undef;
        }
        my $days = int($cgd->getCRLLifeTime() / 24);
        if($days == 0) {
            $days = 1;
        }
        $ret->{'days'} = $days;
    };
    if($@) {

        return $self->SetError( summary => __("Getting defaults failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");

    }
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
    
    my $ca = undef;
    eval {
        
        if( defined $data->{'repository'}) {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "",
                                       $data->{"repository"});
        } else {
            
            $ca = new LIMAL::CaMgm::CA($data->{"caName"}, "");
            
        }
    };
    if($@) {

        return $self->SetError( summary => __("Initializing the CA failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    my $cgd = undef;
    eval {

        $cgd = $ca->getCRLDefaults();

        if(defined $data->{days} && $data->{days} ne "") {
            $cgd->setCRLLifeTime( ($data->{days} * 24) );
        }

        my $exts = $cgd->getExtensions();
        
        my $e = YaST::caUtils->transformAuthorityKeyIdentifier($exts,
                                                               $data->{'authorityKeyIdentifier'});
        if(!defined $e) {
            return undef;
        }

        $e = YaST::caUtils->transformIssuerAltName($exts,
                                                   $data->{'issuerAltName'});
        if(!defined $e) {
            return undef;
        }

        $cgd->setExtensions($exts);
    };
    if($@) {
        
        return $self->SetError( summary => __("Modifying CRLGenerationData failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }
    
    eval {

        $ca->setCRLDefaults($cgd);
    };
    if($@) {
        
        return $self->SetError( summary => __("Writing the defaults failed."),
                                description => "$@",
                                code => "LIMAL_CALL_FAILED");
    }

    return 1;
}

1;

