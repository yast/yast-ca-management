=head1 NAME

YaPI::CaManagement

=head1 PREFACE

This package is the public Yast2 API to the CA management.

=head1 SYNOPSIS

use YaPI::CaManagement

$caList = ReadCAList()

  returns a list of available CAs

$bool = AddRootCA($valueMap)

  create a new selfsigned root CA

$certValueMap = ReadCertificateDefaults($valueMap)

  returns a map with defaults for the requested certificate type

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

B<common parameter in $valueMap>

Here is a list of common parameter which are used in $valueMap

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

package YaPI::CaManagement;

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

our $VERSION="1.0.1";

use strict;
#use Errno qw(ENOENT);
use vars qw(@ISA);

use YaPI;
@ISA = qw( YaPI );


use YaST::YCP;
use YaST::check;
use YaST::caUtils;
use ycp;
use URI::Escape;
use X500::DN;
use MIME::Base64;
use Date::Calc qw( Date_to_Time Add_Delta_DHMS Today_and_Now);

YaST::YCP::Import ("SCR");

our %TYPEINFO;
our @CAPABILITIES = (
                     'SLES9'
                    );

my $CAM_ROOT = "/var/lib/YaST2/CAM";

=item *
C<$caList = ReadCAList()>

returns a list of available CAs

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ReadCAList} = ["function", "any"]; }
sub ReadCAList {
    my $self = shift;
    my $caList = undef;

    my $ret = SCR::Read(".caTools.caList");
    if ( not defined $ret ) {
        return $self->SetError(%{SCR::Error(".caTools")});
    }
    return $ret;
}

=item *
C<$bool = AddRootCA($valueMap)>

create a new selfsigned root CA


EXAMPLE:


=cut

BEGIN { $TYPEINFO{AddRootCA} = ["function", "boolean", "any" ]; }
sub AddRootCA {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";

    if(not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"} || $data->{"caName"} eq "" || $data->{"caName"} =~ /\./) {
        return $self->SetError( summary => "Missing value 'caName'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};

    if (!defined $data->{"keyPasswd"} || $data->{"keyPasswd"} eq "" ||
        length($data->{"keyPasswd"}) <= 4) 
    {
        return $self->SetError( summary => "Missing value 'keyPasswd' or password is to short",
                                code    => "CHECK_PARAM_FAILED");
    }
    if (!defined $data->{"commonName"} || $data->{"commonName"} eq "") {
        return $self->SetError( summary => "Missing value 'commonName'",
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"keyLength"} || $data->{"keyLength"} !~ /^\d{3,4}$/ ) {
        $data->{"keyLength"} = 2048;
    }
    if (!defined $data->{"days"} || $data->{"days"} !~ /^\d{1,}$/) {
        $data->{"days"} = 3650;
    }
    if(not SCR::Write(".caTools.caInfrastructure", $data->{"caName"}))
    {
        return $self->SetError(%{SCR::Error(".caTools")});
    }

    my $retCode = SCR::Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if(not defined $retCode || $retCode != 0) {
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
        if(not defined $ret ) {
            YaST::caUtils->cleanCaInfrastructure($caName);
            return $self->SetError(%{YaST::caUtils->Error()});
        }
        push @dn, $data->{$DN_Part};
    }

    if(not SCR::Write(".var.lib.YaST2.CAM.value.$caName.req.x509_extensions", "v3_ca"))
    { 
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
                 'basicConstraints'       => 'critical,CA:true',
                 'nsComment'              => 'YaMC Generated Certificate',
                 'nsCertType'             => 'sslCA, emailCA',
                 'keyUsage'               => 'cRLSign, keyCertSign',
                 'subjectKeyIdentifier'   => 'hash',
                 'authorityKeyIdentifier' => 'keyid:always,issuer:always',
                 'subjectAltName'         => 'email:copy',
                 'issuerAltName'          => 'issuer:copy',
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
        if(not defined YaST::caUtils->mergeToConfig($extName, 'v3_ca',
                                                         $data, $v3ext{$extName}))
        {
              SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
              return $self->SetError(%{YaST::caUtils->Error()});
        }
    }

    if(not SCR::Write(".var.lib.YaST2.CAM", undef)) 
    {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    my $hash = {
                OUTFILE  => "$CAM_ROOT/$caName/cacert.key",
                PASSWD   => $data->{"keyPasswd"},
                BITS     => $data->{"keyLength"}
               };
    my $ret = SCR::Execute( ".openssl.genKey", $caName, $hash);

    if (not defined $ret) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.req",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             PASSWD  => $data->{"keyPasswd"},
             DN      => \@dn };
    $ret = SCR::Execute( ".openssl.genReq", $caName, $hash);
    if (not defined $ret) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR::Error(".openssl")});
    }

    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.pem",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             REQFILE => "$CAM_ROOT/$caName/cacert.req",
             PASSWD  => $data->{"keyPasswd"},
             DAYS    => $data->{"days"} 
            };
    $ret = SCR::Execute( ".openssl.genCert", $caName, $hash);
    if (not defined $ret) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR::Error(".openssl")});
    }

    $ret = SCR::Execute(".target.bash", "cp $CAM_ROOT/$caName/cacert.pem $CAM_ROOT/.cas/$caName.pem");
    if(not defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not copy CA certificate",
                                code => "COPY_FAILED");
    }
    $ret = SCR::Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");
    if(not defined $ret || $ret != 0) {
        YaST::caUtils->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not create hash vaules in '$CAM_ROOT/.cas/'",
                                code => "C_REHASH_FAILED");
    }
    
    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return 1;
}

=item *
C<$certValueMap = ReadCertificateDefaults($valueMap)>

returns a map with defaults for the requested certificate type

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ReadCertificateDefaults} = ["function", "any", "any"]; }
sub ReadCertificateDefaults {
    my $self = shift;
    my $data = shift;
    my $caName   = "";
    my $certType = "";
    my $ret = {};

    if(not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (defined $data->{"caName"}) {
        $caName = $data->{"caName"};
    } 
    if (defined $data->{"certType"}) {
        $certType = $data->{"certType"};
    } else {
        return $self->SetError(summary => "Missing parameter 'certType'",
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
        if(defined $caName && $caName ne "") {
            $ret->{$extName} = SCR::Read(".openssl.tmpl.value.$caName.v3_$certType.$extName");
            if(not defined $ret->{$extName}) {
                delete $ret->{$extName};
            }
        } else {
            $ret->{$extName} = SCR::Read(".opensslroot.tmpl.value.v3_$certType.$extName");
            if(not defined $ret->{$extName}) {
                delete $ret->{$extName};
            }
        }
    }
    if(defined $caName && $caName ne "") {
        $ret->{'keyLength'} = SCR::Read(".openssl.tmpl.value.$caName.req.default_bits");
        if($certType ne "ca") {
            $ret->{'days'} = SCR::Read(".openssl.tmpl.value.$caName.".$certType."_cert.default_days");
        } else {
            $ret->{'days'} = SCR::Read(".openssl.tmpl.value.$caName.ca.default_days");
        }
    } else {
        $ret->{'keyLength'} = SCR::Read(".opensslroot.tmpl.value.req.default_bits");
        if($certType ne "ca") {
            $ret->{'days'} = SCR::Read(".opensslroot.tmpl.value.".$certType."_cert.default_days");
        } else {
            $ret->{'days'} = SCR::Read(".opensslroot.tmpl.value.ca.default_days");
        }
        
    }    
    delete $ret->{'keyLength'} if(not defined $ret->{'keyLength'});
    delete $ret->{'days'} if(not defined $ret->{'days'});
    
    return $ret;
}

=item *
C<$ca = ReadCA($valueMap)>

returns a CA certificate as plain text or parsed map

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ReadCA} = ["function", "any", "any"]; }
sub ReadCA {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $type   = "";
    my $ret = undef;

   # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
     
    if (not defined $data->{"type"} || 
        !grep( ( $_ eq $data->{"type"}), ("parsed", "plain"))) 
    {
        return $self->SetError(summary => "Wrong value for parameter 'type'",
                               code => "PARAM_CHECK_FAILED");
    }
    $type = $data->{"type"};

    my $size = SCR::Read(".target.size", "$CAM_ROOT/$caName/cacert.pem");
    if($size <= 0) {
        return $self->SetError(summary => "CA Certificate not available in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/cacert.pem",
                INFORM => "PEM"
               };
    if($type eq "parsed") {
        $ret = SCR::Read(".openssl.getParsedCert", $caName, $hash);
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
    } else {
        $ret = SCR::Read(".openssl.getTXTCert", $caName, $hash);
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$name = AddRequest($valueMap)>

create a request for a special CA and returns the name

EXAMPLE:


=cut

BEGIN { $TYPEINFO{AddRequest} = ["function", "string", "any" ]; }
sub AddRequest {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $request = "";

    if(not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"} || $data->{"caName"} eq "" || $data->{"caName"} =~ /\./) {
        return $self->SetError( summary => "Missing value 'caName'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};

    if (!defined $data->{"keyPasswd"} || $data->{"keyPasswd"} eq "" ||
        length($data->{"keyPasswd"}) <= 4) 
    {
        return $self->SetError( summary => "Missing value 'keyPasswd' or password is to short",
                                code    => "CHECK_PARAM_FAILED");
    }
    if (!defined $data->{"commonName"} || $data->{"commonName"} eq "") {
        return $self->SetError( summary => "Missing value 'commonName'",
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"keyLength"} || $data->{"keyLength"} !~ /^\d{3,4}$/ ) {
        $data->{"keyLength"} = 2048;
    }

    # generate the request name
    my $requestString = YaST::caUtils->stringFromDN($data);
    
    if(not defined $requestString) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }
    
    $request = encode_base64($requestString, "");

    # test if this File already exists
    if(SCR::Read(".target.size", "$CAM_ROOT/$caName/keys/".$request.".key") != -1) {
        return $self->SetError(summary => "Duplicate DN($requestString). Request already exists.",
                               code => "FILE_ALREADY_EXIST");
    }
    if(SCR::Read(".target.size", "$CAM_ROOT/$caName/req/".$request.".req") != -1) {
        return $self->SetError(summary => "Duplicate DN($requestString). Request already exists.",
                               code => "FILE_ALREADY_EXIST");
    }    

    my $retCode = SCR::Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if(not defined $retCode || $retCode != 0) {
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
        if(not defined $ret ) {
            SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
        push @dn, $data->{$DN_Part};
    }

    if(not SCR::Write(".var.lib.YaST2.CAM.value.$caName.req.req_extensions", "v3_req"))
    { 
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
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
                 'basicConstraints'       => 'CA:false',
                 'nsComment'              => 'YaMC Generated Certificate',
                 'nsCertType'             => 'client, email, objsign',
                 'keyUsage'               => 'nonRepudiation, digitalSignature, keyEncipherment',
                 'subjectKeyIdentifier'   => 'hash',
                 'subjectAltName'         => 'email:copy',
                 'nsSslServerName'        => undef,
                 'extendedKeyUsage'       => undef,
                 'authorityInfoAccess'    => undef,
                );

    foreach my $extName ( keys %v3ext) {
        if(not defined YaST::caUtils->mergeToConfig($extName, 'v3_req',
                                                         $data, $v3ext{$extName}))
        {
            SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }

    if(not SCR::Write(".var.lib.YaST2.CAM", undef)) 
    {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    my $hash = {
                OUTFILE  => "$CAM_ROOT/$caName/keys/".$request.".key",
                PASSWD   => $data->{"keyPasswd"},
                BITS     => $data->{"keyLength"}
               };
    my $ret = SCR::Execute( ".openssl.genKey", $caName, $hash);

    if (not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/req/".$request.".req",
             KEYFILE => "$CAM_ROOT/$caName/keys/".$request.".key",
             PASSWD  => $data->{"keyPasswd"},
             DN      => \@dn };
    $ret = SCR::Execute( ".openssl.genReq", $caName, $hash);
    if (not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        return $self->SetError(%{SCR::Error(".openssl")});
    }

    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return $request;
}

=item *
C<$name = IssueCertificate($valueMap)>

issue a certificate and returns the name of the new certificate

EXAMPLE:


=cut

BEGIN { $TYPEINFO{IssueCertificate} = ["function", "string", "any" ]; }
sub IssueCertificate {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $request = "";
    my $certificate = "";
    my $certType = "client";

    if(not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"} || $data->{"caName"} eq "" || $data->{"caName"} =~ /\./) {
        return $self->SetError( summary => "Missing value 'caName'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    if (!defined $data->{"request"} || $data->{"request"} eq "" || $data->{"request"} =~ /\./) {
        return $self->SetError( summary => "Missing value 'request'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $request = $data->{"request"};

    if (!defined $data->{"caPasswd"} || $data->{"caPasswd"} eq "" ||
        length($data->{"caPasswd"}) <= 4) 
    {
        return $self->SetError( summary => "Missing value 'caPasswd' or password is to short",
                                code    => "CHECK_PARAM_FAILED");
    }

    # Set default values, if the values are not set and modify the
    # config with this values.
    if (!defined $data->{"days"} || $data->{"days"} !~ /^\d{1,}$/) {
        $data->{"days"} = 365;
    }
    if (defined $data->{"certType"}) {
        $certType = $data->{"certType"};
    }

    # test if the file already exists
    if(SCR::Read(".target.size", "$CAM_ROOT/$caName/req/".$request.".req") == -1) {
        return $self->SetError(summary => "Request does not exists.",
                               code => "FILE_DOES_NOT_EXIST");
    }

    # get next serial number and built the certificate file name
    my $serial = SCR::Read(".caTools.nextSerial", $caName);
    if(not defined $serial) {
        return $self->SetError(%{SCR::Error(".caTools")});
    }
    $certificate = $serial.":".$request;

    # create the configuration file
    my $retCode = SCR::Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if(not defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }

    # check time period of the CA against DAYS to sign this cert
    my $caP = $self->ReadCA({caName => $caName, type => 'parsed'});
    if(not defined $caP) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return undef;
    }
    my $notafter = SCR::Execute(".openssl.getNumericDate", $caName, $caP->{'NOTAFTER'});
    if(not defined $notafter) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    #                     year    month  day  hour   min  sec
    if( $notafter !~ /^(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "Can not parse CA date string '$notafter'",
                                code    => "PARSE_ERROR");
    }
    my @expireCA = ($1, $2, $3, $4, $5, $6);
    my @expireCertDate = Add_Delta_DHMS(Today_and_Now(), $data->{"days"}, 0, 0, 0);

    my $expireCertTime = Date_to_Time(@expireCertDate);
    my $expireCATime   = Date_to_Time(@expireCA);

    if($expireCertTime > $expireCATime) {
        my $caStr = sprintf("%s-%s-%s %s:%s:%s", @expireCA);
        my $certStr = sprintf("%s-%s-%s %s:%s:%s", @expireCertDate);
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError( summary => "CA expires before the certificate should expire. ".
                                "CA expires:'$caStr', Cert should expire:'$certStr'",
                                code  => 'PARAM_CHECK_FAILED');
    }

    if(not SCR::Write(".var.lib.YaST2.CAM.value.$caName.".$certType."_cert.x509_extensions", 
                      "v3_".$certType))
    { 
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
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
                 'basicConstraints'       => 'CA:FALSE',
                 'nsComment'              => 'YaMC Generated Certificate',
                 'nsCertType'             => 'client, email, objsign',
                 'keyUsage'               => 'nonRepudiation, digitalSignature, keyEncipherment',
                 'subjectKeyIdentifier'   => 'hash',
                 'authorityKeyIdentifier' => 'keyid:always,issuer:always',
                 'subjectAltName'         => 'email:copy',
                 'issuerAltName'          => 'issuer:copy',
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
        if(not defined YaST::caUtils->mergeToConfig($extName, 'v3_'.$certType,
                                                         $data, $v3ext{$extName}))
        {
            SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return $self->SetError(%{YaST::caUtils->Error()});
        }
    }

    if(not SCR::Write(".var.lib.YaST2.CAM", undef)) 
    {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
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
    my $ret = SCR::Execute( ".openssl.issueCert", $caName, $hash);

    if (not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    
    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return $certificate;
}

=item *
C<$name = AddCertificate($valueMap)>

create a new Certificate and returns the name

EXAMPLE:


=cut

BEGIN { $TYPEINFO{AddCertificate} = ["function", "string", "any" ]; }
sub AddCertificate {
    my $self = shift;
    my $data = shift;

    my $request = $self->AddRequest($data);
    if(not defined $request) {
        return undef;
    }
    $data->{'request'} = $request;
    my $certificate = $self->IssueCertificate($data);
    if(not defined $certificate) {
        my $caName = $data->{'caName'};
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/req/".$request.".req");
        return undef;
    }

    return $certificate;
}

=item *
C<$certList = ReadCertificateList($valueMap)>

returns a list of maps with all certificates of a special CA

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ReadCertificateList} = ["function", "any", "any"]; }
sub ReadCertificateList {
    my $self = shift;
    my $data = shift;
    my $ret  = undef;

    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Missing parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};
    if (defined $data->{'caPasswd'} &&
        length($data->{'caPasswd'}) < 4) {
        return $self->SetError(summary => "Wrong value for parameter 'caPasswd'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    if( defined $data->{'caPasswd'} ) {    # needed only for UpdateDB
        $ret = $self->UpdateDB($data);
        if ( not defined $ret ) {
            return undef;
        }
    }

    $ret = SCR::Read(".caTools.certificateList", $data->{'caName'});
    if ( not defined $ret ) {
        return $self->SetError(%{SCR::Error(".caTools")});
    }
    return $ret;
}

=item *
C<$bool = UpdateDB($valueMap)>

update the internal openssl database

EXAMPLE:


=cut

BEGIN { $TYPEINFO{UpdateDB} = ["function", "boolean", "any"]; }
sub UpdateDB {
    my $self = shift;
    my $data = shift;
    
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Missing parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    my $caName = $data->{'caName'};
    if (not defined $data->{'caPasswd'} ||
        length($data->{'caPasswd'}) < 4) {
        return $self->SetError(summary => "Wrong value for parameter 'caPasswd'.",
                               code    => "PARAM_CHECK_FAILED");
    }

    my $hash = {
                CAKEY  => "$CAM_ROOT/$caName/cacert.key",
                CACERT => "$CAM_ROOT/$caName/cacert.pem",
                PASSWD => $data->{'caPasswd'}
               };
    my $ret = SCR::Execute(".openssl.updateDB", $data->{'caName'}, $hash);
    if ( not defined $ret ) {
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    return 1;
}

=item *
C<$cert = ReadCertificate($valueMap)>

returns a certificate as plain text or parsed map

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ReadCertificate} = ["function", "any", "any"]; }
sub ReadCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";
    my $type   = "";
    my $ret = undef;

   # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (not defined $data->{"type"} || 
        !grep( ( $_ eq $data->{"type"}), ("parsed", "plain"))) 
      {
          return $self->SetError(summary => "Wrong value for parameter 'type'",
                                 code => "PARAM_CHECK_FAILED");
      }
    $type = $data->{"type"};
    
    if (not defined $data->{"certificate"} || 
        $data->{'certificate'} !~ /^[:A-Za-z0-9\/=+]+$/)
    {
        return $self->SetError(summary => "Wrong value for parameter 'certificate'",
                               code => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};

    my $size = SCR::Read(".target.size", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
    if($size <= 0) {
        return $self->SetError(summary => "Certificate '$certificate.pem' not available in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem",
                INFORM => "PEM"
               };
    if($type eq "parsed") {
        $ret = SCR::Read(".openssl.getParsedCert", $caName, $hash);
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
    } else {
        $ret = SCR::Read(".openssl.getTXTCert", $caName, $hash);
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$bool = RevokeCertificate($valueMap)>

revoke a certificate

EXAMPLE:


=cut

BEGIN { $TYPEINFO{RevokeCertificate} = ["function", "boolean", "any"]; }
sub RevokeCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";

    if(not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
        return $self->SetError( summary => "Missing value 'caName'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    
    if(!defined $data->{"caPasswd"} ) {
        return $self->SetError( summary => "Missing value 'caPasswd'",
                                code    => "CHECK_PARAM_FAILED");
    }
    if(!defined $data->{"certificate"} ) {
        return $self->SetError( summary => "Missing value 'certificate'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $certificate = $data->{"certificate"};

    my $size = SCR::Read(".target.size", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
    if($size <= 0) {
        return $self->SetError(summary => "Certificate '$certificate.pem' not available in '$caName'",
                               code => "FILE_DOES_NOT_EXIST");
    }

    my $hash = {
                CAKEY  => "$CAM_ROOT/$caName/cacert.key",
                CACERT => "$CAM_ROOT/$caName/cacert.pem",
                PASSWD => $data->{'caPasswd'},
                INFILE => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem"
               };
    if(defined $data->{'crlReason'}) {
        $hash->{'CRL_REASON'} = $data->{'crlReason'};
    }
    my $ret = SCR::Execute(".openssl.revoke", $caName, $hash);
    if(not defined $ret) {
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    return 1;
}

=item *
C<$bool = AddCRL($valueMap)>

create a CRL

EXAMPLE:


=cut

BEGIN { $TYPEINFO{AddCRL} = ["function", "boolean", "any"]; }
sub AddCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";

    if(not defined YaST::caUtils->checkCommonValues($data)) {
        return $self->SetError(%{YaST::caUtils->Error()});
    }

    # checking requires
    if (!defined $data->{"caName"}) {
        return $self->SetError( summary => "Missing value 'caName'",
                                code    => "CHECK_PARAM_FAILED");
    }
    $caName = $data->{"caName"};
    
    if(!defined $data->{"caPasswd"} ) {
        return $self->SetError( summary => "Missing value 'caPasswd'",
                                code    => "CHECK_PARAM_FAILED");
    }
    if(!defined $data->{"days"} ) {
        return $self->SetError( summary => "Missing value 'days'",
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
    my $ret = SCR::Execute(".openssl.issueCrl", $caName, $hash);
    if(not defined $ret) {
        return $self->SetError(%{SCR::Error(".openssl")});
    }

    $ret = SCR::Execute(".target.bash", 
                        "cp $CAM_ROOT/$caName/crl/crl.pem $CAM_ROOT/.cas/crl_$caName.pem");
    if(not defined $ret || $ret != 0) {
        return $self->SetError( summary => "Can not copy CRL",
                                code => "COPY_FAILED");
    }
    $ret = SCR::Execute(".target.bash", "c_rehash $CAM_ROOT/.cas/");
    if(not defined $ret || $ret != 0) {
        return $self->SetError( summary => "Can not create hash vaules in '$CAM_ROOT/.cas/'",
                                code => "C_REHASH_FAILED");
    }
    return 1;
}

=item *
C<$crl = ReadCRL($valueMap)>

returns a CRL as plain text or parsed map

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ReadCRL} = ["function", "any", "any"]; }
sub ReadCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $type   = "";
    my $ret = undef;

   # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
    
    if (not defined $data->{"type"} || 
        !grep( ($_ eq $data->{"type"}), ("parsed", "plain"))) 
      {
          return $self->SetError(summary => "Wrong value for parameter 'type'",
                                 code => "PARAM_CHECK_FAILED");
      }
    $type = $data->{"type"};
    
    my $size = SCR::Read(".target.size", "$CAM_ROOT/$caName/crl/crl.pem");
    if($size <= 0) {
        return $self->SetError(summary => "CRL not available in '$caName'",
                        code => "FILE_DOES_NOT_EXIST");
    }
    my $hash = {
                INFILE => "$CAM_ROOT/$caName/crl/crl.pem",
                INFORM => "PEM",
               };
    if($type eq "parsed") {
        $ret = SCR::Read(".openssl.getParsedCRL", $caName, $hash);
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
    } else {
        $ret = SCR::Read(".openssl.getTXTCRL", $caName, $hash);
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
    }
    return $ret;
}

=item *
C<$file = ExportCA($valueMap)>

Export a CA to a file or returns it in different formats

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ExportCA} = ["function", "any", "any"]; }
sub ExportCA {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $destinationFile = undef;
    my $format = undef;

    # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                        code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};

    if(defined $data->{'destinationFile'}) {
        $data->{'destinationFile'} =~ /^(\/.+\/)[A-Za-z0-9-_.]+$/;
        if(not defined $1) {
            return $self->SetError(summary => "Can not parse 'destinationFile' '".$data->{'destinationFile'}."'",
                                   code => "PARAM_CHECK_FAILED");
        }
        my $ret = SCR::Read(".target.dir", $1);
        if(not defined $ret) {
            return $self->SetError(summary => "Directory '$1' does not exist.",
                                   code => "DIR_DOES_NOT_EXIST");
        }
        $destinationFile = $data->{'destinationFile'};
    }

    if (not defined $data->{"exportFormat"} || 
        !grep( ( $_ eq $data->{"exportFormat"}), 
                                  ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY",
                                   "DER_CERT", "PKCS12", "PKCS12_CHAIN"))) 
    {
        return $self->SetError(summary => "Wrong value for parameter 'exportFormat'",
                               code => "PARAM_CHECK_FAILED");
    }
    $format = $data->{"exportFormat"};

    if(not defined $data->{'caPasswd'}) {
        return $self->SetError(summary => "Wrong value for parameter 'caPasswd'",
                               code => "PARAM_CHECK_FAILED");
    }
    
    if(not defined SCR::Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'caPasswd'}, 
                                                             CACERT => 1}))
    {
        return $self->SetError(%{SCR::Error(".caTools")});
    }

    if($format eq "PEM_CERT") {
        my $file = SCR::Read(".target.string", "$CAM_ROOT/$caName/cacert.pem");
        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                       code => "OPEN_FAILED");
            }
            print OUT $file;
            close OUT;
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "PEM_CERT_KEY") {

        my $file1 = SCR::Read(".target.string", "$CAM_ROOT/$caName/cacert.pem");

        my $hash = {
                    DATATYPE => "KEY",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/cacert.key",
                    OUTFORM  => "PEM",
                    INPASSWD => $data->{'caPasswd'},
                   };

        my $file2 = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file2) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                       code => "OPEN_FAILED");
            }
            print OUT $file1;
            print OUT "\n";
            print OUT $file2;
            close OUT;
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif($format eq "PEM_CERT_ENCKEY") {
        my $file1 = SCR::Read(".target.string", "$CAM_ROOT/$caName/cacert.pem");
        my $file2 = SCR::Read(".target.string", "$CAM_ROOT/$caName/cacert.key");
        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                       code => "OPEN_FAILED");
            }
            print OUT $file1;
            print OUT "\n";
            print OUT $file2;
            close OUT;
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif($format eq "DER_CERT") {

        my $hash = {
                    DATATYPE => "CERTIFICATE",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/cacert.pem",
                    OUTFORM  => "DER"
                   };

        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }
        
        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "PKCS12") {
        if(!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
            return $self->SetError(summary =>"Parameter 'P12Password' missing",
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

        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "PKCS12_CHAIN") {

        if(!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
            return $self->SetError(summary =>"Parameter 'P12Password' missing",
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

        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    }
}

=item *
C<$file = ExportCertificate($valueMap)>

Export a certificate to a file or returns it in different formats

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ExportCertificate} = ["function", "any", "any"]; }
sub ExportCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";
    my $destinationFile = undef;
    my $format = undef;

    # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};

    if (not defined $data->{'certificate'} ||
        $data->{'certificate'} !~ /^[:A-Za-z0-9\/=+]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'certificate'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};
    $certificate =~ /^[[:xdigit:]]+:([A-Za-z0-9\/=+]+)$/;
    if(not defined $1) {
        return $self->SetError(summary => "Can not parse certificate name",
                               code => "PARSING_ERROR");
    }
    my $keyname = $1;
    
    if(defined $data->{'destinationFile'}) {
        $data->{'destinationFile'} =~ /^(\/.+\/)[A-Za-z0-9-_.]+$/;
        if(not defined $1) {
            return $self->SetError(summary => "Can not parse 'destinationFile' '".$data->{'destinationFile'}."'",
                                   code => "PARAM_CHECK_FAILED");
        }
        my $ret = SCR::Read(".target.dir", $1);
        if(not defined $ret) {
            return $self->SetError(summary => "Directory '$1' does not exist.",
                                   code => "DIR_DOES_NOT_EXIST");
        }
        $destinationFile = $data->{'destinationFile'};
    }

    if (not defined $data->{"exportFormat"} || 
        !grep( ( $_ eq $data->{"exportFormat"}),
                                  ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY",
                                   "DER_CERT", "PKCS12", "PKCS12_CHAIN"))) 
    {
        return $self->SetError(summary => "Wrong value for parameter 'exportFormat'",
                               code => "PARAM_CHECK_FAILED");
    }
    $format = $data->{"exportFormat"};

    if(not defined $data->{'keyPasswd'}) {
        return $self->SetError(summary => "Wrong value for parameter 'keyPasswd'",
                               code => "PARAM_CHECK_FAILED");
    }
    
    if(not defined SCR::Read(".caTools.checkKey", $caName, { PASSWORD => $data->{'keyPasswd'}, 
                                                             CERT => $certificate}))
    {
        return $self->SetError(%{SCR::Error(".caTools")});
    }

    if($format eq "PEM_CERT") {
        my $file = SCR::Read(".target.string",
                             "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                       code => "OPEN_FAILED");
            }
            print OUT $file;
            close OUT;
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "PEM_CERT_KEY") {
        if(SCR::Read(".target.size", "$CAM_ROOT/$caName/keys/".$keyname.".key") == -1) {
            return $self->SetError(summary => "Keyfile '$CAM_ROOT/$caName/keys/$keyname.key' does not exist",
                                   code => "FILE_DOES_NOT_EXIST");
        }

        my $file1 = SCR::Read(".target.string", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        my $hash = {
                    DATATYPE => "KEY",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/keys/".$keyname.".key",
                    OUTFORM  => "PEM",
                    INPASSWD => $data->{'keyPasswd'},
                   };

        my $file2 = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file2) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                       code => "OPEN_FAILED");
            }
            print OUT $file1;
            print OUT "\n";
            print OUT $file2;
            close OUT;
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif($format eq "PEM_CERT_ENCKEY") {
        my $file1 = SCR::Read(".target.string", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        my $file2 = SCR::Read(".target.string", "$CAM_ROOT/$caName/keys/".$keyname.".key");
        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                       code => "OPEN_FAILED");
            }
            print OUT $file1;
            print OUT "\n";
            print OUT $file2;
            close OUT;
            return 1;
        } else {
            return $file1."\n".$file2;
        }
    } elsif($format eq "DER_CERT") {

        my $hash = {
                    DATATYPE => "CERTIFICATE",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/newcerts/".$certificate.".pem",
                    OUTFORM  => "DER"
                   };

        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }
        
        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "PKCS12") {
        if(!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
            return $self->SetError(summary =>"Parameter 'P12Password' missing",
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

        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "PKCS12_CHAIN") {
        if(!defined $data->{'P12Password'} || $data->{'P12Password'} eq "") {
            return $self->SetError(summary =>"Parameter 'P12Password' missing",
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

        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }

        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    }
}

=item *
C<$file = ExportCRL($valueMap)>

Export a CRL to a file or returns it in different formats

EXAMPLE:


=cut

BEGIN { $TYPEINFO{ExportCRL} = ["function", "any", "any"]; }
sub ExportCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $destinationFile = undef;
    my $format = undef;

    # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};
 
    if (not defined $data->{"exportFormat"} || 
        !grep( ( $_ eq $data->{"exportFormat"}), ("PEM", "DER"))) 
    {
        return $self->SetError(summary => "Wrong value for parameter 'exportFormat'",
                               code => "PARAM_CHECK_FAILED");
    }
    $format = $data->{"exportFormat"};

    if(defined $data->{'destinationFile'}) {
        $data->{'destinationFile'} =~ /^(\/.+\/)[A-Za-z0-9-_.]+$/;
        if(not defined $1) {
            return $self->SetError(summary => "Can not parse 'destinationFile' '".$data->{'destinationFile'}."'",
                                   code => "PARAM_CHECK_FAILED");
        }
        my $ret = SCR::Read(".target.dir", $1);
        if(not defined $ret) {
            return $self->SetError(summary => "Directory '$1' does not exist.",
                                   code => "DIR_DOES_NOT_EXIST");
        }
        $destinationFile = $data->{'destinationFile'};
    }

    if(SCR::Read(".target.size", "$CAM_ROOT/$caName/crl/crl.pem") == -1) {
        return $self->SetError(summary => "CRL does not exist",
                        code => "FILE_DOES_NOT_EXIST");
    }

    if($format eq "PEM") {

        my $file = SCR::Read(".target.string", "$CAM_ROOT/$caName/crl/crl.pem");

        if(defined $destinationFile) {
            if(!open(OUT, "> $destinationFile")) {
                return $self->SetError(summary => "Can not open File '$destinationFile' '$!'",
                                code => "OPEN_FAILED");
            }
            print OUT $file;
            close OUT;
            return 1;
        } else {
            return $file;
        }
    } elsif($format eq "DER") {
        my $hash = {
                    DATATYPE => "CRL",
                    INFORM   => "PEM",
                    INFILE   => "$CAM_ROOT/$caName/crl/crl.pem",
                    OUTFORM  => "DER"
                   };
        
        if(defined $destinationFile) {
            $hash->{'OUTFILE'} = $destinationFile;
        }
        
        my $file = SCR::Execute(".openssl.dataConvert", $caName, $hash);
        if(not defined $file) {
            return $self->SetError(%{SCR::Error(".openssl")});
        }
        if(defined $destinationFile) {
            return 1;
        } else {
            return $file;
        }
    } else {
        return $self->SetError(summary => "Wrong value for parameter 'exportFormat'",
                        code => "PARAM_CHECK_FAILED");
    }
}

=item *
C<$bool = Verify($valueMap)>

verify a certificate

EXAMPLE:


=cut

BEGIN { $TYPEINFO{Verify} = ["function", "any", "any"]; }
sub Verify {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";

    # checking requires
    if (not defined $data->{'caName'} ||
        $data->{'caName'} !~ /^[A-Za-z0-9-_]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'caName'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $caName = $data->{"caName"};

    if (not defined $data->{'certificate'} ||
        $data->{'certificate'} !~ /^[:A-Za-z0-9\/=+]+$/) {
        return $self->SetError(summary => "Wrong value for parameter 'certificate'.",
                               code    => "PARAM_CHECK_FAILED");
    }
    $certificate = $data->{"certificate"};
    
    my $hash = { 
                CERT => "$CAM_ROOT/$caName/newcerts/$certificate.pem",
                CAPATH => "$CAM_ROOT/.cas/",
                CRLCHECK => 1
               };
    my $ret = SCR::Execute(".openssl.verify", $caName, $hash);
    if( not defined $ret ) {
        return $self->SetError(%{SCR::Error(".openssl")});
    }
    return $ret;
}

1;
