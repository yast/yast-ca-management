package CaManagement;

our $VERSION="1.0.1";

use strict;
use Errno qw(ENOENT);

use YaST::YCP;
use ycp;
use URI::Escape;
use X500::DN;
use MIME::Base64;
use Date::Calc qw( Date_to_Time Add_Delta_DHMS Today_and_Now)
;
YaST::YCP::Import ("SCR");

#@YaST::Logic::ISA = qw( YaST );

our %TYPEINFO;

my $CAM_ROOT = "/var/lib/YaST2/CAM";

BEGIN { $TYPEINFO{ReadCAList} = ["function", "any"]; }
sub ReadCAList {
    my $self   = shift;
    my $caList = undef;

    my $ret = SCR::Read(".caTools.caList");
    if ( not defined $ret ) {
        return $self->SetError(%{SCR::Error(".caTools")});
    }
    return $ret;
}


BEGIN { $TYPEINFO{AddRootCA} = ["function", "boolean", "any" ]; }
sub AddRootCA {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";

    return undef if(not defined $self->checkCommonValues($data));

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
        my $ret = $self->checkValueWithConfig($DN_Part, $data);
        if(not defined $ret ) {
            $self->cleanCaInfrastructure($caName);
            return undef;
        }
        push @dn, $data->{$DN_Part};
    }

    if(not SCR::Write(".var.lib.YaST2.CAM.value.$caName.req.x509_extensions", "v3_ca"))
    { 
        $self->cleanCaInfrastructure($caName);
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
        $self->mergeToConfig($extName, 'v3_ca',
                             $data, $v3ext{$extName});
    }

    if(not SCR::Write(".var.lib.YaST2.CAM", undef)) 
    {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not write to config file",
                                code => "SCR_WRITE_FAILED");
    }
    my $hash = {
                OUTFILE  => "$CAM_ROOT/$caName/cacert.key",
                PASSWD   => $data->{"keyPasswd"},
                BITS     => $data->{"keyLength"}
               };
    my $ret = SCR::Execute( ".openca.openssl.genKey", $caName, $hash);

    if (not defined $ret) {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.req",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             PASSWD  => $data->{"keyPasswd"},
             DN      => \@dn };
    $ret = SCR::Execute( ".openca.openssl.genReq", $caName, $hash);
    if (not defined $ret) {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }

    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.pem",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             REQFILE => "$CAM_ROOT/$caName/cacert.req",
             PASSWD  => $data->{"keyPasswd"},
             DAYS    => $data->{"days"} 
            };
    $ret = SCR::Execute( ".openca.openssl.genCert", $caName, $hash);
    if (not defined $ret) {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    
    return 1;
}

BEGIN { $TYPEINFO{ReadCertificateDefaults} = ["function", "any", "any"]; }
sub ReadCertificateDefaults {
    my $self = shift;
    my $data = shift;
    my $caName   = "";
    my $certType = "";
    my $ret = {};

    return undef if(not defined $self->checkCommonValues($data));

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
        !$self->isOneOfList($data->{"type"}, ["parsed", "plain"])) 
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
    if($type eq "parsed") {
        $ret = SCR::Read(".openca.X509.getParsed", "$CAM_ROOT/$caName/cacert.pem");
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openca.X509")});
        }
    } else {
        $ret = SCR::Read(".openca.X509.getTXT", "$CAM_ROOT/$caName/cacert.pem");
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openca.X509")});
        }
    }
    return $ret;
}

BEGIN { $TYPEINFO{AddRequest} = ["function", "string", "any" ]; }
sub AddRequest {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $request = "";

    return undef if(not defined $self->checkCommonValues($data));

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
    my $requestString = $self->stringFromDN($data);
    
    return undef if(not defined $requestString);
    
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
        my $ret = $self->checkValueWithConfig($DN_Part, $data);
        if(not defined $ret ) {
            SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return undef;
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
        if(not defined $self->mergeToConfig($extName, 'v3_req',
                                            $data, $v3ext{$extName}))
        {
            SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return undef;
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
    my $ret = SCR::Execute( ".openca.openssl.genKey", $caName, $hash);

    if (not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/req/".$request.".req",
             KEYFILE => "$CAM_ROOT/$caName/keys/".$request.".key",
             PASSWD  => $data->{"keyPasswd"},
             DN      => \@dn };
    $ret = SCR::Execute( ".openca.openssl.genReq", $caName, $hash);
    if (not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/keys/".$request.".key");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }

    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return $request;
}

BEGIN { $TYPEINFO{IssueCertificate} = ["function", "string", "any" ]; }
sub IssueCertificate {
    my $self = shift;
    my $data = shift;
    my @dn   = ();
    my $caName  = "";
    my $request = "";
    my $certificate = "";
    my $certType = "client";

    return undef if(not defined $self->checkCommonValues($data));

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
    my $notafter = SCR::Execute(".openca.openssl.getNumericDate", $caName, $caP->{'NOTAFTER'});
    if(not defined $notafter) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
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
        if(not defined $self->mergeToConfig($extName, 'v3_'.$certType,
                                            $data, $v3ext{$extName}))
        {
            SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
            return undef;
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
    my $ret = SCR::Execute( ".openca.openssl.issueCert", $caName, $hash);

    if (not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    
    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return $certificate;
}

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

BEGIN { $TYPEINFO{ReadCertificateList} = ["function", "any", "any"]; }
sub ReadCertificateList {
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

    my $ret = $self->UpdateDB($data);
    if ( not defined $ret ) {
        return undef;
    }

    $ret = SCR::Read(".caTools.certificateList", $data->{'caName'});
    if ( not defined $ret ) {
        return $self->SetError(%{SCR::Error(".caTools")});
    }
    return $ret;
}

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

    my $retCode = SCR::Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if(not defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }

    my $hash = {
                CAKEY  => "$CAM_ROOT/$caName/cacert.key",
                CACERT => "$CAM_ROOT/$caName/cacert.pem",
                PASSWD => $data->{'caPasswd'}
               };
    my $ret = SCR::Read(".openca.openssl.updateDB", $data->{'caName'}, $hash);
    if ( not defined $ret ) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
}

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
        !$self->isOneOfList($data->{"type"}, ["parsed", "plain"])) 
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
    if($type eq "parsed") {
        $ret = SCR::Read(".openca.X509.getParsed", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openca.X509")});
        }
    } else {
        $ret = SCR::Read(".openca.X509.getTXT", "$CAM_ROOT/$caName/newcerts/".$certificate.".pem");
        if(not defined $ret) {
            return $self->SetError(%{SCR::Error(".openca.X509")});
        }
    }
    return $ret;
}

BEGIN { $TYPEINFO{RevokeCertificate} = ["function", "boolean", "any"]; }
sub RevokeCertificate {
    my $self = shift;
    my $data = shift;
    my $caName = "";
    my $certificate = "";

    return undef if(not defined $self->checkCommonValues($data));

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

    my $retCode = SCR::Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if(not defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
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
    my $ret = SCR::Execute(".openca.openssl.revoke", $caName, $hash);
    if(not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return 1;
}

BEGIN { $TYPEINFO{AddCRL} = ["function", "boolean", "any"]; }
sub AddCRL {
    my $self = shift;
    my $data = shift;
    my $caName = "";

    return undef if(not defined $self->checkCommonValues($data));

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

    my $retCode = SCR::Execute(".target.bash",
                               "cp $CAM_ROOT/$caName/openssl.cnf.tmpl $CAM_ROOT/$caName/openssl.cnf");
    if(not defined $retCode || $retCode != 0) {
        return $self->SetError( summary => "Can not create config file '$CAM_ROOT/$caName/openssl.cnf'",
                                code => "COPY_FAILED");
    }

    my $hash = {
                CAKEY   => "$CAM_ROOT/$caName/cacert.key",
                CACERT  => "$CAM_ROOT/$caName/cacert.pem",
                PASSWD  => $data->{'caPasswd'},
                DAYS    => $data->{'days'},
                OUTFORM => "PEM",
                OUTFILE => "$CAM_ROOT/$caName/crl/crl.pem"
               };
    my $ret = SCR::Execute(".openca.openssl.issueCrl", $caName, $hash);
    if(not defined $ret) {
        SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
        return $self->SetError(%{SCR::Error(".openca.openssl")});
    }
    SCR::Execute(".target.remove", "$CAM_ROOT/$caName/openssl.cnf");
    return 1;
}



sub cleanCaInfrastructure {
    my $self     = shift || return undef;
    my $caName = shift;
    if (!defined $caName || $caName eq "" || $caName =~ /\./) {
        return undef;
    }
    if(!defined $CAM_ROOT || $CAM_ROOT !~ /^\/var\/lib\/YaST2/) {
        return undef;
    }
    SCR::Execute(".target.bash", "rm -rf $CAM_ROOT/$caName");
}

sub checkValueWithConfig {
    my $self     = shift || return undef;
    my $name     = shift || return undef;
    my $param    = shift || return undef;

    my $min      = undef;
    my $max      = undef;
    my $policy   = "optional"; # also possible supplied and match
    my $caName   = $param->{'caName'};

    # check for limits
    my $value = SCR::Read(".var.lib.YaST2.CAM.value.$caName.req_distinguished_name.$name"); 
    if(not defined $value) {
        $value = SCR::Read(".var.lib.YaST2.CAM.value.$caName.req_attributes.$name"); 
        # $name is not in req_distinguished_name nor in req_attributes
        # this is an error
        if (not defined $value) {
            return $self->SetError( summary => "Can not find $name in config file",
                                    code => "PARAM_CHECK_FAILED");
        }
        $min = SCR::Read(".var.lib.YaST2.CAM.value.$caName.req_attributes.".$name."_min");
        $max = SCR::Read(".var.lib.YaST2.CAM.value.$caName.req_attributes.".$name."_max");
    } else {
        $min = SCR::Read(".var.lib.YaST2.CAM.value.$caName.req_distinguished_name.".$name."_min");
        $max = SCR::Read(".var.lib.YaST2.CAM.value.$caName.req_distinguished_name.".$name."_max");
    }
    $policy = SCR::Read(".var.lib.YaST2.CAM.value.$caName.policy_server.$name");

    if( defined $param->{$name} ) {
        if( (defined $min) && length($param->{$name}) < $min ) {
            return $self->SetError( summary => "Value '$name' is to short, must be min $min",
                                    code    => "PARAM_CHECK_FAILED");
        }
        if( (defined $max) && length($param->{$name}) > $max ) {
            return $self->SetError( summary => "Value '$name' is to long, must be max $max",
                                    code    => "PARAM_CHECK_FAILED");
        }
    }

    # check the policy
    if( (defined $policy) && ($policy eq "supplied") && 
        (not defined $param->{$name} || $param->{$name} eq "")) {
        return $self->SetError( summary => "Value '$name' must be set",
                                code    => "PARAM_CHECK_FAILED");
    }
    # FIXME: add a "match check" here
    return 1;
}

sub mergeToConfig {
  my $self     = shift || return undef;
  my $name     = shift || return undef;
  my $ext_name = shift || return undef;
  my $param    = shift || return undef;
  my $default  = shift || undef;
  my $caName = $param->{'caName'};
  
  my $cfg_exists = SCR::Read(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name");
  
  if (defined $default && (not defined $param->{"$name"} or $param->{"$name"} eq "")) {
      if (defined $cfg_exists) {  # a default in the configfile is given
          $param->{"$name"} = $cfg_exists;
      } else {                    # use hardcoded default
          $param->{"$name"} = "$default";
      }
  }

  if ((not defined $param->{"$name"} ) && (defined $cfg_exists )) {
      # remove value from config
      y2debug("remove value from config (".$param->{"$name"}."/$name");
      if(not SCR::Write(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name", undef)) {
          return $self->SetError( summary => "Can not write to config file",
                                  code => "SCR_WRITE_FAILED");
      }
  } elsif (defined $param->{"$name"}) {
      # add or modify are the same here
      y2debug("modify value in config (".$param->{"$name"}."/$name");
      if(not SCR::Write(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name", $param->{$name})) {
          return $self->SetError( summary => "Can not write to config file",
                                  code => "SCR_WRITE_FAILED");
      }
  } # else do nothing: $param->{"$name"} is not defined and not in the config file
  return 1;
}

sub checkCommonValues {
    my $self = shift || return undef;
    my $data = shift || return $self->SetError(summary=>"Missing 'data' map.",
                                               code => "PARAM_CHECK_FAILED");

    foreach my $key (keys %{$data}) {
        if ( $key eq "caName") {
            if (not defined $data->{$key} ||
                $data->{$key} !~ /^[A-Za-z0-9-_]+$/) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "certType") {
            if ( !$self->isOneOfList($data->{$key}, ["client", "server", "ca"] ) ) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "newCaName") {
            if (not defined $data->{$key} ||
                $data->{$key} !~ /^[A-Za-z0-9-_]+$/) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "template") {
            #FIXME: Is this parameter needed?
        } elsif ( $key eq "request") {
            if (not defined $data->{$key} ||
                $data->{$key} !~ /^[A-Za-z0-9\/=+]+$/) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "certificate") {
            if (not defined $data->{$key} ||
                $data->{$key} !~ /^[:A-Za-z0-9\/=+]+$/) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyPasswd" || $key eq "caPasswd") {
            if (not defined $data->{$key} ||
                length($data->{$key}) < 4) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyLength") {
            if ( not defined $data->{$key} ||
                 $data->{$key} !~ /^\d{3,4}$/ ) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "days") {
            if ( not defined $data->{$key} ||
                 $data->{$key} !~ /^\d{1,}$/ ) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "crlReason") {
            if ( !$self->isOneOfList($data->{$key}, ["unspecified", "keyCompromise", "CACompromise",
                                                     "affiliationChanged", "superseded", 
                                                     "cessationOfOperation", "certificateHold"] ) ) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "commonName" || $key eq "emailAddress" ||
                  $key eq "countryName" || $key eq "stateOrProvinceName" ||
                  $key eq "localityName" || $key eq "organizationName" ||
                  $key eq "organizationalUnitName" || $key eq "challengePassword" ||
                  $key eq "unstructuredName") {
            if ($data->{$key} !~ /^[[:print:]]*$/ ) {
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
            # this seems to be not needed
            #$data->{$key} =~ s/([`$"'\\])/\\$1/g ; 
        } elsif ( $key eq "basicConstraints") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                next if(uc($p) eq "CA:TRUE");
                next if(uc($p) eq "CA:FALSE");
                next if($p     =~ /pathlen:\d+/);
                return $self->SetError( summary => "Unknown value '$p' in '$key'.",
                                        code => "PARAM_CHECK_FAILED");
            } 
        } elsif ( $key eq "nsComment") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "nsCertType") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                if ( !$self->isOneOfList($p, ["client", "server", "email", "objsign",
                                              "reserved", "sslCA", "emailCA", "objCA"])) {
                    return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
        } elsif ( $key eq "keyUsage") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                if ( !$self->isOneOfList($p, ["digitalSignature", "nonRepudiation",
                                              "keyEncipherment", "dataEncipherment",
                                              "keyAgreement", "keyCertSign", "cRLSign",
                                              "encipherOnly", "decipherOnly"])) {
                    return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
        } elsif ( $key eq "subjectKeyIdentifier") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p eq "critical");
                next if($p eq "hash");
                next if($p =~ /^([[:xdigit:]]{2}:)+[[:xdigit:]]{2}$/);
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "authorityKeyIdentifier") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                next if($self->isOneOfList($p, ["issuer:always", "keyid:always",
                                                "issuer", "keyid"]));
          
                return $self->SetError(summary => "Wrong value for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "subjectAltName" || $key eq "issuerAltName") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            my @san = split(/\s*,\s*/ , $data->{$key});
            foreach my $p (@san) {
                next if($p eq "critical");
                next if($p eq "email:copy" && $key eq "subjectAltName");
                next if($p eq "issuer:copy" && $key eq "issuerAltName");
                if ($p =~ /^\s*email:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^[^@]+@[^@]+\.[^@]$/) {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*URI:(.+)\s*$/) {
                    if (!defined $1 || !$self->checkURI($1)) {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*DNS:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^[^_@]+\.[^_@]$/) {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*RID:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^(\d+\.)+\d+$/) {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*IP:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^\d+\.\d+\.\d+\.\d+$/) {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
            $data->{$key} = join(",", @san);
        } elsif ( $key eq "nsBaseUrl" || $key eq "nsRevocationUrl" ||
                  $key eq "nsCaRevocationUrl" || $key eq "nsRenewalUrl" ||
                  $key eq "nsCaPolicyUrl" ) {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            $data->{$key} =~ /^\s*critical\s*,\s*(.*)/ ;
            if (!checkURI($1)) {
                return $self->SetError(summary => "Wrong value'$1' for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "nsSslServerName") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "extendedKeyUsage") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                next if($p !~ /^(\d+\.)+\d+$/);
                next if($self->isOneOfList($p, ["serverAuth", "clientAuth", "codeSigning",
                                                "emailProtection", "timeStamping",
                                                "msCodeInd", "msCodeCom", "msCTLSign",
                                                "msSGC", "msEFS", "nsSGC"]));
                return $self->SetError(summary => "Wrong value '$p' for parameter '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        
        } elsif ( $key eq "authorityInfoAccess") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                my($accessOID, $location) = split(/\s*;\s*/ , $p, 2);
                if ( $accessOID eq "OCSP" || $accessOID eq "caIssuers" ||
                     $accessOID =~ /^(\d+\.)+\d+$/ ) {
                    if ($location =~ /^\s*email:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^[^@]+@[^@]+\.[^@]$/) {
                            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                                   code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*URI:(.+)\s*$/) {
                        if (!defined $1 || !$self->checkURI($1)) {
                            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                                   code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*DNS:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^[^_@]+\.[^_@]$/) {
                            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                                   code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*RID:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^(\d+\.)+\d+$/) {
                            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                                   code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*IP:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^\d+\.\d+\.\d+\.\d+$/) {
                            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                                   code    => "PARAM_CHECK_FAILED");
                        }
                    } else {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => "Wrong value '$location' for parameter '$key'.",
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
        } elsif ( $key eq "crlDistributionPoints") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => "Wrong use of 'critical' in '$key'.",
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p eq "critical");
                if ($p =~ /^\s*URI:(.+)\s*$/) {
                    if (!defined $1 || !$self->checkURI($1)) {
                        return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
        } else {
            # FIXME: What do we do here?
            y2error("ATTENTION: unsupported value '$key' = '".$data->{$key}."'");
        }
    }
    return 1;
}

sub isOneOfList {
    my $self  = shift || return 0;
    my $value = shift || return 0;
    my $list  = shift || return 0;
    
    foreach my $v (@$list) {
        return 1 if($v eq $value);
    }
    return 0;
}

sub checkURI {
    my $self     = shift || return 0;
    my $url      = shift || return 0;
    my $doEscape = shift || 0;
    
    
    my($scheme, $authority, $path, $query, $fragment) =
      $url =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

    return 0 if(not defined $scheme || $scheme eq "");
    return 0 if(not defined $authority || $authority !~ /\./);
    if($doEscape) {
        $url = $scheme."://".$authority.uri_escape($path);
        if(defined $query) {
            $url .= "?".uri_escape($query);
        }
        if(defined $fragment) {
            $url .= "#".uri_escape($fragment);
        }
        return $url;
    } else {
        return 1;
    }
}

sub stringFromDN {
    my $self = shift || return undef;
    my $data = shift || return $self->SetError(summary => "Missing parameter 'data'",
                                               code => "PARAM_CHECK_FAILED");;
    my @rdn = ();

    my @DN_Values = ('countryName', 
                     'stateOrProvinceName', 
                     'localityName',
                     'organizationName',
                     'organizationalUnitName',
                     'commonName',
                     'emailAddress',
                    );
    foreach my $name (@DN_Values) {
        if($name eq 'countryName') {
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('C'=>$data->{$name});
            }
        } elsif( $name eq 'stateOrProvinceName') {
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('ST'=>$data->{$name});
            }
        } elsif( $name eq 'localityName') {
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('L'=>$data->{$name});
            }
        } elsif( $name eq 'organizationName') {
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('O'=>$data->{$name});
            }
        } elsif( $name eq 'organizationalUnitName') {
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('OU'=>$data->{$name});
            }
        } elsif( $name eq 'commonName') {
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('CN'=>$data->{$name});
            }
        } elsif( $name eq 'emailAddress'){
            if(defined $data->{$name} && $data->{$name} ne "" ) {
                push @rdn, new X500::RDN('emailAddress'=>$data->{$name});
            }
        }
    }
    my $dn = new X500::DN(@rdn);
    if(defined $dn) {
        return $dn->getOpenSSLString();
    } else {
        return $self->SetError(summary => "Creating DN Object failed.",
                               code => "INI_OBJECT_FAILED");
    }
}

# -------------- error handling -------------------
my %__error = ();

BEGIN { $TYPEINFO{SetError} = ["function", "boolean", ["map", "string", "any" ]]; }
sub SetError {
    my $class = shift;      # so that SetError can be called via -> like all
                            # other SCRAgent functions
    %__error = @_;
    if( !$__error{package} && !$__error{file} && !$__error{line})
    {
        @__error{'package','file','line'} = caller();
    }
    if ( defined $__error{summary} ) {
        y2error($__error{code}."[".$__error{line}.":".$__error{file}." ".$__error{summary});
    } else {
        y2error($__error{code});
    }
    return undef;
}

BEGIN { $TYPEINFO{Error} = ["function", ["map", "string", "any"] ]; }
sub Error {
    return \%__error;
}

# -------------------------------------------------


1;
