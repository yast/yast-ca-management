package CaManagement;

our $VERSION="1.0.1";

use strict;
use Errno qw(ENOENT);

use YaST::YCP;
use ycp;
YaST::YCP::Import ("SCR");

#@YaST::Logic::ISA = qw( YaST );

our %TYPEINFO;

my $CAM_ROOT = "/var/lib/YaST2/CAM";

BEGIN { $TYPEINFO{ReadCAList} = ["function", ["list", "strings"]]; }
sub ReadCAList {
    my $self   = shift;
    my $caList = undef;

    my $ret = SCR::Read(".caTools.caList");
    if ( not defined $ret ) {
        return $self->SetError(SCR::Error(".caTools.caList"));
        #return $self->SetError(code => "SCR_READ_ERROR",
        #                summary => "Can not call SCR::Read(.caTools.caList)");
    }
    return @$ret;
}


BEGIN { $TYPEINFO{AddRootCA} = ["function", "boolean", [ "map", "string", "any" ] ]; }
sub AddRootCA {
    my $self = shift;
    my $data = shift;
    my @dn       = ();
    my $caName  = "";

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
#    if (!defined $data->{"emailAddress"} || $data->{"emailAddress"} eq "") {
#        return $self->SetError( summary => "missing value 'emailAddress'",
#                         code    => "CHECK_PARAM_FAILED");
#    }
#    if (!-d "$CAM_ROOT/$caName") {
#        return $self->SetError( summary => "'$CAM_ROOT/$caName' does not exist!",
#                         code    => "DIR_DOES_NOT_EXIST");
#    }
#    if (!-e "$CAM_ROOT/$caName/openssl.cnf") {
#        #return $self->SetError( summary => "'$CAM_ROOT/$caName/openssl.cnf' does not exist!",
#        #                       code    => -121)];
#        return undef;
#    }
#    if (-e "$CAM_ROOT/$caName/cacert.key" or -e "$CAM_ROOT/$caName/cacert.req" or
#        -e "$CAM_ROOT/$caName/cacert.pem" ) {
#        #return $self->SetError( summary => "CA '$caName' already exists in '$CAM_ROOT'",
#        #                       code    => -122)];
#        return undef;
#    }


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
        return $self->SetError(SCR::Error(".caTools"));
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

    if(not defined SCR::Write(".var.lib.YaST2.CAM.value.$caName.req.x509_extensions", "v3_ca"))
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

    if(not defined SCR::Write(".var.lib.YaST2.CAM.value.$caName", "nil")) 
    {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError( summary => "Can not write to config file",
                         code => "SCR_WRITE_FAILED");
    }

    my $hash = {
                OUTFILE  => "$CAM_ROOT/$caName/cacert.key",
                PASSWD   => $data->{"KeyPasswd"},
                BITS     => $data->{"KeyLength"}
               };
    my $ret = SCR::Execute( ".openca.openssl.genKey", $hash);

    if (not defined $ret) {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError(SCR::Error(".openca.openssl"));
    }
    
    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.req",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             PASSWD  => $data->{"KeyPasswd"},
             DN      => \@dn };
    $ret = SCR::Execute( ".openca.openssl.genReq", $hash);
    if (not defined $ret) {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError(SCR::Error(".openca.openssl"));
    }

    $hash = {
             OUTFILE => "$CAM_ROOT/$caName/cacert.pem",
             KEYFILE => "$CAM_ROOT/$caName/cacert.key",
             REQFILE => "$CAM_ROOT/$caName/cacert.req",
             PASSWD  => $data->{"KeyPasswd"},
             DAYS    => $data->{"days"} 
            };
    $ret = SCR::Execute( ".openca.openssl.genCert", $hash);
    if (not defined $ret) {
        $self->cleanCaInfrastructure($caName);
        return $self->SetError(SCR::Error(".openca.openssl"));
    }
    
    return 1;
}

sub cleanCaInfrastructure {
    my $self     = shift || return undef;
    my $caName = shift;
    if (!defined $caName || $caName eq "" || $caName =~ /\./) {
        return undef;
    }
    if(!defined $CAM_ROOT || $CAM_ROOT != /^\/var\/lib\/YaST2/) {
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
    SCR::Write(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name", "nil");
  } elsif (defined $param->{"$name"}) {
    # add or modify are the same here
    y2debug("modify value in config (".$param->{"$name"}."/$name");
    SCR::Write(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name", $param->{$name});
  }                             # else do nothing: $param->{"$name"} is not defined and not in the config file
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
          $data->{$key} !~ /^[A-Za-z0-9\/=+]+\.req$/) {
        return $self->SetError(summary => "Wrong value for parameter '$key'.",
                               code    => "PARAM_CHECK_FAILED");
      }
    } elsif ( $key eq "certificate") {
      if (not defined $data->{$key} ||
          $data->{$key} !~ /^[:A-Za-z0-9\/=+]+\.pem$/) {
        return $self->SetError(summary => "Wrong value for parameter '$key'.",
                               code    => "PARAM_CHECK_FAILED");
      }
    } elsif ( $key eq "keyPasswd") {
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
    } elsif ( $key eq "commonName") {
    } elsif ( $key eq "emailAddress") {
    } elsif ( $key eq "countryName") {
    } elsif ( $key eq "stateOrProvinceName") {
    } elsif ( $key eq "localityName") {
    } elsif ( $key eq "organizationName") {
    } elsif ( $key eq "organizationalUnitName") {
    } elsif ( $key eq "challengePassword") {
    } elsif ( $key eq "unstructuredName") {
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
          my $nu = 0;
          if (!defined $1 || !($nu = $self->checkURI($1, 1))) {
            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                   code    => "PARAM_CHECK_FAILED");
          }
          $p = "URI:$nu";
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
              $key eq "nsCaRevocationUrl" || "nsRenewalUrl" ||
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
            my $nu = 0;
            if (!defined $1 || !($nu = $self->checkURI($1, 1))) {
              return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                     code    => "PARAM_CHECK_FAILED");
            }
            $location = "URI:$nu";
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
          my $nu = 0;
          if (!defined $1 || !($nu = $self->checkURI($1, 1))) {
            return $self->SetError(summary => "Wrong value'$p' for parameter '$key'.",
                                   code    => "PARAM_CHECK_FAILED");
          }
          $p = "URI:$nu";
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
        y2error($__error{code}." ".$__error{summary});
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
