package YaST::caUtils;

BEGIN {
    push @INC, '/usr/share/YaST2/modules';
}

use strict;
use Errno qw(ENOENT);

use YaST::YCP;
use ycp;
use POSIX ();     # Needed for setlocale()

use Locale::gettext;
POSIX::setlocale(LC_MESSAGES, "");
textdomain("ca-management");

YaST::YCP::Import ("SCR");
YaST::YCP::Import ("IP");
YaST::YCP::Import ("Hostname");
YaST::YCP::Import ("URL");

our %TYPEINFO;
my %__error = ();
my $CAM_ROOT = "/var/lib/YaST2/CAM";


sub cleanCaInfrastructure {
    my $self = shift;
    my $caName = shift;
    if (!defined $caName || $caName eq "" || $caName =~ /\./) {
        return undef;
    }
    if(!defined $CAM_ROOT || $CAM_ROOT !~ /^\/var\/lib\/YaST2/) {
        return undef;
    }
    SCR->Execute(".target.bash", "rm -rf $CAM_ROOT/$caName");
}

sub checkValueWithConfig {
    my $self = shift;
    my $name     = shift || return undef;
    my $param    = shift || return undef;

    my $min      = undef;
    my $max      = undef;
    my $policy   = "optional"; # also possible supplied and match
    my $caName   = $param->{'caName'};

    # check for limits
    my $value = SCR->Read(".var.lib.YaST2.CAM.value.$caName.req_distinguished_name.$name"); 
    if(not defined $value) {
        $value = SCR->Read(".var.lib.YaST2.CAM.value.$caName.req_attributes.$name"); 
        # $name is not in req_distinguished_name nor in req_attributes
        # this is an error
        if (not defined $value) {
            return $self->SetError( summary => "Can not find $name in config file",
                                    code => "PARAM_CHECK_FAILED");
        }
        $min = SCR->Read(".var.lib.YaST2.CAM.value.$caName.req_attributes.".$name."_min");
        $max = SCR->Read(".var.lib.YaST2.CAM.value.$caName.req_attributes.".$name."_max");
    } else {
        $min = SCR->Read(".var.lib.YaST2.CAM.value.$caName.req_distinguished_name.".$name."_min");
        $max = SCR->Read(".var.lib.YaST2.CAM.value.$caName.req_distinguished_name.".$name."_max");
    }
    $policy = SCR->Read(".var.lib.YaST2.CAM.value.$caName.policy_server.$name");

    if( defined $param->{$name} ) {
        if( (defined $min) && length($param->{$name}) < $min ) {
            return $self->SetError( summary => sprintf(
                                                       _("Value '%s' is to short, must be min %s"),
                                                       $name, $min),
                                    code    => "PARAM_CHECK_FAILED");
        }
        if( (defined $max) && length($param->{$name}) > $max ) {
            return $self->SetError( summary => sprintf(
                                                       _("Value '%s' is to long, must be max %s"),
                                                       $name, $max),
                                    code    => "PARAM_CHECK_FAILED");
        }
    }

    # check the policy
    if( (defined $policy) && ($policy eq "supplied") && 
        (! defined $param->{$name} || $param->{$name} eq "")) {
        return $self->SetError( summary => sprintf(
                                                   _("Value '%s' must be set.",$name)),
                                code    => "PARAM_CHECK_FAILED");
    }
    # FIXME: add a "match check" here
    return 1;
}

sub mergeToConfig {
    my $self = shift;
    my $name     = shift || return undef;
    my $ext_name = shift || return undef;
    my $param    = shift || return undef;
    my $default  = shift || undef;
    my $caName = $param->{'caName'};
  
  my $cfg_exists = SCR->Read(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name");
  
  if (defined $default && (! defined $param->{"$name"} || $param->{"$name"} eq "")) {
      if (defined $cfg_exists) {  # a default in the configfile is given
          $param->{"$name"} = $cfg_exists;
      } else {                    # use hardcoded default
          $param->{"$name"} = "$default";
      }
  }

  if ((! defined $param->{"$name"} ) && (defined $cfg_exists )) {
      # remove value from config
      y2debug("remove value from config ($name)");
      if(not SCR->Write(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name", undef)) {
          return $self->SetError( summary => "Can not write to config file",
                                 code => "SCR_WRITE_FAILED");
      }
  } elsif (defined $param->{"$name"}) {
      # add or modify are the same here
      y2debug("modify value in config (".$param->{"$name"}."/$name");
      if(not SCR->Write(".var.lib.YaST2.CAM.value.$caName.$ext_name.$name", $param->{$name})) {
          return $self->SetError( summary => "Can not write to config file",
                                 code => "SCR_WRITE_FAILED");
      }
  } # else do nothing: $param->{"$name"} is not defined and not in the config file
  return 1;
}

sub checkCommonValues {
    my $self = shift;
    my $data = shift || return $self->SetError(summary=>"Missing 'data' map.",
                                              code => "PARAM_CHECK_FAILED");

    foreach my $key (keys %{$data}) {
        if ( $key eq "caName") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[A-Za-z0-9-_]+$/) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "certType") {
            if ( !grep( ($_ eq $data->{$key}), ("client", "server", "ca") ) ) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "newCaName") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[A-Za-z0-9-_]+$/) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "request") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[[:xdigit:]]+$/) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "certificate") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[[:xdigit:]]+:[[:xdigit:]]+$/) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyPasswd" || $key eq "caPasswd") {
            if (! defined $data->{$key} ||
                length($data->{$key}) < 4) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyLength") {
            if ( ! defined $data->{$key} ||
                 $data->{$key} !~ /^\d{3,4}$/ ) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "days") {
            if ( ! defined $data->{$key} ||
                 $data->{$key} !~ /^\d{1,}$/ ) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "crlReason") {
            if ( !grep( ($_ eq $data->{$key}), 
                                           ("unspecified", "keyCompromise", "CACompromise",
                                            "affiliationChanged", "superseded", 
                                            "cessationOfOperation", "certificateHold") ) ) 
            {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "commonName" || $key eq "emailAddress" ||
                  $key eq "countryName" || $key eq "stateOrProvinceName" ||
                  $key eq "localityName" || $key eq "organizationName" ||
                  $key eq "organizationalUnitName" || $key eq "challengePassword" ||
                  $key eq "unstructuredName") {
            if ($data->{$key} !~ /^[[:print:]]*$/ ) {
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
                                       code    => "PARAM_CHECK_FAILED");
            }
            if($key eq "emailAddress") {
                if (!defined $data->{$key} || $data->{$key} !~ /^[^@]+@[^@]+\.[^@]+$/) {
                    return $self->SetError(summary => sprintf(
                                                              _("Wrong value'%s' for parameter '%s'."),
                                                              $data->{$key}, $key),
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
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
                return $self->SetError( summary => sprintf(
                                                           _("Unknown value '%s' in '%s'."),
                                                           $p, $key),
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
                next if($p eq "critical");
                if ( !grep( ($_ eq $p), ("client", "server", "email", "objsign",
                                         "reserved", "sslCA", "emailCA", "objCA"))) {
                    return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
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
                if ( !grep( ($_ eq $p), ("digitalSignature", "nonRepudiation",
                                         "keyEncipherment", "dataEncipherment",
                                         "keyAgreement", "keyCertSign", "cRLSign",
                                         "encipherOnly", "decipherOnly")))
                { 
                    return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
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
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
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
                next if(grep( ($_ eq $p), ("issuer:always", "keyid:always",
                                           "issuer", "keyid")));
          
                return $self->SetError(summary => _("Wrong value for parameter")." '$key'.",
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
                    if (!defined $1 || $1 !~ /^[^@]+@[^@]+\.[^@]+$/) {
                        return $self->SetError(summary => sprintf(
                                                           _("Wrong value'%s' for parameter '%s'."),
                                                            $p, $key),
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*URI:(.+)\s*$/) {
                    if (!defined $1 || !URL->Check("$1")) {
                        return $self->SetError(summary =>  sprintf(
                                                           _("Wrong value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*DNS:(.+)\s*$/) {
                    if (!defined $1 || !Hostname->CheckDomain("$1")) {
                        return $self->SetError(summary => sprintf(
                                                           _("Wrong value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*RID:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^(\d+\.)+\d+$/) {
                        return $self->SetError(summary => sprintf(
                                                           _("Wrong value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*IP:(.+)\s*$/) {
                    if (!defined $1 || !(IP->Check4("$1") || IP->Check6("$1")) ) {
                        return $self->SetError(summary => sprintf(
                                                           _("Wrong value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => sprintf(
                                                            _("Wrong value'%s' for parameter '%s'."),
                                                            $p, $key),
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
            $data->{$key} =~ /^\s*(critical)?\s*,*\s*(.*)/ ;
            if (!URL->Check("$2")) {
                return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $2, $key),
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
                next if(grep( ($_ eq $p), ("serverAuth", "clientAuth", "codeSigning",
                                           "emailProtection", "timeStamping",
                                           "msCodeInd", "msCodeCom", "msCTLSign",
                                           "msSGC", "msEFS", "nsSGC")));
                return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key), 
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
                        if (!defined $1 || $1 !~ /^[^@]+@[^@]+\.[^@]+$/) {
                            return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*URI:(.+)\s*$/) {
                        if (!defined $1 || !URL->Check("$1")) {
                            return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*DNS:(.+)\s*$/) {
                        if (!defined $1 || !Hostname->CheckDomain("$1")) {
                            return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*RID:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^(\d+\.)+\d+$/) {
                            return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*IP:(.+)\s*$/) {
                        if (!defined $1 || !(IP->Check4("$1") || IP->Check6("$1")) ) {
                            return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } else {
                        return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $location, $key),
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
                    if (!defined $1 || !URL->Check("$1")) {
                        return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $1, $key),
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => sprintf(
                                                          _("Wrong value'%s' for parameter '%s'."),
                                                          $p, $key),
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


sub stringFromDN {
    my $self = shift;
    my $data = shift || return $self->SetError(summary => "Missing parameter 'data'",
                                              code => "PARAM_CHECK_FAILED");
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


sub SetError {
    my $self = shift;
    %__error = @_;
    if( !$__error{package} && !$__error{file} && !$__error{line})
    {
        @__error{'package','file','line'} = caller();
    }
    if ( defined $__error{summary} ) {
        y2error($__error{code}."[".$__error{line}.":".$__error{file}."] ".$__error{summary});
    } else {
        y2error($__error{code}."[".$__error{line}.":".$__error{file}."] ");
    }
    return undef;
}

sub Error {
    my $self = shift;
    return \%__error;
}
