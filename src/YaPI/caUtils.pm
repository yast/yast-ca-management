###############################################################
# Copyright 2004, Novell, Inc.  All rights reserved.
#
# $Id$
###############################################################

package YaST::caUtils;

BEGIN {
    push @INC, '/usr/share/YaST2/modules';
}

use strict;
use Errno qw(ENOENT);

use LIMAL;
use LIMAL::CaMgm;
use YaST::YCP;
use ycp;
use Date::Calc qw( Date_to_Time );
use POSIX ();     # Needed for setlocale()

my $domain = "ca-management";

use Locale::gettext;
POSIX::setlocale(LC_MESSAGES, "");
textdomain("ca-management");

YaST::YCP::Import ("SCR");
YaST::YCP::Import ("IP");
YaST::YCP::Import ("Hostname");
YaST::YCP::Import ("URL");

our %TYPEINFO;
my %__error = ();
my $CAM_ROOT = "/var/lib/CAM";


my $transMap = {
                'Netscape CA Revocation Url'      => 'nsCaRevocationUrl',
                'Netscape CA Policy Url'          => 'nsCaPolicyUrl',
                'Netscape Base Url'               => 'nsBaseUrl',
                'Netscape Renewal Url'            => 'nsRenewalUrl',
                'Netscape Revocation Url'         => 'nsRevocationUrl',
                'Netscape Cert Type'              => 'nsCertType',
                'Netscape Comment'                => 'nsComment',
                'Netscape SSL Server Name'        => 'nsSslServerName',
                'X509v3 CRL Distribution Points'  => 'crlDistributionPoints',
                'X509v3 Basic Constraints'        => 'basicConstraints',
                'X509v3 Key Usage'                => 'keyUsage',
                'X509v3 Issuer Alternative Name'  => 'issuserAltName',
                'X509v3 Subject Alternative Name' => 'subjectAltName',
                'X509v3 Authority Key Identifier' => 'authorityKeyIdentifier',
                'X509v3 Extended Key Usage'       => 'extendedKeyUsage',
                'X509v3 Subject Key Identifier'   => 'subjectKeyIdentifier',
                'X509v3 Certificate Policies'     => 'certificatePolicies',
                'Authority Information Access'    => 'authorityInfoAccess',
                
                'nsCaRevocationUrl'      => 'Netscape CA Revocation Url'    ,
                'nsCaPolicyUrl'          => 'Netscape CA Policy Url'        ,
                'nsBaseUrl'              => 'Netscape Base Url'             ,
                'nsRenewalUrl'           => 'Netscape Renewal Url'          ,
                'nsRevocationUrl'        => 'Netscape Revocation Url'       ,
                'nsCertType'             => 'Netscape Cert Type'            ,
                'nsComment'              => 'Netscape Comment'              ,
                'nsSslServerName'        => 'Netscape SSL Server Name'      ,
                'crlDistributionPoints'  => 'X509v3 CRL Distribution Points',
                'basicConstraints'       => 'X509v3 Basic Constraints'      ,
                'keyUsage'               => 'X509v3 Key Usage'              ,
                'issuserAltName'         => 'X509v3 Issuer Alternative Name',
                'subjectAltName'         => 'X509v3 Subject Alternative Name',
                'authorityKeyIdentifier' => 'X509v3 Authority Key Identifier', 
                'extendedKeyUsage'       => 'X509v3 Extended Key Usage'     ,
                'subjectKeyIdentifier'   => 'X509v3 Subject Key Identifier' ,
                'certificatePolicies'    => 'X509v3 Certificate Policies'   ,
                'authorityInfoAccess'    => 'Authority Information Access'  ,
                     
                # double entry            'email'         => 'email',
                'URI'           => 'URI',
                'DNS'           => 'DNS',
                'Registered ID' => 'RID',
                'RID'           => 'Registered ID',
                'IP Address'    => 'IP',
                'IP'            => 'IP Address',
                'keyid'         => 'keyid',
                'caIssuers'     => 'CA Issuers',
                'CA Issuers'    => 'caIssuers',
                'OCSP'          => 'OCSP',

                'serverAuth'      => 'SSL/TLS Web Server Authentication',
                'clientAuth'      => 'SSL/TLS Web Client Authentication',
                'codeSigning'     => 'Code signing',
                'emailProtection' => 'E-mail Protection',
                'timeStamping'    => 'Trusted Timestamping',
                'msCodeInd'       => 'Microsoft Individual Code Signing',
                'msCodeCom'       => 'Microsoft Commercial Code Signing',
                'msCTLSign'       => 'Microsoft Trust List Signing',
                'msSGC'           => 'Microsoft Server Gated Crypto',
                'msEFS'           => 'Microsoft Encrypted File System',
                'nsSGC'           => 'Netscape Server Gated Crypto',

                'SSL/TLS Web Server Authentication' => 'serverAuth'    , 
                'SSL/TLS Web Client Authentication' => 'clientAuth'    , 
                'Code signing'                      => 'codeSigning'   , 
                'E-mail Protection'                 => 'emailProtection',
                'Trusted Timestamping'              => 'timeStamping'  , 
                'Microsoft Individual Code Signing' => 'msCodeInd'     , 
                'Microsoft Commercial Code Signing' => 'msCodeCom'     , 
                'Microsoft Trust List Signing'      => 'msCTLSign'     , 
                'Microsoft Server Gated Crypto'     => 'msSGC'         , 
                'Microsoft Encrypted File System'   => 'msEFS'         , 
                'Netscape Server Gated Crypto'      => 'nsSGC'         , 

                'client'   => 'SSL Client',
                'server'   => 'SSL Server',
                #                         'email'    => 'S/MIME',
                'objsign'  => 'Object Signing',
                'reserved' => 'Unused',
                'sslCA'    => 'SSL CA',
                'emailCA'  => 'S/MIME CA',
                'objCA'    => 'Object Signing CA',

                'digitalSignature' => 'Digital Signature',
                'nonRepudiation'   => 'Non Repudiation',
                'keyEncipherment'  => 'Key Encipherment',
                'dataEncipherment' => 'Data Encipherment',
                'keyAgreement'     => 'Key Agreement',
                'keyCertSign'      => 'Certificate Sign',
                'cRLSign'          => 'CRL Sign',
                'encipherOnly'     => 'Encipher Only',
                'decipherOnly'     => 'Decipher Only',


                'SSL Client'        => 'client'  ,  
                'SSL Server'        => 'server'  ,  
                'S/MIME'            => 'email'   ,  
                'Object Signing'    => 'objsign' , 
                'Unused'            => 'reserved',
                'SSL CA'            => 'sslCA'   ,
                'S/MIME CA'         => 'emailCA' ,
                'Object Signing CA' => 'objCA'   ,
                     
                'Digital Signature' => 'digitalSignature',
                'Non Repudiation'   => 'nonRepudiation'  ,
                'Key Encipherment'  => 'keyEncipherment' ,
                'Data Encipherment' => 'dataEncipherment',
                'Key Agreement'     => 'keyAgreement'    ,
                'Certificate Sign'  => 'keyCertSign'     ,
                'CRL Sign'          => 'cRLSign'         ,
                'Encipher Only'     => 'encipherOnly'    ,
                'Decipher Only'     => 'decipherOnly'    ,
               };

sub transformBasicConstaints {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit  = 0;
    my $ca    = undef;
    my $pathl = -1;

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }            
        if(uc($p) eq "CA:TRUE") {
            $ca = 1;
            next;
        }
        if(uc($p) eq "CA:FALSE") {
            $ca = 0;
            next;
        }
        if($p =~ /pathlen:(\d+)/ && defined $1) {
            $pathl = $1;
            # Oh, oh ... how to say perl that this is a number ...
            $pathl = $pathl + 0;
            next;
        }
    }

    my $bc = new LIMAL::CaMgm::BasicConstraintsExt();
    if(!defined $value || $value eq "") {
     
        $bc->setPresent(0);
        
    } else {

        $bc->setBasicConstraints($ca, $pathl);
        if($crit) {
            $bc->setCritical($crit);
        }
    }
    
    $exts->setBasicConstraints($bc);
    return 1;
}

sub transformStringExtension {
    my $self  = shift;
    my $exts  = shift;
    my $type  = shift;
    my $value = shift || undef;

    my $crit   = 0;
    my $string = "";

    if ( !grep( ($_ eq $type), 
                ("nsComment", "nsBaseUrl", "nsRevocationUrl",
                 "nsCaRevocationUrl", "nsRenewalUrl",
                 "nsCaPolicyUrl", "nsSslServerName") ) ) {

        return $self->SetError( summary => sprintf(__("Invalid type for StringExtension '%s'."),$type),
                                code => "PARAM_CHECK_FAILED");
    }

    if(defined $value && $value =~ /^\s*(critical\s*,)*\s*(.+)\s*$/) {

        if(defined $1 && $1 ne "") {
            $crit = 1;
        }
        if(defined $2) {
            $string = $2;
        }            
    }
    
    if($type eq "nsComment") {

        my $e = new LIMAL::CaMgm::NsCommentExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsComment($e);
        
    } elsif($type eq "nsBaseUrl") {

        my $e = new LIMAL::CaMgm::NsBaseUrlExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsBaseUrl($e);

    } elsif($type eq "nsRevocationUrl") {

        my $e = new LIMAL::CaMgm::NsRevocationUrlExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsRevocationUrl($e);

    } elsif($type eq "nsCaRevocationUrl") {

        my $e = new LIMAL::CaMgm::NsCaRevocationUrlExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsCaRevocationUrl($e);

    } elsif($type eq "nsRenewalUrl") {

        my $e = new LIMAL::CaMgm::NsRenewalUrlExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsRenewalUrl($e);

    } elsif($type eq "nsCaPolicyUrl") {

        my $e = new LIMAL::CaMgm::NsCaPolicyUrlExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsCaPolicyUrl($e);

    } elsif($type eq "nsSslServerName") {

        my $e = new LIMAL::CaMgm::NsSslServerNameExt();
        if(!defined $value || $value eq "") {
     
            $e->setPresent(0);
        
        } else {

            $e->setValue($string);
            if($crit) {
                $e->setCritical($crit);
            }
        }
    
        $exts->setNsSslServerName($e);
    }
    return 1;
}

sub transformNsCertType {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit   = 0;
    my $ct     = 0;

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }            
        if(lc($p) eq "client") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::client;

        } elsif(lc($p) eq "server") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::server;

        } elsif(lc($p) eq "email") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::email;

        } elsif(lc($p) eq "objsign") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::objsign;

        } elsif(lc($p) eq "reserved") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::reserved;

        } elsif(lc($p) eq "sslca") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::sslCA;

        } elsif(lc($p) eq "emailca") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::emailCA;

        } elsif(lc($p) eq "objca") {

            $ct |= $LIMAL::CaMgm::NsCertTypeExt::objCA;

        }
    }   
    
    my $e = new LIMAL::CaMgm::NsCertTypeExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {

        $e->setNsCertType($ct);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setNsCertType($e);

    return 1;
}

sub transformKeyUsage {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit   = 0;
    my $ku     = 0;

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }            
        if(lc($p) eq "digitalsignature") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::digitalSignature;

        } elsif(lc($p) eq "nonrepudiation") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::nonRepudiation;

        } elsif(lc($p) eq "keyencipherment") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::keyEncipherment;

        } elsif(lc($p) eq "dataencipherment") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::dataEncipherment;

        } elsif(lc($p) eq "keyagreement") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::keyAgreement;

        } elsif(lc($p) eq "keycertsign") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::keyCertSign;

        } elsif(lc($p) eq "crlsign") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::cRLSign;

        } elsif(lc($p) eq "encipheronly") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::encipherOnly;

        } elsif(lc($p) eq "decipheronly") {

            $ku |= $LIMAL::CaMgm::KeyUsageExt::decipherOnly;

        }
    }   
    
    my $e = new LIMAL::CaMgm::KeyUsageExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {

        $e->setKeyUsage($ku);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setKeyUsage($e);

    return 1;
}

sub transformSubjectKeyIdentifier {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit   = 0;
    my $auto   = 0;
    my $hv     = "";

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        if($p eq "hash") {
            $auto = 1;
            next;
        }
        if($p =~ /^([[:xdigit:]]{2}:)+[[:xdigit:]]{2}$/) {
            $hv = $p;
            next;
        }
    }

    my $e = new LIMAL::CaMgm::SubjectKeyIdentifierExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {

        $e->setSubjectKeyIdentifier($auto, $hv);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setSubjectKeyIdentifier($e);
    return 1;
}

sub transformAuthorityKeyIdentifier {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit   = 0;
    my $keyID  = $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::KeyID_none;
    my $issuer = $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::Issuer_none;

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        if($p eq "keyid") {
            $keyID = $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::KeyID_normal;
            next;
        }
        if($p eq "keyid:always") {
            $keyID = $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::KeyID_always;
            next;
        }
        if($p eq "issuer") {
            $issuer = $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::Issuer_normal;
            next;
        }
        if($p eq "issuer:always") {
            $issuer = $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::Issuer_always;
            next;
        }
    }

    my $e = new LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {

        $e->setKeyID($keyID);
        $e->setIssuer($issuer);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setAuthorityKeyIdentifier($e);

    return 1;
}

sub transformSubjectAltName {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";
    my $forDefaults = shift || 0;
    
    my $crit   = 0;
    my $emailCopy = 0;
    my $list = new LIMAL::CaMgm::LiteralValueList();

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        if($p eq "email:copy") {
            $emailCopy = 1;
            next;
        }
        if($p =~ /^MS-UPN:(.+)/)
        {
            if(!$forDefaults)
            {
                $list->push_back(new LIMAL::CaMgm::LiteralValue("1.3.6.1.4.1.311.20.2.3:$1"));
            }
            next;
        }
        if($p =~ /^K5PN:(.+)/)
        {
            if(!$forDefaults)
            {
                $list->push_back(new LIMAL::CaMgm::LiteralValue("1.3.6.1.5.2.2:$1"));
            }
            next;
        }
                    
        $list->push_back(new LIMAL::CaMgm::LiteralValue($p));
    }

    my $e = new LIMAL::CaMgm::SubjectAlternativeNameExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {

        $e->setCopyEmail($emailCopy);
        $e->setAlternativeNameList($list);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setSubjectAlternativeName($e);

    return 1;
}

sub transformIssuerAltName {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";
    my $forDefaults = shift || 0;
    
    my $crit       = 0;
    my $issuerCopy = 0;
    my $list = new LIMAL::CaMgm::LiteralValueList();

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        if($p eq "issuer:copy") {
            $issuerCopy = 1;
            next;
        }
        if($p =~ /^MS-UPN:(.+)/)
        {
            if(!$forDefaults)
            {
                $list->push_back(new LIMAL::CaMgm::LiteralValue("1.3.6.1.4.1.311.20.2.3:$1"));
            }
            next;
        }
        if($p =~ /^K5PN:(.+)/)
        {
            if(!$forDefaults)
            {
                $list->push_back(new LIMAL::CaMgm::LiteralValue("1.3.6.1.5.2.2:$1"));
            }
            next;
        }

        $list->push_back(new LIMAL::CaMgm::LiteralValue($p));
    }

    my $e = new LIMAL::CaMgm::IssuerAlternativeNameExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {
        
        $e->setCopyIssuer($issuerCopy);
        $e->setAlternativeNameList($list);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setIssuerAlternativeName($e);

    return 1;
}

sub transformExtendedKeyUsage {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit  = 0;
    my $list  = new LIMAL::StringList();
   
    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        $list->push_back($p);
    }

    my $e = new LIMAL::CaMgm::ExtendedKeyUsageExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {
        
        $e->setExtendedKeyUsage($list);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setExtendedKeyUsage($e);

    return 1;
}

sub transformAuthorityInfoAccess {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit  = 0;
    my $list  = new LIMAL::CaMgm::AuthorityInformationList();
   
    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        my($accessOID, $location) = split(/\s*;\s*/ , $p, 2);
        if ( $accessOID eq "OCSP" || $accessOID eq "caIssuers" ||
             $accessOID =~ /^(\d+\.)+\d+$/ ) {
         
            my $lv = new LIMAL::CaMgm::LiteralValue($location);
            my $ai = new LIMAL::CaMgm::AuthorityInformation($accessOID, $lv);

            $list->push_back($ai);
        }
    }

    my $e = new LIMAL::CaMgm::AuthorityInfoAccessExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {
        
        $e->setAuthorityInformation($list);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setAuthorityInfoAccess($e);

    return 1;
}

sub transformCrlDistributionPoints {
    my $self  = shift;
    my $exts  = shift;
    my $value = shift || "";

    my $crit       = 0;
    my $list = new LIMAL::CaMgm::LiteralValueList();

    foreach my $p (split(/\s*,\s*/ , $value)) {
        if($p eq "critical") {
            $crit = 1;
            next;
        }
        $list->push_back(new LIMAL::CaMgm::LiteralValue($p));
    }

    my $e = new LIMAL::CaMgm::CRLDistributionPointsExt();
    if(!defined $value || $value eq "") {
     
        $e->setPresent(0);
        
    } else {
        
        $e->setCRLDistributionPoints($list);
        if($crit) {
            $e->setCritical($crit);
        }
    }
    
    $exts->setCRLDistributionPoints($e);

    return 1;
}


sub extractBasicConstraits {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    if($ext->isCA()) {

        push @vals, "CA:TRUE";

    } else {

        push @vals, "CA:FALSE";

    }

    if($ext->getPathLength() != -1) {

        push @vals, "pathlen:".$ext->getPathLength();

    }

    $ret->{'basicConstraints'} = join(', ', @vals);

    return 1;
}

sub extractStringExtension {
    my $self = shift;
    my $ext  = shift;
    my $type = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    push @vals, $ext->getValue();
    
    $ret->{$type} = join(', ', @vals);

    return 1;
}

sub extractNsCertType {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }
    
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::client)) {
        push @vals, "client";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::server)) {
        push @vals, "server";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::email)) {
        push @vals, "email";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::objsign)) {
        push @vals, "objsign";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::reserved)) {
        push @vals, "reserved";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::sslCA)) {
        push @vals, "sslCA";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::emailCA)) {
        push @vals, "emailCA";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::NsCertTypeExt::objCA)) {
        push @vals, "objCA";
    }
    
    $ret->{'nsCertType'} = join(', ', @vals);

    return 1;
}

sub extractKeyUsage {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }
    
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::digitalSignature)) {
        push @vals, "digitalSignature";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::nonRepudiation)) {
        push @vals, "nonRepudiation";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::keyEncipherment)) {
        push @vals, "keyEncipherment";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::dataEncipherment)) {
        push @vals, "dataEncipherment";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::keyAgreement)) {
        push @vals, "keyAgreement";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::keyCertSign)) {
        push @vals, "keyCertSign";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::cRLSign)) {
        push @vals, "cRLSign";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::encipherOnly)) {
        push @vals, "encipherOnly";
    }
    if($ext->isEnabledFor($LIMAL::CaMgm::KeyUsageExt::decipherOnly)) {
        push @vals, "decipherOnly";
    }
    
    $ret->{'keyUsage'} = join(', ', @vals);

    return 1;
}

sub extractSubjectKeyIdentifier {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }
    
    if($ext->isAutoDetectionEnabled()) {

        push @vals, "hash";

    } else {

        push @vals, $ext->getKeyID();

    }
    
    $ret->{'subjectKeyIdentifier'} = join(', ', @vals);

    return 1;
}

sub extractAuthorityKeyIdentifier {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    if($ext->getKeyID() == $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::KeyID_normal)
    {
        push @vals, "keyid";
    }
    elsif($ext->getKeyID() == $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::KeyID_always)
    {
        push @vals, "keyid:always";
    }

    if($ext->getIssuer() == $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::Issuer_normal)
    {
        push @vals, "issuer";
    }
    elsif($ext->getIssuer() == $LIMAL::CaMgm::AuthorityKeyIdentifierGenerateExt::Issuer_always)
    {
        push @vals, "issuer:always";
    }
    
    $ret->{'authorityKeyIdentifier'} = join(', ', @vals);

    return 1;
}

sub extractSubjectAltName {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    if($ext->getCopyEmail()) {

        push @vals, "email:copy";

    }

    my $list = $ext->getAlternativeNameList();

    for(my $it = $list->begin();
        !$list->iterator_equal($it, $list->end());
        $list->iterator_incr($it)) 
    {
        if($list->iterator_value($it)->getType() eq "1.3.6.1.4.1.311.20.2.3")
        {
            push @vals, "MS-UPN:".$list->iterator_value($it)->getValue();
        }
        elsif($list->iterator_value($it)->getType() eq "1.3.6.1.5.2.2")
        {
            push @vals, "K5PN:".$list->iterator_value($it)->getValue();
        }
        else
        {
            push @vals, $list->iterator_value($it)->toString();
        }
    }
    
    $ret->{'subjectAltName'} = join(', ', @vals);

    return 1;
}

sub extractIssuerAltName {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    if($ext->getCopyIssuer()) {

        push @vals, "issuer:copy";

    }

    my $list = $ext->getAlternativeNameList();

    for(my $it = $list->begin();
        !$list->iterator_equal($it, $list->end());
        $list->iterator_incr($it)) 
    {
        if($list->iterator_value($it)->getType() eq "1.3.6.1.4.1.311.20.2.3")
        {
            push @vals, "MS-UPN:".$list->iterator_value($it)->getValue();
        }
        elsif($list->iterator_value($it)->getType() eq "1.3.6.1.5.2.2")
        {
            push @vals, "K5PN:".$list->iterator_value($it)->getValue();
        }
        else
        {
            push @vals, $list->iterator_value($it)->toString();
        }
    }
    
    $ret->{'issuerAltName'} = join(', ', @vals);

    return 1;
}

sub extractExtendedKeyUsage {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    my $list = $ext->getExtendedKeyUsage();

    for(my $it = $list->begin();
        !$list->iterator_equal($it, $list->end());
        $list->iterator_incr($it)) 
    {

        push @vals, $list->iterator_value($it);
        
    }
    
    $ret->{'extendedKeyUsage'} = join(', ', @vals);

    return 1;
}

sub extractAuthorityInfoAccess {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    my $list = $ext->getAuthorityInformation();

    for(my $it = $list->begin();
        !$list->iterator_equal($it, $list->end());
        $list->iterator_incr($it)) 
    {
        my $ai =  $list->iterator_value($it);
        my $str = $ai->getAccessOID().";".$ai->getLocation()->toString();
        push @vals, $str;
    }
    
    $ret->{'authorityInfoAccess'} = join(', ', @vals);

    return 1;
}

sub extractCrlDistributionPoints {
    my $self = shift;
    my $ext  = shift;
    my $ret  = shift;

    my @vals = ();

    if(!$ext->isPresent()) {

        return 1;

    }

    if($ext->isCritical()) {

        push @vals , "critical";

    }

    my $list = $ext->getCRLDistributionPoints();

    for(my $it = $list->begin();
        !$list->iterator_equal($it, $list->end());
        $list->iterator_incr($it)) 
    {
        push @vals, $list->iterator_value($it)->toString();
    }
    
    $ret->{'crlDistributionPoints'} = join(', ', @vals);

    return 1;
}

sub parseDN {
    my $self     = shift;
    my $dnObject = shift;
    my $ret = {};

    my $list = $dnObject->getDN();

    for(my $it = $list->begin();
        !$list->iterator_equal($it, $list->end());
        $list->iterator_incr($it)) {

        my $ov = $list->iterator_value($it)->getOpenSSLValue();

        $ov =~ /^(\w+)=(.*)/;
        if(defined $1 && $1 ne "" &&
           defined $2 && $2 ne "") {

            if(exists  $ret->{$1} &&
               defined $ret->{$1} &&
               ref($ret->{$1}) eq "ARRAY") {

                my @a = @{$ret->{$1}};
                
                push(@a, $2);
                $ret->{$1} = \@a;

            } else {

                $ret->{$1} = ["$2"];

            }
        }
    }
    return $ret;
}

sub getParsed {
    my $self = shift;
    my $cert = shift;
    my $ret  = {};
    
    $ret->{PLAIN_EXTENSIONS} = $cert->getExtensionsAsText();
    
    $ret->{DN_HASH} = $self->parseDN($cert->getSubjectDN());
    $ret->{ISSUER_HASH} = $self->parseDN($cert->getIssuerDN());

    $ret->{DN}     = $cert->getSubjectDN()->getOpenSSLString();
    $ret->{ISSUER} = $cert->getIssuerDN()->getOpenSSLString();

    my @a = split('\n', $cert->getCertificateAsText());

    my $found = 0;
   
    my $val = "";
    
    foreach my $line (@a) {
        chomp($line);

        if($line =~ /^\s*(Modulus.*)/) {
            $found = 1;
            $val   = $1;
        } elsif($line =~ /^\s*X509v3 extensions/) {
            $found = 0;
        } elsif($found && $line =~ /^\s*([0-9a-fA-F:]+)$/) {
            $val .= "\n    $1";
        } elsif($found && $line =~ /^\s*(.*)/) {
            $val .= "\n$1";
        }
    }
    $ret->{PUBKEY} = $val;

    $ret->{NOTBEFORE} = $self->time2human($cert->getStartDate());
    $ret->{NOTAFTER}  = $self->time2human($cert->getEndDate());
    
    $ret->{FINGERPRINT} = $cert->getFingerprint();
    $ret->{KEYSIZE}     = $cert->getKeysize();

    if($cert->getPublicKeyAlgorithm() == $LIMAL::CaMgm::E_RSA) {

        $ret->{PUBKEY_ALGORITHM} = "rsaEncryption";

    } elsif($cert->getPublicKeyAlgorithm() == $LIMAL::CaMgm::E_DSA) {

        $ret->{PUBKEY_ALGORITHM} = "dsaEncryption";

    } elsif($cert->getPublicKeyAlgorithm() == $LIMAL::CaMgm::E_DH) {

        $ret->{PUBKEY_ALGORITHM} = "dhEncryption";

    }
    if($cert->getSignatureAlgorithm() == $LIMAL::CaMgm::E_SHA1RSA) {

        $ret->{SIGNATURE_ALGORITHM} = "sha1WithRSAEncryption";

    } elsif($cert->getSignatureAlgorithm() == $LIMAL::CaMgm::E_MD5RSA) {

        $ret->{SIGNATURE_ALGORITHM} = "md5WithRSAEncryption";

    } elsif($cert->getSignatureAlgorithm() == $LIMAL::CaMgm::E_SHA1DSA) {

        $ret->{SIGNATURE_ALGORITHM} = "sha1WithDSAEncryption";

    }
    $ret->{SERIAL} = $cert->getSerial();

    if($cert->getExtensions()->getBasicConstraints()->isPresent()) {
        if($cert->getExtensions()->getBasicConstraints()->isCA()) {
            $ret->{IS_CA} = 1;
        } else {
            $ret->{IS_CA} = 0;
        }
    } else {
        $ret->{IS_CA} = 0;
    }
    $ret->{VERSION} = $cert->getVersion();

    my @em = ();
    if(exists $ret->{DN_HASH}->{emailAddress}) {
        @em = @{$ret->{DN_HASH}->{emailAddress}};
    }
    
    if($cert->getExtensions()->getSubjectAlternativeName()->isPresent()) {

        my $list = $cert->getExtensions()->getSubjectAlternativeName()->getAlternativeNameList();

        for(my $it = $list->begin();
            !$list->iterator_equal($it, $list->end());
            $list->iterator_incr($it)) {
            
            if($list->iterator_value($it)->getType() eq "email") {
                
                push @em, $list->iterator_value($it)->getValue();
            }
        }
    }

    $ret->{EMAILADDRESS} = join("\n", @em);

    my $sig = unpack( "H*", pack("a*", $cert->getSignature()->data()));
    $ret->{SIGNATURE} = "";

    for(my $i = 0; $i < length($sig); $i = $i+2) {

        if($i > 0) {

            $ret->{SIGNATURE} .= ":";
        }

        if( $i > 0 && (($i/2) % 18) == 0 ) {

            $ret->{SIGNATURE} .= "\n";
        }

        $ret->{SIGNATURE} .= substr($sig, $i, 2);
    }

    $ret->{OPENSSL_EXTENSIONS} = $self->simpleExtParsing($cert);

    return $ret;
}

sub getParsedCRL {
    my $self = shift;
    my $crl  = shift;
    my $ret  = {};
    
    $ret->{PLAIN_EXTENSIONS} = $crl->getExtensionsAsText();
    
    $ret->{ISSUER_HASH} = $self->parseDN($crl->getIssuerDN());
    $ret->{ISSUER} = $crl->getIssuerDN()->getOpenSSLString();

    $ret->{LASTUPDATE} = $self->time2human($crl->getLastUpdateDate());
    $ret->{NEXTUPDATE} = $self->time2human($crl->getNextUpdateDate());
    
    $ret->{FINGERPRINT} = $crl->getFingerprint();

    if($crl->getSignatureAlgorithm() == $LIMAL::CaMgm::E_SHA1RSA) {

        $ret->{SIGNATURE_ALGORITHM} = "sha1WithRSAEncryption";

    } elsif($crl->getSignatureAlgorithm() == $LIMAL::CaMgm::E_MD5RSA) {

        $ret->{SIGNATURE_ALGORITHM} = "md5WithRSAEncryption";

    } elsif($crl->getSignatureAlgorithm() == $LIMAL::CaMgm::E_SHA1DSA) {

        $ret->{SIGNATURE_ALGORITHM} = "sha1WithDSAEncryption";

    }

    $ret->{VERSION} = $crl->getVersion();

    my $sig = unpack( "H*", pack("a*", $crl->getSignature()->data()));
    $ret->{SIGNATURE} = "";

    for(my $i = 0; $i < length($sig); $i = $i+2) {

        if($i > 0) {

            $ret->{SIGNATURE} .= ":";
        }

        if( $i > 0 && (($i/2) % 18) == 0 ) {

            $ret->{SIGNATURE} .= "\n";
        }

        $ret->{SIGNATURE} .= substr($sig, $i, 2);
    }

    $ret->{OPENSSL_EXTENSIONS} = $self->simpleExtParsing($crl);

    my @entries;

    my $revData = $crl->getRevocationData();

    for(my $mit = $revData->begin();
        !$revData->iterator_equal($mit, $revData->end());
        $revData->iterator_incr($mit))
    {
        my $entry = $revData->iterator_value($mit);
        my $hash = undef;

        $hash->{SERIAL} = $entry->getSerial();
        $hash->{DATE}   = $self->time2human($entry->getRevocationDate());

        my $reason = $entry->getReason();
        if($reason->getReason() ne "none") {

            $hash->{REASON} = $reason->getReason();
        }
        push @entries, $hash;
    }

    $ret->{REVOKED_PARSED} = \@entries;

    foreach my $r (@{$ret->{REVOKED_PARSED}}) {
        $ret->{REVOKED} .= $r->{SERIAL}."\n";
        $ret->{REVOKED} .= "        ".$r->{DATE}."\n";
        if(exists $r->{REASON} && defined $r->{REASON}) {
            $ret->{REVOKED} .= $r->{REASON};
            $r->{REASON} =~ s/^\s*(.+)\s*$/$1/gm;
        }
    }

    return $ret;
}

sub getParsedRequest {
    my $self = shift;
    my $req  = shift;
    my $ret  = {};
    
    $ret->{PLAIN_EXTENSIONS} = $req->getExtensionsAsText();
    
    $ret->{SUBJECT_HASH} = $self->parseDN($req->getSubjectDN());
    $ret->{DN}     = $req->getSubjectDN()->getOpenSSLString();

    my @a = split('\n', $req->getRequestAsText());

    my $found = 0;
   
    my $val = "";
    
    foreach my $line (@a) {
        chomp($line);

        if($line =~ /^\s*(Modulus.*)/) {
            $found = 1;
            $val   = $1;
        } elsif($line =~ /^\s*Attributes/ || $line =~ /^\s*Requested Extensions/) {
            $found = 0;
        } elsif($found && $line =~ /^\s*([0-9a-fA-F:]+)$/) {
            $val .= "\n    $1";
        } elsif($found && $line =~ /^\s*(.*)/) {
            $val .= "\n$1";
        }
    }
    $ret->{PUBKEY} = $val;

    #
    # is not supported by openssl command
    #
    #$ret->{FINGERPRINT} = $req->getFingerprint();

    $ret->{KEYSIZE}     = $req->getKeysize();

    if($req->getKeyAlgorithm() == $LIMAL::CaMgm::E_RSA) {

        $ret->{PUBKEY_ALGORITHM} = "rsaEncryption";

    } elsif($req->getKeyAlgorithm() == $LIMAL::CaMgm::E_DSA) {

        $ret->{PUBKEY_ALGORITHM} = "dsaEncryption";

    } elsif($req->getKeyAlgorithm() == $LIMAL::CaMgm::E_DH) {

        $ret->{PUBKEY_ALGORITHM} = "dhEncryption";

    }
    if($req->getSignatureAlgorithm() == $LIMAL::CaMgm::E_SHA1RSA) {

        $ret->{SIGNATURE_ALGORITHM} = "sha1WithRSAEncryption";

    } elsif($req->getSignatureAlgorithm() == $LIMAL::CaMgm::E_MD5RSA) {

        $ret->{SIGNATURE_ALGORITHM} = "md5WithRSAEncryption";

    } elsif($req->getSignatureAlgorithm() == $LIMAL::CaMgm::E_SHA1DSA) {

        $ret->{SIGNATURE_ALGORITHM} = "sha1WithDSAEncryption";

    }

    if($req->getExtensions()->getBasicConstraints()->isPresent()) {

        if($req->getExtensions()->getBasicConstraints()->isCA()) {
            $ret->{IS_CA} = 1;
        } else {
            $ret->{IS_CA} = 0;
        }
    } else {
        $ret->{IS_CA} = 0;
    }
    $ret->{VERSION} = $req->getVersion();

    my @em = ();
    if(exists $ret->{SUBJECT_HASH}->{emailAddress}) {
        @em = @{$ret->{SUBJECT_HASH}->{emailAddress}};
    }
    
    if($req->getExtensions()->getSubjectAlternativeName()->isPresent()) {

        my $list = $req->getExtensions()->getSubjectAlternativeName()->getAlternativeNameList();

        for(my $it = $list->begin();
            !$list->iterator_equal($it, $list->end());
            $list->iterator_incr($it)) {
            
            if($list->iterator_value($it)->getType() eq "email") {
                
                push @em, $list->iterator_value($it)->getValue();
                
            }
        }
    }

    $ret->{EMAILADDRESS} = join("\n", @em);

    my $sig = unpack( "H*", pack("a*", $req->getSignature()->data()));
    $ret->{SIGNATURE} = "";

    for(my $i = 0; $i < length($sig); $i = $i+2) {

        if($i > 0) {

            $ret->{SIGNATURE} .= ":";
        }

        if( $i > 0 && (($i/2) % 18) == 0 ) {

            $ret->{SIGNATURE} .= "\n";
        }

        $ret->{SIGNATURE} .= substr($sig, $i, 2);
    }

    $ret->{OPENSSL_EXTENSIONS} = $self->simpleExtParsing($req);

    return $ret;
}

sub simpleExtParsing {
    my $self = shift;
    my $cert = shift;
    my $ret  = {};

    my ($c, $val, $key);
    my @lines = split(/\n/, $cert->getExtensionsAsText());

    my $i = 0;
    while($i < @lines) {
        if($lines[$i] =~ /^\s*([^:]+):\s*(critical|\s*)$/i) {
            $key = $1;
            $ret->{$key} = [];
            push(@{$ret->{$key}}, $2) if($2 eq "critical");
            $i++;
            while($i < @lines && $lines[$i] !~ /^\s.+:\s*(critical|\s*)$/) {
                $val = $lines[$i];
                $val =~ s/^\s+//g;
                $val =~ s/\s+$//g;
                $i++;
                next if $val =~ /^$/;
                if($key eq "X509v3 Subject Alternative Name" || $key eq "X509v3 Issuer Alternative Name:")
                {
                    my @pairs = split(/\s*,\s*/, $val);
                    $val = "";
                    foreach my $pair (@pairs)
                    {
                        my ($k, $v) = split(/:/, $pair, 2);
                        if($k eq "othername")
                        {
                            next;
                        }
                        else
                        {
                            $val .= "$pair, ";
                        }
                    }

                    my $list = $cert->getExtensions()->getSubjectAlternativeName()->getAlternativeNameList();

                    for(my $it = $list->begin();
                        !$list->iterator_equal($it, $list->end());
                        $list->iterator_incr($it)) {
                        
                        if($list->iterator_value($it)->getType() eq "1.3.6.1.4.1.311.20.2.3") 
                        {
                            $val .= "MS-UPN:".$list->iterator_value($it)->getValue().", ";
                            
                        }
                        elsif($list->iterator_value($it)->getType() eq "1.3.6.1.5.2.2") 
                        {
                            $val .= "K5PN:".$list->iterator_value($it)->getValue().", ";
                        }
                    }
                }
                $val =~ s/, $//;
                push(@{$ret->{$key}}, $val);
            }
        } else {
            $i++;
        }
    }
    return $ret;
}

sub extensionParsing {
    my $this = shift;
    my $data = shift;

    my $ext = {};
    my $newExt = {};

    
    $ext = $data->{OPENSSL_EXTENSIONS};
    delete $data->{OPENSSL_EXTENSIONS};

    foreach my $a (keys %$ext) {
        
        my $newKey = $transMap->{$a};
        
        $newExt->{$newKey}->{description} = $a;
        $newExt->{$newKey}->{critical}    = 0;
        $newExt->{$newKey}->{value}       = [];
        
        foreach my $b (@{$ext->{$a}}) {

            if($b =~ /^\s*critical/) {
                $newExt->{$newKey}->{critical} = 1;
            }
            elsif($newKey eq 'nsBaseUrl'         || $newKey eq 'nsRevocationUrl' ||
                  $newKey eq 'nsCaRevocationUrl' || $newKey eq 'nsCaPolicyUrl' ||
                  $newKey eq 'nsRenewalUrl'      || $newKey eq 'nsComment' ||
                  $newKey eq 'nsSslServerName' )
              {
                  $newExt->{$newKey}->{value} = $b;
              }
            elsif($newKey eq 'authorityInfoAccess')
              {
                  my @sp = split(/\s-\s/, $b, 2);
                  my $h = {};

                  $h->{accessOID} = $transMap->{$sp[0]};

                  if(defined $sp[1]) {
                      my @sp1 = split(/:/, $sp[1], 2);

                      $h->{type}  = $transMap->{$sp1[0]};
                      if(!defined $h->{type}) {
                          $h->{type} = $sp1[0];
                      }
                      if(defined $sp1[1]) {
                          $h->{value} = $sp1[1];
                      } else {
                          $h->{value} = "";
                      }
                  } else {

                      $h->{type} = "";
                      $h->{value} = ""
                  }
                  push( @{$newExt->{$newKey}->{value}}, $h);
              }
            elsif($newKey eq 'subjectAltName' ||
                  $newKey eq 'issuserAltName' ||
                  $newKey eq 'crlDistributionPoints' ||
                  $newKey eq 'basicConstraints' ||
                  $newKey eq 'authorityKeyIdentifier'
                 )
              {
                  my @sp = split(/\s?,\s?/, $b);
                  foreach my $t (@sp) {


                      my @sp1 = split(/:/, $t, 2);
                      if($sp1[0] eq "othername")
                      {
                          # not supported by openssl
                          next;
                      }
                      
                      my $h = {};
                      $h->{type}  = $transMap->{$sp1[0]};
                      if(!defined $h->{type}) {
                          $h->{type} = $sp1[0];
                      }
                      if(defined $sp1[1]) {
                          $h->{value} = $sp1[1];
                      } else {
                          $h->{value} = "";
                      }

                      push( @{$newExt->{$newKey}->{value}}, $h);
                  }
              }
            else
            {
                  my @sp = split(/\s?,\s?/, $b);
                  foreach my $t (@sp) {
                      if(exists $transMap->{$t}) {
                          push( @{$newExt->{$newKey}->{value}}, $transMap->{$t});
                      } else {
                          push( @{$newExt->{$newKey}->{value}}, $t);
                      }
                  }
              }
        }
    }
    $data->{OPENSSL_EXTENSIONS} = $newExt;
    return $data;
}



sub time2human {
    my $self = shift;
    my $time = shift;
    my $ret  = "";

    my $monHash = { "1" => "Jan", "2" => "Feb", "3" => "Mar", 
                    "4" => "Apr", "5" => "May", "6" => "Jun",
                    "7" => "Jul", "8" => "Aug", "9" => "Sep",
                    "10"=> "Oct", "11"=> "Nov", "12"=> "Dec"};

    my ($year,$month,$day, $hour,$min,$sec) = 
      Date::Calc::Time_to_Date($time);

    $ret = $monHash->{$month}." $day $hour:$min:$sec $year GMT";
    return $ret;
}

sub checkCommonValues {
    my $self = shift;
    my $data = shift || return $self->SetError(summary => __("Missing 'data' map."),
                                               code    => "PARAM_CHECK_FAILED");
    
    foreach my $key (keys %{$data}) {
        # we check only common values. 
        # It is possible that keys appear which could not be checked.
        if ( $key eq "caName" || $key eq "newCaName") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[A-Za-z0-9-_]+$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
            if($data->{$key} =~ /^-/ || $data->{$key} =~ /-$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       description => "'-' as first or last character is forbidden.",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "certType") {
            if ( !grep( ($_ eq $data->{$key}), ("client", "server", "ca") ) ) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "request") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[[:xdigit:]]+[\d-]*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "certificate") {
            if (! defined $data->{$key} ||
                $data->{$key} !~ /^[[:xdigit:]]+:[[:xdigit:]]+[\d-]*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyPasswd" || $key eq "caPasswd") {
            if (! defined $data->{$key} ||
                length($data->{$key}) < 4) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyLength") {
            if ( ! defined $data->{$key} ||
                 $data->{$key} !~ /^\d{3,4}$/ ||
                 $data->{$key} < 512 ) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       description => "Minimal key length is 512 Bit",
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "days") {
            if ( ! defined $data->{$key} ||
                 $data->{$key} !~ /^\d{1,}$/ ) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "crlReason") {
            if ( !grep( ($_ eq $data->{$key}), 
                                           ("unspecified", "keyCompromise", "CACompromise",
                                            "affiliationChanged", "superseded", 
                                            "cessationOfOperation", "certificateHold") ) ) 
            {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "commonName" || $key eq "emailAddress" ||
                  $key eq "countryName" || $key eq "stateOrProvinceName" ||
                  $key eq "localityName" || $key eq "organizationName" ||
                  $key eq "organizationalUnitName" || $key eq "challengePassword" ||
                  $key eq "unstructuredName") {
            if ($data->{$key} !~ /^[[:print:]]*$/ ) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
            if($key eq "emailAddress") {
                if (!defined $data->{$key} || $data->{$key} !~ /^[^@]+@[^@]+$/) {
                    return $self->SetError(summary => sprintf(
                                                              __("Invalid value'%s' for parameter '%s'."),
                                                              $data->{$key}, $key),
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
        } elsif ( $key eq "basicConstraints") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                next if(uc($p) eq "CA:TRUE");
                next if(uc($p) eq "CA:FALSE");
                next if($p     =~ /pathlen:\d+/);
                return $self->SetError( summary => sprintf(
                                                           __("Unknown value '%s' in '%s'."),
                                                           $p, $key),
                                        code => "PARAM_CHECK_FAILED");
            } 
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "nsComment") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "nsCertType") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p eq "critical");
                if ( !grep( ($_ eq $p), ("client", "server", "email", "objsign",
                                         "reserved", "sslCA", "emailCA", "objCA"))) {
                    return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "keyUsage") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                       code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                if ( !grep( ($_ eq $p), ("digitalSignature", "nonRepudiation",
                                         "keyEncipherment", "dataEncipherment",
                                         "keyAgreement", "keyCertSign", "cRLSign",
                                         "encipherOnly", "decipherOnly")))
                { 
                    return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "subjectKeyIdentifier") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p eq "critical");
                next if($p eq "hash");
                next if($p =~ /^([[:xdigit:]]{2}:)+[[:xdigit:]]{2}$/);
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "authorityKeyIdentifier") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                next if(grep( ($_ eq $p), ("issuer:always", "keyid:always",
                                           "issuer", "keyid")));
          
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "subjectAltName" || $key eq "issuerAltName") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                       code => "PARAM_CHECK_FAILED");
            }
            my @san = split(/\s*,\s*/ , $data->{$key});
            foreach my $p (@san) {
                next if($p eq "critical");
                next if($p eq "email:copy" && $key eq "subjectAltName");
                next if($p eq "issuer:copy" && $key eq "issuerAltName");
                if ($p =~ /^\s*email:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^[^@]+@[^@]+$/) {
                        return $self->SetError(summary => sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*URI:(.+)\s*$/) {
                    if (!defined $1 || !URL->Check("$1")) {
                        return $self->SetError(summary =>  sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*DNS:(.+)\s*$/) {
                    if (!defined $1 || !Hostname->CheckDomain("$1")) {
                        return $self->SetError(summary => sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*RID:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^(\d+\.)+\d+$/) {
                        return $self->SetError(summary => sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*IP:(.+)\s*$/) {
                    if (!defined $1 || !(IP->Check4("$1") || IP->Check6("$1")) ) {
                        return $self->SetError(summary => sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*MS-UPN:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^[^@]+@[^@]+$/) {
                        return $self->SetError(summary => sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } elsif ($p =~ /^\s*K5PN:(.+)\s*$/) {
                    if (!defined $1 || $1 !~ /^[^@]+@[^@]+$/) {
                        return $self->SetError(summary => sprintf(
                                                           __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => sprintf(
                                                            __("Invalid value'%s' for parameter '%s'."),
                                                            $p, $key),
                                          code    => "PARAM_CHECK_FAILED");
                }
            }
            $data->{$key} = join(",", @san);
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "nsBaseUrl" || $key eq "nsRevocationUrl" ||
                  $key eq "nsCaRevocationUrl" || $key eq "nsRenewalUrl" ||
                  $key eq "nsCaPolicyUrl" ) {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            $data->{$key} =~ /^\s*(critical)?\s*,*\s*(.*)/ ;
            if (!URL->Check("$2")) {
                return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $2, $key),
                                      code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "nsSslServerName") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "extendedKeyUsage") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                next if($p =~ /^(\d+\.)+\d+$/);
                next if(grep( ($_ eq $p), ("serverAuth", "clientAuth", "codeSigning",
                                           "emailProtection", "timeStamping",
                                           "msCodeInd", "msCodeCom", "msCTLSign",
                                           "msSGC", "msEFS", "nsSGC")));
                return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key), 
                                      code    => "PARAM_CHECK_FAILED");
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        
        } elsif ( $key eq "authorityInfoAccess") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p     eq "critical");
                my($accessOID, $location) = split(/\s*;\s*/ , $p, 2);
                if ( $accessOID eq "OCSP" || $accessOID eq "caIssuers" ||
                     $accessOID =~ /^(\d+\.)+\d+$/ ) {
                    if ($location =~ /^\s*email:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^[^@]+@[^@]+$/) {
                            return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*URI:(.+)\s*$/) {
                        if (!defined $1 || !URL->Check("$1")) {
                            return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*DNS:(.+)\s*$/) {
                        if (!defined $1 || !Hostname->CheckDomain("$1")) {
                            return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*RID:(.+)\s*$/) {
                        if (!defined $1 || $1 !~ /^(\d+\.)+\d+$/) {
                            return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } elsif ($location =~ /^\s*IP:(.+)\s*$/) {
                        if (!defined $1 || !(IP->Check4("$1") || IP->Check6("$1")) ) {
                            return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                                  code    => "PARAM_CHECK_FAILED");
                        }
                    } else {
                        return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                              code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $accessOID, $key),
                                          code    => "PARAM_CHECK_FAILED");
                }
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        } elsif ( $key eq "crlDistributionPoints") {
            # test critical
            if ($data->{$key} =~ /critical/ && 
                $data->{$key} !~ /^\s*critical/) {
                return $self->SetError(summary => sprintf(__("Wrong use of 'critical' in '%s'."),$key),
                                      code => "PARAM_CHECK_FAILED");
            }
            foreach my $p (split(/\s*,\s*/ , $data->{$key})) {
                next if($p eq "critical");
                if ($p =~ /^\s*URI:(.+)\s*$/) {
                    if (!defined $1 || !URL->Check("$1")) {
                        return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $1, $key),
                                               code    => "PARAM_CHECK_FAILED");
                    }
                } else {
                    return $self->SetError(summary => sprintf(
                                                          __("Invalid value'%s' for parameter '%s'."),
                                                          $p, $key),
                                           code    => "PARAM_CHECK_FAILED");
                }
            }
            if ($data->{$key} =~ /^\s*(critical)?\s*$/) {
                return $self->SetError(summary => sprintf(__("Invalid value '%s' for parameter '%s'."),$data->{$key}, $key),
                                       code    => "PARAM_CHECK_FAILED");
            }
        }
    }
    return 1;
}

sub exception2String {
    my $self = shift;
    my $err  = shift || undef;
    
    if(!defined $err) 
    {
        return "";
    }
    elsif(ref($err) eq "HASH") 
    {
        my $msg = "";
        if(exists $err->{type} && defined $err->{type})
        {
            $msg .= $err->{type};
        }
        $msg .= ":";
        if(exists $err->{code} && defined $err->{code})
        {
            $msg .= $err->{code};
        }
        $msg .= ":";
        if(exists $err->{message} && defined $err->{message})
        {
            $msg .= $err->{message};
        }
        if(exists $err->{subexception} && defined $err->{subexception})
        {
            $msg .= "\n";
            $msg .= exception2String($err->{subexception});
        }
        return $msg;
    }
    else
    {
        return "$err";
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

sub __ {
    my $msgid = shift;
    return Locale::gettext::dgettext ($domain, $msgid);
}
