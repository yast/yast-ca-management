#! /usr/bin/perl -w

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

use strict;
use YaPI::CaManagement;
use Data::Dumper;

my $CAM_ROOT = '/var/lib/YaST2/CAM';
my $pwd = $ENV{'PWD'};
print "$pwd\n";
exit 1 if (!defined $pwd || $pwd eq "");

init_testsetup();
T01_Interface();
T02_Version();
T03_Capabilities();
T04_AddRootCA();
T05_AddRootCA2();
T06_ReadCAList();
T07_ReadCertificateDefaults();
T08_ReadCertificateDefaults2();
T09_ReadCA();
T10_AddRequest();
T11_issueCertificate();
T12_AddCertificate();
T13_AddCertificate2();
T14_ReadCertificateList();
T15_ReadCertificate();
T16_RevokeCertificate();
T17_AddCRL();
T18_ReadCRL();
T19_ExportCA();
T20_ExportCertificate();
T21_ExportCRL();
T22_Verify();
T23_AddSubCA();
#24_ExportCAToLDAP();
#25_ExportCRLToLDAP();
T26_UpdateDB();
T27_CreateManyCerts();
T28_ListManyCerts();
T29_WriteCertificateDefaults();
#30_ReadLDAPExportDefaults();
#31_ReadLDAPExportDefaults2();
#32_InitLDAPcaManagement();
#33_ExportCertificateToLDAP();
T34_DeleteCertificate();

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
    exit 1;
}


sub init_testsetup {

    if( -d "/$pwd/testout") {
        system("rm -r /$pwd/testout");
    }
    mkdir("/$pwd/testout", 0755);
    open(STDERR, ">> /$pwd/testout/YaST2-CaManagement-fulltest-OUTPUT.log");
#    open(STDOUT, ">> /$pwd/testout/YaST2-CaManagement-fulltest-OUT.log");

    if( -d "$CAM_ROOT/Test1_SuSE_CA") {
        system("rm -r /var/lib/YaST2/CAM/Test1_SuSE_CA");
        unlink("/var/lib/YaST2/CAM/.cas/Test1_SuSE_CA.pem");
        unlink("/var/lib/YaST2/CAM/.cas/crl_Test1_SuSE_CA.pem");
    }
    if( -d "$CAM_ROOT/Test2_SuSE_CA") {
        system("rm -r /var/lib/YaST2/CAM/Test2_SuSE_CA");
        unlink("/var/lib/YaST2/CAM/.cas/Test2_SuSE_CA.pem");
        unlink("/var/lib/YaST2/CAM/.cas/crl_Test2_SuSE_CA.pem");
    }
    if( -d "$CAM_ROOT/Test3_SuSE_CA") {
        system("rm -r /var/lib/YaST2/CAM/Test3_SuSE_CA");
        unlink("/var/lib/YaST2/CAM/.cas/Test3_SuSE_CA.pem");
        unlink("/var/lib/YaST2/CAM/.cas/crl_Test3_SuSE_CA.pem");
    }
    system("c_rehash /var/lib/YaST2/CAM/.cas/");
}


sub T01_Interface {

    print STDERR "------------------- T01_Interface ---------------------\n";
    print "------------------- T01_Interface ---------------------\n";
    my $res = YaPI::CaManagement->Interface();
    if( not defined $res ) {
        my $msg = YaPI::CaManagement->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump($res)."\n";
    }
}

sub T02_Version {
    print STDERR "------------------- T02_Version ---------------------\n";
    print "------------------- T02_Version ---------------------\n";
    my $res = YaPI::CaManagement->Version();
    if( not defined $res ) {
        my $msg = YaPI::CaManagement->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T03_Capabilities {
    print STDERR "------------------- T03_Capabilities ---------------------\n";
    print "------------------- T03_Capabilities ---------------------\n";
    foreach my $cap ("SLES9", "USER") {
        my $res = YaPI::CaManagement->Supports($cap);
          if( not defined $res ) {
              my $msg = YaPI::CaManagement->Error();
              printError($msg);
          } else {
              print "OK: test CAP = $cap\n";
              print STDERR Data::Dumper->Dump([$res])."\n";
          }
    }
}

sub T04_AddRootCA {
    print STDERR "------------------- T04_AddRootCA ---------------------\n";
    print "------------------- T04_AddRootCA ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'keyPasswd'             => 'system',
                'commonName'            => 'Test1_SuSE CA',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '3650',
                'countryName'           => 'DE',
                'localityName'          => 'Nuernberg',
                'organizationName'      => 'My GmbH',
                'basicConstraints'      => 'critical, CA:true',
                'crlDistributionPoints' => 'URI:http://my.linux.tux/',
               };
    my $res = YaPI::CaManagement->AddRootCA($data);
    if( not defined $res ) {
        my $msg = YaPI::CaManagement->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T05_AddRootCA2 {
    print STDERR "------------------- T05_AddRootCA2 ---------------------\n";
    print "------------------- T05_AddRootCA2 ---------------------\n";
    my $data = {
                'caName'                => 'Test2_SuSE_CA',
                'keyPasswd'             => 'system',
                'commonName'            => 'Test2_SuSE CA',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '3650',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux Tux GmbH',
                'challengePassword'     => 'tralla',
                'unstructuredName'      => 'My unstructured Name',
                'basicConstraints'      => 'critical, CA:TRUE',
                'nsComment'             => '"Heide Witzka, Herr Kapitaen"',
                'nsCertType'            => 'sslCA, emailCA',
                'keyUsage'              => 'cRLSign, keyCertSign',
                'subjectKeyIdentifier'  => 'critical, hash',
                'authorityKeyIdentifier' => 'issuer, keyid',
                'subjectAltName'        => 'email:me@linux.tux, URI:http://www.linux.tux/, DNS:tait.linux.tux, RID:1.2.3.4, IP:10.10.0.161',
                'issuerAltName'         => 'email:iss@linux.tux, URI:http://www.linux.tux/, DNS:hermes.linux.tux, RID:1.7.9.1.1.4.5.7.1, IP:10.10.0.8',
                'nsBaseUrl'             => 'http://www.linux.tux/',
                'nsRevocationUrl'       => 'http://www.linux.tux/',
                'nsCaRevocationUrl'     => 'http://www.linux.tux/',
                'nsRenewalUrl'          => 'http://www.linux.tux/',
                'nsCaPolicyUrl'         => 'http://www.linux.tux/',
                'extendedKeyUsage'      => 'emailProtection, msSGC, nsSGC',
                'authorityInfoAccess'   => 'OCSP;URI:http://ocsp.my.host/',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/cn=Test2_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de",
               };
    my $res = YaPI::CaManagement->AddRootCA($data);
    if( not defined $res ) {
        my $msg = YaPI::CaManagement->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T06_ReadCAList {
    print STDERR "------------------- T06_ReadCAList ---------------------\n";
    print "------------------- T06_ReadCAList ---------------------\n";
    my $res = YaPI::CaManagement->ReadCAList();
    if( not defined $res ) {
        my $msg = YaPI::CaManagement->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T07_ReadCertificateDefaults {
    print STDERR "------------------- T07_ReadCertificateDefaults ---------------------\n";
    print "------------------- T07_ReadCertificateDefaults ---------------------\n";
    foreach my $certType ("ca", "client", "server") {
        my $data = {
                    'caName'    => 'Test1_SuSE_CA',
                    'certType'  => $certType
                   };
      
        my $res = YaPI::CaManagement->ReadCertificateDefaults($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: certType = $certType\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T08_ReadCertificateDefaults2 {
    print STDERR "------------------- T08_ReadCertificateDefaults2 ---------------------\n";
    print "------------------- T08_ReadCertificateDefaults2 ---------------------\n";
    my $data = {
                'certType'  => 'ca'
               };

    my $res = YaPI::CaManagement->ReadCertificateDefaults($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T09_ReadCA {
    print STDERR "------------------- T09_ReadCA ---------------------\n";
    print "------------------- T09_ReadCA ---------------------\n";
    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => 'Test2_SuSE_CA',
                    'type'   => $type
                   };
        
        my $res = YaPI::CaManagement->ReadCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: type = $type\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T10_AddRequest {
    print STDERR "------------------- T10_AddRequest ---------------------\n";
    print "------------------- T10_AddRequest ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'keyPasswd'             => 'system',
                'commonName'            => 'My Request5',
                'emailAddress'          => 'my2@tait.linux.tux',
                'keyLength'             => '2048',
                'days'                  => '365',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux, Inc.',
                'nsComment'             => '"My Comment"'
               };
    
    my $res = YaPI::CaManagement->AddRequest($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T11_issueCertificate {
    print STDERR "------------------- T11_issueCertificate ---------------------\n";
    print "------------------- T11_issueCertificate ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'request'               => '0763f25e2b3af9bd86f8afcf4bd0897b',
                'certType'              => 'client',
                'caPasswd'              => 'system',
                'days'                  => '365',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/cn=Test1_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de",
                'nsComment'             => '"Toller comment"',
               };
    
    my $res = YaPI::CaManagement->IssueCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T12_AddCertificate {
    print STDERR "------------------- T12_AddCertificate ---------------------\n";
    print "------------------- T12_AddCertificate ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'certType'              => 'server',
                'keyPasswd'             => 'system',
                'caPasswd'              => 'system',
                'commonName'            => 'donar.linux.tux',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '365',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux Tux GmbH',
                'days'                  => '365',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/cn=Test1_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de",
               };
    
    my $res = YaPI::CaManagement->AddCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T13_AddCertificate2 {
    print STDERR "------------------- T13_AddCertificate2 ---------------------\n";
    print "------------------- T13_AddCertificate2 ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'certType'              => 'client',
                'keyPasswd'             => 'system',
                'caPasswd'              => 'system',
                'commonName'            => 'Michael Calmer',
                'emailAddress'          => 'mc@suse.de',
                'keyLength'             => '2048',
                'days'                  => '365',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux Tux GmbH',
                'challengePassword'     => 'tralla',
                'unstructuredName'      => 'My unstructured Name',
                'basicConstraints'      => 'critical, CA:FALSE',
                'nsComment'             => '"Heide Witzka, Herr Kapitaen"',
                'nsCertType'            => 'client, email',
                'keyUsage'              => 'digitalSignature, keyEncipherment',
                'subjectKeyIdentifier'  => 'critical, hash',
                'authorityKeyIdentifier'=> 'issuer, keyid',
                'subjectAltName'        => 'email:me@linux.tux, URI:http://www.linux.tux/, DNS:tait.linux.tux, RID:1.2.3.4, IP:10.10.0.161',
                'issuerAltName'         => 'email:iss@linux.tux, URI:http://www.linux.tux/, DNS:hermes.linux.tux, RID:1.7.9.1.1.4.5.7.1, IP:10.10.0.8',
                'nsBaseUrl'             => 'http://www.linux.tux/',
                'nsRevocationUrl'       => 'http://www.linux.tux/',
                'nsCaRevocationUrl'     => 'http://www.linux.tux/',
                'nsRenewalUrl'          => 'http://www.linux.tux/',
                'nsCaPolicyUrl'         => 'http://www.linux.tux/',
                'extendedKeyUsage'      => 'emailProtection, msSGC, nsSGC',
                'authorityInfoAccess'   => 'OCSP;URI:http://ocsp.my.host/',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/cn=Test1_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de",
               };
    
    my $res = YaPI::CaManagement->AddCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T14_ReadCertificateList {
    print STDERR "------------------- T14_ReadCertificateList ---------------------\n";
    print "------------------- T14_ReadCertificateList ---------------------\n";
    my $data = {
                caName => 'Test1_SuSE_CA',
                caPasswd => "system"
               };

    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T15_ReadCertificate {
    print STDERR "------------------- T15_ReadCertificate ---------------------\n";
    print "------------------- T15_ReadCertificate ---------------------\n";
    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => 'Test1_SuSE_CA',
                    'type'   => $type,
                    'certificate' => '03:52324820ee92ebe512780bec85174c14'
                   };
       
        my $res = YaPI::CaManagement->ReadCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK:\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T16_RevokeCertificate {
    print STDERR "------------------- T16_RevokeCertificate ---------------------\n";
    print "------------------- T16_RevokeCertificate ---------------------\n";
    my $data = {
                'caName'      => 'Test1_SuSE_CA',
                'caPasswd'    => 'system',
                'certificate' => '01:0763f25e2b3af9bd86f8afcf4bd0897b'
               };
    
    my $res = YaPI::CaManagement->RevokeCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T17_AddCRL {
    print STDERR "------------------- T17_AddCRL ---------------------\n";
    print "------------------- T17_AddCRL ---------------------\n";
    my $data = {
                'caName'      => 'Test1_SuSE_CA',
                'caPasswd'    => 'system',
                'days'        => 8
               };
   
    my $res = YaPI::CaManagement->AddCRL($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T18_ReadCRL {
    print STDERR "------------------- T18_ReadCRL ---------------------\n";
    print "------------------- T18_ReadCRL ---------------------\n";
    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => 'Test1_SuSE_CA',
                    'type'   => $type,
                   };
        
        my $res = YaPI::CaManagement->ReadCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: type = $type\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T19_ExportCA {
    print STDERR "------------------- T19_ExportCA ---------------------\n";
    print "------------------- T19_ExportCA ---------------------\n";
    foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12", "PKCS12_CHAIN") {
        my $data = {
                    'caName' => 'Test1_SuSE_CA',
                    'exportFormat' => $ef,
                    'caPasswd' => "system",
                   };
        if($ef =~ /^PKCS12/) {
            $data->{'P12Password'} = "tralla";
        }
    
        my $res = YaPI::CaManagement->ExportCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: $ef\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
        $data->{'destinationFile'} = "/$pwd/testout/CA_$ef";
        $res = YaPI::CaManagement->ExportCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: file export $ef\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T20_ExportCertificate {
    print STDERR "------------------- T20_ExportCertificate ---------------------\n";
    print "------------------- T20_ExportCertificate ---------------------\n";
    foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12", "PKCS12_CHAIN") {
        my $data = {
                    'caName' => 'Test1_SuSE_CA',
                    'certificate' => '03:52324820ee92ebe512780bec85174c14',
                    'exportFormat' => $ef,
                    'keyPasswd' => "system",
                   };
        if($ef =~ /^PKCS12/) {
            $data->{'P12Password'} = "tralla";
        }
    
        my $res = YaPI::CaManagement->ExportCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: $ef\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
        $data->{'destinationFile'} = "/$pwd/testout/CRT_$ef";
        $res = YaPI::CaManagement->ExportCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: file export $ef\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T21_ExportCRL {
    print STDERR "------------------- T21_ExportCRL ---------------------\n";
    print "------------------- T21_ExportCRL ---------------------\n";
    foreach my $ef ("PEM", "DER") {
        my $data = {
                    'caName' => 'Test1_SuSE_CA',
                    'exportFormat' => $ef,
                   };
    
        my $res = YaPI::CaManagement->ExportCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: $ef\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
        $data->{'destinationFile'} = "/$pwd/testout/CRL_$ef";
        $res = YaPI::CaManagement->ExportCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: file export $ef\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T22_Verify {
    print STDERR "------------------- T22_Verify ---------------------\n";
    print "------------------- T22_Verify ---------------------\n";
    my $data = {
                caName => 'Test1_SuSE_CA',
                caPasswd => "system"
               };
    
    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        foreach my $cert (@$res) {
            $data = {
                     caName => 'Test1_SuSE_CA', 
                     certificate => $cert->{'certificate'} 
                    };

            my $Vret = YaPI::CaManagement->Verify($data);
            if(not defined $Vret) {
                my $err = YaPI::CaManagement->Error();
                if( $cert->{'certificate'} ne "01:0763f25e2b3af9bd86f8afcf4bd0897b") {
                    printError($err);
                } else {
                    print "Verify: false positive ".$err->{description}."\n";
                }
            } else {
                print "OK: ".$cert->{'certificate'}." == $Vret\n";
            }
        }
    }
}

sub T23_AddSubCA {
    print STDERR "------------------- T23_AddSubCA ---------------------\n";
    print "------------------- T23_AddSubCA ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'newCaName'             => 'Test3_SuSE_CA',
                'keyPasswd'             => 'tralla',
                'caPasswd'              => 'system',
                'commonName'            => 'My CA New Sub CA',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '3600',
                'countryName'           => 'DE',
                'localityName'          => 'Nuernberg',
                'organizationName'      => 'My GmbH',
                'basicConstraints'      => 'CA:TRUE, pathlen:2',
                'crlDistributionPoints' => 'URI:http://my.linux.tux/',
               };

    my $res = YaPI::CaManagement->AddSubCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T24_ExportCAToLDAP {

}

sub T25_ExportCRLToLDAP {

}

sub T26_UpdateDB {
    print STDERR "------------------- T26_UpdateDB ---------------------\n";
    print "------------------- T26_UpdateDB ---------------------\n";
    foreach my $pass ( "system", "false" ) {
        my $data = {
                    caName => 'Test1_SuSE_CA',
                    caPasswd => $pass
                   };
        
        my $res = YaPI::CaManagement->UpdateDB($data);
        if( not defined $res ) {
            if($pass eq "false") {
                print "OK: error with wrong password\n";
            } else {
                print STDERR "Fehler\n";
                my $err = YaPI::CaManagement->Error();
                printError($err);
            }
        } else {
            if($pass eq "system") {
                print "OK\n";
            } else {
                print STDERR "Fehler\n";
                my $err = YaPI::CaManagement->Error();
                printError($err);
            }
        }
    }
}

sub T27_CreateManyCerts {
    print STDERR "------------------- T27_CreateManyCerts ---------------------\n";
    print "------------------- T27_CreateManyCerts ---------------------\n";
    for(my $i = 0; $i < 200; $i++) {
        
        my $data = {
                    'caName'                => 'Test2_SuSE_CA',
                    'certType'              => 'client', 
                    'keyPasswd'             => 'system',
                    'caPasswd'              => 'system',
                    'commonName'            => "My Request $i",
                    'emailAddress'          => 'my@linux.tux',
                    'keyLength'             => '1024',
                    'days'                  => '365', 
                    'countryName'           => 'DE',
                    'localityName'          => 'Nuremberg',
                    'stateOrProvinceName'   => 'Bavaria',
                    'organizationalUnitName'=> 'IT Abteilung',
                    'organizationName'      => 'My Linux Tux GmbH',
                    'days'                  => '365',
                   };
        
        my $res = YaPI::CaManagement->AddCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: $i\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T28_ListManyCerts {
    print STDERR "------------------- T28_ListManyCerts ---------------------\n";
    print "------------------- T28_ListManyCerts ---------------------\n";
    use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
    my $start = [gettimeofday];   
    my $data = {
                caName => 'Test2_SuSE_CA',
                caPasswd => "system"
               };
    
    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: time=".tv_interval($start)."\n";
    }
}

sub T29_WriteCertificateDefaults {
    print STDERR "------------------- T29_WriteCertificateDefaults ---------------------\n";
    print "------------------- T29_WriteCertificateDefaults ---------------------\n";
    my $data = {
                'caName'                => 'Test3_SuSE_CA',
                'certType'              => 'server',
                'basicConstraints'      => 'critical, CA:FALSE',
                'nsComment'             => '"SuSE Certificate"',
                'crlDistributionPoints' => 'URI:http://www.suse.de/CA/crl.pem',
               };
    
    my $res = YaPI::CaManagement->WriteCertificateDefaults($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T30_ReadLDAPExportDefaults {

}

sub T31_ReadLDAPExportDefaults2 {

}

sub T32_InitLDAPcaManagement {

}

sub T33_ExportCertificateToLDAP {

}

sub T34_DeleteCertificate {
    print STDERR "------------------- T34_DeleteCertificate ---------------------\n";
    print "------------------- T34_DeleteCertificate ---------------------\n";
    my $data = {
                caName        => 'Test1_SuSE_CA',
                certificate   => '01:0763f25e2b3af9bd86f8afcf4bd0897b',
                caPasswd      => 'system'
               };
    
    my $res = YaPI::CaManagement->DeleteCertificate($data);
    if( not defined $res ) {
        # error
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    $data->{certificate} = "04:31c25358eb2e3e5c44f3ed307023fd06";
    $res = YaPI::CaManagement->DeleteCertificate($data);
    if( not defined $res ) {
        # error
        print "OK: false positive\n";
        my $err = YaPI::CaManagement->Error();
        print STDERR $err->{summary}."\n".$err->{description}."\n";
    } else {
        print STDERR "Fehler\n";
        exit 1;
    }

}

