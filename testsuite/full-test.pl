#! /usr/bin/perl -w

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
    if ( defined $ENV{RPM_BUILD_ROOT} && 
         -d $ENV{RPM_BUILD_ROOT}.'/usr/share/YaST2/modules/' )
    {
	push @INC, $ENV{RPM_BUILD_ROOT}.'/usr/share/YaST2/modules/';
    }
}

use strict;
use YaPI::CaManagement;
use Data::Dumper;

my $CAM_ROOT = '/var/lib/CAM';
my $pwd = $ENV{'PWD'};
print "$pwd\n";
exit 1 if (!defined $pwd || $pwd eq "");

my $req1 = "";
my $req3 = "";
my $req4 = "";
my $crt1 = "";
my $crt2 = "";
my $crt3 = "";
my %rev = ();

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

T42_RevokeManyCertificate();
T43_AddCRL3();
T44_ReadCRL3();

T29_WriteCertificateDefaults();
#30_ReadLDAPExportDefaults();
#31_ReadLDAPExportDefaults2();
#32_InitLDAPcaManagement();
#33_ExportCertificateToLDAP();
T34_DeleteCertificate();

T35_ImportCommonServerCertificate();

T36_ReadFile();

T37_CheckCA1();
T38_CheckCA2();
T39_CheckCertificate1();
T40_CheckCertificate2();
T41_CheckCRL1();
T45_CheckCRL3();

T46_ReadRequest();
T47_ReadRequestList();
T48_ImportRequest();
T49_DeleteRequest();

T50_ImportCA();

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
    exit 1;
}


sub init_testsetup {
    
    if($> != 0) {
        print "We are not 'root'. Exiting without performing test\n";
        exit 0;
    }
    
    if( -d "/$pwd/testout") {
        system("rm -r /$pwd/testout");
    }
    mkdir("/$pwd/testout", 0755);
    open(STDERR, ">> /$pwd/testout/YaST2-CaManagement-fulltest-OUTPUT.log");
#    open(STDOUT, ">> /$pwd/testout/YaST2-CaManagement-fulltest-OUT.log");

    if( -d "$CAM_ROOT/Test1_SuSE_CA") {
        system("rm -r /var/lib/CAM/Test1_SuSE_CA");
        unlink("/var/lib/CAM/.cas/Test1_SuSE_CA.pem");
        unlink("/var/lib/CAM/.cas/crl_Test1_SuSE_CA.pem");
    }
    if( -d "$CAM_ROOT/Test2_SuSE_CA") {
        system("rm -r /var/lib/CAM/Test2_SuSE_CA");
        unlink("/var/lib/CAM/.cas/Test2_SuSE_CA.pem");
        unlink("/var/lib/CAM/.cas/crl_Test2_SuSE_CA.pem");
    }
    if( -d "$CAM_ROOT/Test3_SuSE_CA") {
        system("rm -r /var/lib/CAM/Test3_SuSE_CA");
        unlink("/var/lib/CAM/.cas/Test3_SuSE_CA.pem");
        unlink("/var/lib/CAM/.cas/crl_Test3_SuSE_CA.pem");
    }
    if( -d "$CAM_ROOT/Test4_SuSE_CA") {
        system("rm -r /var/lib/CAM/Test4_SuSE_CA");
        unlink("/var/lib/CAM/.cas/Test4_SuSE_CA.pem");
        unlink("/var/lib/CAM/.cas/crl_Test4_SuSE_CA.pem");
    }
    system("c_rehash /var/lib/CAM/.cas/");
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
                'subjectKeyIdentifier'  => 'hash',
                'authorityKeyIdentifier'=> 'keyid:always,issuer:always',
                'subjectAltName'        => 'email:copy',
                'issuerAltName'         => 'issuer:copy',
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
                'organizationName'      => 'My Linux, Inc.'
               };
    
    my $res = YaPI::CaManagement->AddRequest($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
        $req1 = $res;
    }
}

sub T11_issueCertificate {
    print STDERR "------------------- T11_issueCertificate ---------------------\n";
    print "------------------- T11_issueCertificate ---------------------\n";
    my $data = {
                'caName'                => 'Test1_SuSE_CA',
                'request'               => $req1,
                'certType'              => 'client',
                'caPasswd'              => 'system',
                'days'                  => '365',
                'subjectKeyIdentifier'  => 'hash',
                'authorityKeyIdentifier'=> 'keyid:always,issuer:always',
                'subjectAltName'        => 'email:copy',
                'issuerAltName'         => 'issuer:copy',
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
        $crt1 = $res;
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
                'subjectKeyIdentifier'  => 'hash',
                'authorityKeyIdentifier'=> 'keyid:always,issuer:always',
                'subjectAltName'        => 'email:copy',
                'issuerAltName'         => 'issuer:copy',
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
        $crt2 = $res;
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
        $crt3 = $res;
    }

    if($crt3 =~ /^[[:xdigit:]]+:([[:xdigit:]]+[\d-]*)$/) {
        $req3 = $1
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
                    'certificate' => $crt3
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
                'certificate' => $crt1
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
                    'certificate' => $crt3,
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
                if( $cert->{'certificate'} ne $crt1) {
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

        if($res =~ /^11:/) {
            $rev{$res} = "unspecified";
        }
        if($res =~ /^1D:/) {
            $rev{$res} = "keyCompromise";
        }
        if($res =~ /^26:/) {
            $rev{$res} = "CACompromise";
        }
        if($res =~ /^2B:/) {
            $rev{$res} = "affiliationChanged";
        }
        if($res =~ /^A1:/) {
            $rev{$res} = "superseded";
        }
        if($res =~ /^B2:/) {
            $rev{$res} = "cessationOfOperation";
        }
        if($res =~ /^BA:/) {
            $rev{$res} = "certificateHold";
        }
        if($res =~ /^C1:/) {
            $rev{$res} = undef;
        }
        if($res =~ /^C5:/) {
            $rev{$res} = undef;
        }
        if($res =~ /^C8:/) {
            $rev{$res} = undef;
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
                certificate   => $crt1,
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

sub T35_ImportCommonServerCertificate {
    print STDERR "------------------- T35_ImportCommonServerCertificate ---------------------\n";
    print "------------------- T35_ImportCommonServerCertificate ---------------------\n";
    my $data = {
                inFile        => "/$pwd/testout/CRT_PKCS12_CHAIN",
                passwd        => 'tralla'
               };
    
    my $res = YaPI::CaManagement->ImportCommonServerCertificate($data);
    if( not defined $res ) {
        # error
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

}

sub T36_ReadFile {
    print STDERR "------------------- T36_ReadFile ---------------------\n";
    print "------------------- T36_ReadFile ---------------------\n";
    foreach my $type ( "parsed", "plain" ) {
        my $data = {
                    datatype      => "CERTIFICATE",
                    inFile        => '/var/lib/CAM/Test1_SuSE_CA/certs/01.pem',
                    inForm        => 'PEM',
                    type          => $type
                   };
        
        my $res = YaPI::CaManagement->ReadFile($data);
        if( not defined $res ) {
            # error
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: $type\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }

    foreach my $type ( "parsed", "plain" ) {
        my $data = {
                    datatype      => "CRL",
                    inFile        => '/var/lib/CAM/Test1_SuSE_CA/crl/crl.pem',
                    inForm        => 'PEM',
                    type          => $type
                   };
        
        my $res = YaPI::CaManagement->ReadFile($data);
        if( not defined $res ) {
            # error
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print "OK: $type\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T37_CheckCA1 {
    print STDERR "------------------- T37_CheckCA1 ---------------------\n";
    print "------------------- T37_CheckCA1 ---------------------\n";

    my $data = {
                'caName' => 'Test1_SuSE_CA',
                'type'   => "plain"
               };
    
    my $res = YaPI::CaManagement->ReadCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        my $ref = 
'Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: emailAddress=my@linux.tux,CN=Test1_SuSE CA,O=My GmbH,L=Nuernberg,C=DE
        Validity
            Not Before: Apr 27 08:56:21 2004 GMT
            Not After : Apr 25 08:56:21 2014 GMT
        Subject: emailAddress=my@linux.tux,CN=Test1_SuSE CA,O=My GmbH,L=Nuernberg,C=DE
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:c6:aa:2d:1b:5a:5f:3b:98:20:c0:de:ef:3e:a7:
                    b4:af:06:da:5f:d5:f2:45:44:3d:84:d8:27:e5:e9:
                    59:68:cb:18:22:63:94:47:90:37:81:2c:1c:03:32:
                    93:62:6a:a7:af:14:86:b0:e6:4f:09:fd:b0:95:2d:
                    6d:67:aa:f5:37:de:8b:99:58:15:ca:56:5e:7a:50:
                    1b:6c:99:ba:39:80:61:4e:0e:1a:04:06:25:33:fc:
                    4f:c8:b1:3b:97:dd:ae:37:c6:0d:aa:f6:72:1f:67:
                    09:0c:4a:24:71:80:36:ee:6f:16:ac:a7:69:95:9d:
                    49:e3:23:3b:1f:05:20:af:ac:47:55:0b:ef:4d:fd:
                    a3:a0:33:d8:84:6d:e3:ec:76:73:4e:48:1f:37:75:
                    2f:3e:ac:8e:96:5b:08:50:ac:29:83:14:d8:aa:60:
                    07:99:4d:4b:05:04:88:18:b0:d6:61:a6:83:d5:09:
                    90:a3:da:5d:5e:06:7a:97:08:3f:82:75:35:42:df:
                    45:b7:b8:46:a0:f7:d1:31:e8:f0:ca:5b:8b:f8:e1:
                    0d:68:1b:87:dc:99:ef:87:f9:f1:7b:e8:d1:35:00:
                    dc:b0:ce:96:55:d9:b7:b9:7a:0c:09:fb:07:4f:0d:
                    45:32:5d:ff:df:c5:1b:cf:b3:ab:5a:27:f4:b2:9a:
                    31:63
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                CD:41:49:CB:55:22:ED:E3:38:E1:14:83:0D:C8:8A:36:CA:6B:10:DA
            X509v3 Authority Key Identifier:
                keyid:CD:41:49:CB:55:22:ED:E3:38:E1:14:83:0D:C8:8A:36:CA:6B:10:DA
                DirName:/C=DE/L=Nuernberg/O=My GmbH/CN=Test1_SuSE CA/emailAddress=my@linux.tux
                serial:00

            X509v3 Subject Alternative Name:
                email:my@linux.tux
            X509v3 Issuer Alternative Name:
                email:my@linux.tux
            X509v3 CRL Distribution Points:
                URI:http://my.linux.tux/

    Signature Algorithm: sha1WithRSAEncryption
        7b:51:18:16:ac:1c:c7:de:06:76:91:4b:12:76:ac:ca:30:df:
        14:ed:c7:e0:45:ef:6b:2a:17:fd:80:91:f4:69:e3:20:f9:17:
        cb:29:2b:be:c8:38:71:05:d0:0b:70:e9:97:7a:2d:fd:f4:0a:
        f9:19:ce:e1:62:57:1f:b9:66:cd:d7:df:43:d6:7d:ea:ef:2b:
        8e:bc:d5:cc:4c:eb:ff:3a:35:bf:bf:2c:b6:a5:ee:05:0f:f9:
        be:5a:46:5c:ba:44:7d:ba:bf:5e:3c:8a:57:c6:54:4d:82:6d:
        3e:93:eb:84:ea:38:8e:55:01:31:1e:5f:26:86:7c:6c:d3:3a:
        d6:30:ea:c0:d8:b5:cf:79:bc:ff:96:2f:67:40:b1:28:3f:fa:
        9f:93:c3:b4:20:10:d8:91:c7:68:fa:17:a0:a4:29:f3:5c:f9:
        60:28:9f:4b:37:dd:ac:c0:7d:fb:97:8b:51:e5:93:61:04:33:
        ca:88:7c:f5:86:63:90:0c:cd:e9:94:33:92:44:7d:92:54:b4:
        38:13:b3:99:44:f3:e4:ec:ac:e4:8c:f7:47:5f:3e:31:c0:da:
        5f:b8:a7:82:eb:ed:00:3e:67:12:63:51:9a:ad:76:b1:fa:ea:
        28:5f:a8:57:bf:6b:18:20:70:d6:b7:90:0c:14:6c:21:6e:b3:
        8c:f8:1c:ce
';

        my $err = __checkCerts($res, $ref);
    
        if($err == 0) {
            print "OK\n";
        } else {
            print "ERROR\n";
        }
    }
}

sub T38_CheckCA2 {
    print STDERR "------------------- T38_CheckCA2 ---------------------\n";
    print "------------------- T38_CheckCA2 ---------------------\n";
    
    my $data = {
                'caName' => 'Test2_SuSE_CA',
                'type'   => "plain"
               };
    
    my $res = YaPI::CaManagement->ReadCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        my $ref = 
'Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: emailAddress=my@linux.tux,CN=Test2_SuSE CA,OU=IT Abteilung,O=My Linux Tux GmbH,L=Nuremberg,ST=Bavaria,C=DE
        Validity
            Not Before: Apr 27 09:36:17 2004 GMT
            Not After : Apr 25 09:36:17 2014 GMT
        Subject: emailAddress=my@linux.tux,CN=Test2_SuSE CA,OU=IT Abteilung,O=My Linux Tux GmbH,L=Nuremberg,ST=Bavaria,C=DE
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d3:4e:07:c4:92:0b:15:03:a3:1a:56:91:6d:fd:
                    8f:d1:d7:72:a8:93:a1:b5:f7:26:94:89:69:64:40:
                    6a:ac:70:09:1f:ac:3d:57:15:2e:b9:b8:59:c7:74:
                    b4:94:02:a3:a3:11:17:09:dc:a9:36:73:10:74:d6:
                    ab:fb:9f:a6:e7:2e:8e:fa:f5:95:8c:28:72:75:ff:
                    c0:1a:72:da:63:fc:e7:f4:f1:21:ec:81:54:50:0c:
                    4d:a7:97:d4:cc:1b:32:45:73:2b:b1:4d:22:95:68:
                    f4:e1:41:72:27:b1:f6:30:59:de:02:d1:2d:c3:a7:
                    b7:64:8f:42:55:2b:cb:68:48:94:75:43:a2:18:94:
                    6d:94:b8:ce:89:6c:8e:21:9b:c7:18:4f:ae:76:f0:
                    5b:8c:7b:30:cf:22:6d:f1:40:e8:cc:0f:88:a3:2f:
                    4d:da:71:1a:92:2b:80:61:0e:ac:97:30:2d:80:06:
                    a6:7a:12:fc:af:de:a7:cd:ee:79:aa:9c:d4:62:29:
                    95:94:aa:74:b2:60:28:ed:e0:0a:41:69:6d:82:1a:
                    ed:a7:50:76:fb:fc:f1:80:98:bd:07:e4:02:7f:6f:
                    67:54:45:ac:8f:3a:0f:f0:08:2d:ea:ad:67:fc:ae:
                    ee:61:34:27:04:bd:dd:a5:20:62:36:ad:57:14:30:
                    26:bb
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            Netscape Comment:
                Heide Witzka, Herr Kapitaen
            Netscape Cert Type:
                SSL CA, S/MIME CA
            X509v3 Key Usage:
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: critical
                C6:6E:BB:48:7D:60:C5:A7:B1:05:01:E9:EC:47:CA:D4:9B:2D:E0:B1
            X509v3 Authority Key Identifier:
                keyid:C6:6E:BB:48:7D:60:C5:A7:B1:05:01:E9:EC:47:CA:D4:9B:2D:E0:B1

            X509v3 Subject Alternative Name:
                email:me@linux.tux, URI:http://www.linux.tux/, DNS:tait.linux.tux, Registered ID:1.2.3.4, IP Address:10.10.0.161
            X509v3 Issuer Alternative Name:
                email:iss@linux.tux, URI:http://www.linux.tux/, DNS:hermes.linux.tux, Registered ID:1.7.9.1.1.4.5.7.1, IP Address:10.10.0.8
            Netscape CA Revocation Url:
                http://www.linux.tux/
            Netscape Revocation Url:
                http://www.linux.tux/
            X509v3 Extended Key Usage:
                E-mail Protection, Microsoft Server Gated Crypto, Netscape Server Gated Crypto
            X509v3 CRL Distribution Points:
                URI:ldap://my.linux.tux/cn=Test2_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de

            Netscape Base Url:
                http://www.linux.tux/
            Netscape CA Policy Url:
                http://www.linux.tux/
            Authority Information Access:
                OCSP - URI:http://ocsp.my.host/

            Netscape Renewal Url:
                http://www.linux.tux/
    Signature Algorithm: sha1WithRSAEncryption
        8b:fd:b6:73:d1:2e:12:20:e9:54:89:1d:47:94:11:2b:82:44:
        45:87:41:a3:f3:dc:3b:35:f5:e3:b9:a5:e4:84:b3:43:5d:fc:
        23:4b:ec:ae:9f:c7:b6:32:49:fe:c6:8c:80:30:7e:13:03:29:
        8f:f1:a9:89:ad:5a:04:01:2c:64:6c:f1:6b:a9:7c:0f:94:90:
        93:7f:5d:04:67:59:72:76:c5:31:dc:15:0c:36:ff:0b:67:fa:
        a9:3d:99:49:7d:1e:f0:91:63:28:02:ca:c1:98:3e:68:5d:bd:
        7b:e1:43:92:09:d3:ae:f6:9e:f0:19:4a:06:4d:cd:fc:0d:91:
        11:ce:17:09:24:0e:4f:b9:76:98:26:ab:ee:44:53:cd:49:82:
        f6:5b:e4:a4:e6:dd:71:a9:5f:f4:e0:49:6e:81:38:e3:8f:22:
        cc:c6:bb:dc:3b:6d:68:44:37:be:47:d3:6f:42:01:9b:74:1b:
        40:48:ea:40:24:3f:de:19:47:0e:04:dc:c3:8f:9d:fa:c1:15:
        c4:a5:9c:e8:40:71:0b:fd:fe:b4:61:e1:a6:59:72:16:a3:bb:
        49:e2:fa:ee:41:fe:3e:cf:79:04:21:7d:a6:ff:b7:31:59:34:
        d8:59:86:f7:08:13:cc:37:50:f0:6e:a0:ca:55:d7:76:10:c0:
        43:6a:9e:ef
';

        my $err = __checkCerts($res, $ref);
    
        if($err == 0) {
            print "OK\n";
        } else {
            print "ERROR\n";
        }
    }
}

sub T39_CheckCertificate1 {
    print STDERR "------------------- T39_CheckCertificate1 ---------------------\n";
    print "------------------- T39_CheckCertificate1 ---------------------\n";
    
    my $data = {
                'caName' => 'Test1_SuSE_CA',
                'type'   => "plain",
                'certificate' => $crt2
               };
    
    my $res = YaPI::CaManagement->ReadCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        my $ref = 
'Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: emailAddress=my@linux.tux,CN=Test1_SuSE CA,O=My GmbH,L=Nuernberg,C=DE
        Validity
            Not Before: Apr 27 09:59:23 2004 GMT
            Not After : Apr 27 09:59:23 2005 GMT
        Subject: emailAddress=my@linux.tux,CN=donar.linux.tux,OU=IT Abteilung,O=My Linux Tux GmbH,L=Nuremberg,ST=Bavaria,C=DE
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:d6:b6:5e:82:7d:8f:81:82:34:26:06:12:7c:2c:
                    64:b9:ff:88:4a:a6:86:1c:72:45:79:3a:01:f4:74:
                    32:6d:7b:54:a1:97:80:e8:62:f2:5a:3e:b1:56:eb:
                    f2:a1:34:86:6e:45:d7:10:06:07:f1:20:1f:2e:d7:
                    fd:72:45:1f:3a:4b:14:d5:66:09:90:81:5a:53:e4:
                    92:ab:b8:97:6a:40:fd:3d:a1:df:85:82:d0:f2:d6:
                    b7:9c:39:74:ba:33:76:e6:c5:21:a0:96:dc:f1:00:
                    f9:43:68:28:9a:c6:2a:64:27:14:4e:82:63:6b:25:
                    2a:56:51:7c:14:19:d4:2f:82:7b:95:6d:e9:50:6b:
                    2b:d7:fd:62:f6:3f:de:f7:8f:63:41:d4:1f:e4:b8:
                    17:1e:82:69:eb:65:4f:52:b1:02:01:3f:39:9e:be:
                    2d:0c:b1:ac:a8:c6:95:93:d2:31:bb:05:c9:b8:d8:
                    8b:1a:d7:4b:30:a9:a7:ad:f3:5d:6c:84:5c:7f:43:
                    95:87:e4:38:55:05:13:ba:19:61:c1:3e:cc:b7:ea:
                    97:75:de:41:b9:c7:cc:75:a6:ef:ea:a5:0f:a1:bb:
                    22:e8:40:48:d8:c2:2c:50:77:7d:49:81:c9:18:60:
                    47:f0:e3:b8:10:cb:48:74:6f:76:22:fd:4b:9f:18:
                    f8:63
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                A9:04:DB:D8:C3:EC:F4:D3:0F:7C:0D:16:26:0A:3C:83:A0:07:57:6B
            X509v3 Authority Key Identifier:
                keyid:A8:21:7D:03:42:FD:BB:EF:94:FA:99:24:D6:38:0D:11:11:E1:38:AD
                DirName:/C=DE/L=Nuernberg/O=My GmbH/CN=Test1_SuSE CA/emailAddress=my@linux.tux
                serial:00

            X509v3 Subject Alternative Name:
                email:my@linux.tux
            X509v3 Issuer Alternative Name:
                email:my@linux.tux
            X509v3 CRL Distribution Points:
                URI:ldap://my.linux.tux/cn=Test1_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de

    Signature Algorithm: sha1WithRSAEncryption
        89:74:60:74:41:12:09:d6:c4:9f:94:fe:da:00:c5:34:46:39:
        34:d0:45:2d:63:c2:a2:2a:72:80:a0:a9:d9:78:65:a6:80:ae:
        97:e2:2c:d7:38:24:4d:a6:3e:b6:9e:0f:7f:cb:b8:1a:1a:4a:
        6a:70:01:ce:ab:7f:a3:a6:d2:92:10:8e:1c:a1:8d:b4:50:83:
        9e:af:d7:42:d8:5c:c7:6d:aa:f8:d6:26:fe:17:e4:3c:ef:fc:
        ea:53:5a:35:3b:90:f6:bc:a6:1a:e2:07:57:be:f3:6e:9f:5f:
        86:ea:72:40:74:10:35:5c:3a:18:12:d8:03:27:50:1e:2e:55:
        10:4b:85:5a:83:4f:12:f5:2d:ae:f9:0a:c7:ca:4c:e5:28:ad:
        83:6b:f2:b4:20:c4:b6:df:87:c7:72:48:46:ab:cb:0d:8b:09:
        3c:ad:6a:be:bf:c3:17:6f:59:f0:6c:e9:50:44:fe:50:ad:4e:
        63:af:2e:2f:83:d1:b2:46:4d:87:de:46:fe:0f:16:16:f2:9e:
        03:bb:d8:d4:ea:8c:21:10:10:64:8c:5a:94:18:7f:48:29:7c:
        d6:b3:ca:e0:c7:67:02:07:3e:19:e2:3b:da:0c:e8:a6:eb:97:
        33:10:9e:64:2b:2f:d3:c6:c6:a3:b9:15:03:e5:d8:9b:87:ed:
        1b:1f:64:b5
';

        my $err = __checkCerts($res, $ref);
    
        if($err == 0) {
            print "OK\n";
        } else {
            print "ERROR\n";
        }
    }
}

sub T40_CheckCertificate2 {
    print STDERR "------------------- T40_CheckCertificate2 ---------------------\n";
    print "------------------- T40_CheckCertificate2 ---------------------\n";
    
    my $data = {
                'caName' => 'Test1_SuSE_CA',
                'type'   => "plain",
                'certificate' => $crt3
               };
    
    my $res = YaPI::CaManagement->ReadCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        my $ref = 
'Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 3 (0x3)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: emailAddress=my@linux.tux,CN=Test1_SuSE CA,O=My GmbH,L=Nuernberg,C=DE
        Validity
            Not Before: Apr 27 10:16:05 2004 GMT
            Not After : Apr 27 10:16:05 2005 GMT
        Subject: emailAddress=mc@suse.de,CN=Michael Calmer,OU=IT Abteilung,O=My Linux Tux GmbH,L=Nuremberg,ST=Bavaria,C=DE
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:a8:4d:9d:ff:86:46:3c:ab:2e:4d:97:0d:51:8e:
                    ed:c1:bf:8c:57:f6:7b:82:99:dd:0b:b2:68:bc:fb:
                    ac:c6:41:98:0b:98:38:70:f7:65:20:74:96:86:45:
                    ca:73:57:ee:0d:5b:36:c8:e9:b1:dc:84:6e:07:80:
                    85:4f:10:b6:c2:2e:8e:3e:34:ac:de:0a:a9:25:fe:
                    3a:92:ec:b9:41:a9:58:b6:e7:14:d9:fa:27:b8:0d:
                    11:13:97:41:db:fb:55:08:64:0f:5e:df:bd:2a:7a:
                    d9:47:34:21:3a:d2:ee:5e:aa:55:07:e0:5d:60:10:
                    5e:21:71:28:d9:bf:cb:86:93:76:a8:59:24:d9:97:
                    0d:f6:ae:77:1b:e7:dc:7c:ea:90:c2:ee:9e:ea:26:
                    79:f3:68:db:65:9b:ff:fc:99:cd:5f:64:e5:19:7d:
                    d0:90:dd:9f:a0:7e:f1:76:5b:b0:ec:f5:c4:22:f3:
                    b2:b9:c5:5f:a4:ae:39:9c:fc:59:42:e3:35:2a:6e:
                    24:a1:ba:5f:f7:39:1c:bc:12:98:be:29:0b:4e:69:
                    31:4f:de:0f:1a:fe:ca:fc:0f:88:4a:c2:66:b1:96:
                    b0:f6:de:ad:34:d9:a3:54:6f:a0:7e:67:ca:37:18:
                    06:45:2c:41:eb:bf:2f:f5:a5:00:44:63:10:81:db:
                    d5:b1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 CRL Distribution Points:
                URI:ldap://my.linux.tux/cn=Test1_SuSE_CA%2Cou=CA%2Cdc=suse%2Cdc=de

            X509v3 Basic Constraints: critical
                CA:FALSE
            Netscape Comment:
                Heide Witzka, Herr Kapitaen
            Netscape Cert Type:
                SSL Client, S/MIME
            X509v3 Key Usage:
                Digital Signature, Key Encipherment
            X509v3 Subject Key Identifier: critical
                ED:A1:47:69:67:BD:48:24:FF:86:CF:AF:E1:3E:45:5E:C9:AF:EF:8A
            X509v3 Authority Key Identifier:
                keyid:09:BA:5C:7C:4E:E2:CF:FE:3B:D1:1E:8D:36:87:92:5A:CE:97:68:04

            X509v3 Subject Alternative Name:
                email:me@linux.tux, URI:http://www.linux.tux/, DNS:tait.linux.tux, Registered ID:1.2.3.4, IP Address:10.10.0.161
            X509v3 Issuer Alternative Name:
                email:iss@linux.tux, URI:http://www.linux.tux/, DNS:hermes.linux.tux, Registered ID:1.7.9.1.1.4.5.7.1, IP Address:10.10.0.8
            Netscape CA Revocation Url:
                http://www.linux.tux/
            Netscape Revocation Url:
                http://www.linux.tux/
            X509v3 Extended Key Usage:
                E-mail Protection, Microsoft Server Gated Crypto, Netscape Server Gated Crypto
            Netscape Base Url:
                http://www.linux.tux/
            Netscape CA Policy Url:
                http://www.linux.tux/
            Authority Information Access:
                OCSP - URI:http://ocsp.my.host/

            Netscape Renewal Url:
                http://www.linux.tux/
    Signature Algorithm: sha1WithRSAEncryption
        b1:a4:8e:d7:1a:bf:be:83:2a:7b:94:57:b7:1e:56:9a:29:19:
        ea:9b:62:43:ae:33:72:1b:ce:48:1d:8e:88:62:56:ef:b4:73:
        8c:2e:a7:79:ab:b8:9a:23:e9:6f:82:d0:33:89:06:ac:ec:cd:
        90:ab:58:c8:7b:c5:74:f3:97:cd:03:b0:95:b4:70:10:18:c4:
        66:1d:d6:69:62:eb:9e:36:7f:5b:ce:aa:2b:79:59:01:ff:d5:
        a7:f6:f9:dc:35:64:6e:08:3b:cd:4c:8a:0b:c8:56:5d:81:ec:
        27:dd:5c:7f:80:37:88:1c:65:c6:c4:7d:f9:6b:5f:d9:a1:d2:
        41:e2:10:31:c1:c2:6f:35:9b:bf:ec:9b:ef:90:da:0b:c0:17:
        16:a5:2b:30:77:84:1f:dd:2f:ca:34:32:56:b1:ac:e3:df:29:
        16:8d:f7:60:83:a9:2f:e4:0a:0e:45:3f:b7:b0:ba:19:3d:05:
        d6:22:86:0b:bf:ff:be:73:35:92:ce:3a:c8:c5:5a:55:57:64:
        2a:67:e2:a1:66:83:5c:26:02:9f:88:e5:9a:7f:76:53:1c:7e:
        ae:f6:d4:62:14:52:16:b5:10:3f:3e:75:ab:97:a5:3b:ec:36:
        de:9f:a3:48:00:91:00:27:f2:94:b9:11:5d:7c:d1:eb:37:3b:
        02:53:a2:cc
';

        my $err = __checkCerts($res, $ref);
    
        if($err == 0) {
            print "OK\n";
        } else {
            print "ERROR\n";
        }
    }
}

sub T41_CheckCRL1 {
    print STDERR "------------------- T41_CheckCRL1 ---------------------\n";
    print "------------------- T41_CheckCRL1 ---------------------\n";
    my $data = {
                'caName' => 'Test1_SuSE_CA',
                'type'   => "plain",
               };
    
    my $res = YaPI::CaManagement->ReadCRL($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        my $ref = 
'Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: /C=DE/L=Nuernberg/O=My GmbH/CN=Test1_SuSE CA/emailAddress=my@linux.tux
        Last Update: Apr 27 10:20:26 2004 GMT
        Next Update: May  5 10:20:26 2004 GMT
        CRL extensions:
            X509v3 Authority Key Identifier:
                keyid:48:E8:76:57:5F:FE:08:62:D7:D8:33:83:DC:75:EE:9C:6D:AF:4C:9A
                DirName:/C=DE/L=Nuernberg/O=My GmbH/CN=Test1_SuSE CA/emailAddress=my@linux.tux
                serial:00

Revoked Certificates:
    Serial Number: 01
        Revocation Date: Apr 27 10:20:26 2004 GMT
    Signature Algorithm: sha1WithRSAEncryption
        86:76:55:8b:bb:c6:5f:47:1b:4d:ea:2e:47:f5:d1:ec:cd:36:
        22:d9:23:9f:f4:fe:75:09:c5:dd:3d:9b:d0:3d:8d:45:e4:32:
        b2:45:d4:9d:7b:69:8e:3e:b8:3c:3e:a5:6e:08:43:3e:52:00:
        0f:93:23:e4:0e:ec:cf:09:6b:df:87:dd:c4:71:16:0f:a4:26:
        ca:9d:c6:05:3e:61:e6:83:3e:3a:fd:03:21:e4:04:1e:62:57:
        c4:c6:7a:34:08:10:90:6c:de:39:88:ae:83:ee:ec:83:a9:67:
        72:22:e2:f7:27:fc:e0:f3:75:41:2e:e0:28:a9:d2:fd:8f:61:
        21:e2:d0:e2:c6:48:06:3d:27:e0:14:a5:43:9c:a1:a7:f2:c9:
        e7:27:91:8f:78:a4:21:ba:0e:67:00:64:cd:a5:52:dd:3f:19:
        fe:d4:e0:a3:ce:27:c2:2c:7f:22:d2:b7:a8:19:17:20:ae:6e:
        29:63:91:59:de:cf:80:8f:54:04:ae:40:bc:6a:c6:92:b0:8b:
        ca:68:a8:a9:89:31:54:8a:d0:ae:b3:a2:df:96:1f:bd:c1:8e:
        66:14:7f:b0:ab:7f:9c:3d:62:42:bc:47:d1:8d:dc:3c:5a:34:
        3d:a3:0e:73:91:81:92:21:10:64:c7:d0:73:de:da:9a:5d:47:
        7e:33:72:99
';

        my $err = __checkCerts($res, $ref);
        
        if($err == 0) {
            print "OK\n";
        } else {
            print "ERROR\n";
        }
    }
}

sub T42_RevokeManyCertificate {
    print STDERR "------------------- T42_RevokeManyCertificate ---------------------\n";
    print "------------------- T42_RevokeManyCertificate ---------------------\n";

    foreach my $c (keys %rev) {
    
        my $data = {
                    'caName'      => 'Test2_SuSE_CA',
                    'caPasswd'    => 'system',
                    'certificate' => $c
                   };
        if(defined $rev{$c}) {
            $data->{crlReason} = $rev{$c};
        }
        
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
}

sub T43_AddCRL3 {
    print STDERR "------------------- T43_AddCRL3 ---------------------\n";
    print "------------------- T43_AddCRL3 ---------------------\n";
    my $data = {
                'caName'      => 'Test2_SuSE_CA',
                'caPasswd'    => 'system',
                'days'        => 1
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

sub T44_ReadCRL3 {
    print STDERR "------------------- T44_ReadCRL3 ---------------------\n";
    print "------------------- T44_ReadCRL3 ---------------------\n";
    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => 'Test2_SuSE_CA',
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

sub T45_CheckCRL3 {
    print STDERR "------------------- T45_CheckCRL3 ---------------------\n";
    print "------------------- T45_CheckCRL3 ---------------------\n";
    my $data = {
                'caName' => 'Test2_SuSE_CA',
                'type'   => "plain",
               };
    
    my $res = YaPI::CaManagement->ReadCRL($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        my $ref = 
'Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: /C=DE/ST=Bavaria/L=Nuremberg/O=My Linux Tux GmbH/OU=IT Abteilung/CN=Test2_SuSE CA/emailAddress=my@linux.tux
        Last Update: Apr 27 11:34:15 2004 GMT
        Next Update: Apr 28 11:34:15 2004 GMT
        CRL extensions:
            X509v3 Authority Key Identifier:
                keyid:09:76:2C:45:C7:92:03:19:AE:9D:D5:0F:35:90:88:B3:05:54:80:24
                DirName:/C=DE/ST=Bavaria/L=Nuremberg/O=My Linux Tux GmbH/OU=IT Abteilung/CN=Test2_SuSE CA/emailAddress=my@linux.tux
                serial:00

Revoked Certificates:
    Serial Number: 11
        Revocation Date: Apr 27 11:34:15 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Unspecified
    Serial Number: 1D
        Revocation Date: Apr 27 11:34:15 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Key Compromise
    Serial Number: 26
        Revocation Date: Apr 27 11:34:14 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                CA Compromise
    Serial Number: 2B
        Revocation Date: Apr 27 11:34:14 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Affiliation Changed
    Serial Number: A1
        Revocation Date: Apr 27 11:34:15 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Superseded
    Serial Number: B2
        Revocation Date: Apr 27 11:34:14 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Cessation Of Operation
    Serial Number: BA
        Revocation Date: Apr 27 11:34:14 2004 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Certificate Hold
    Serial Number: C1
        Revocation Date: Apr 27 11:34:14 2004 GMT
    Serial Number: C5
        Revocation Date: Apr 27 11:34:14 2004 GMT
    Serial Number: C8
        Revocation Date: Apr 27 11:34:14 2004 GMT
    Signature Algorithm: sha1WithRSAEncryption
        20:57:83:fd:1c:50:f4:5e:0a:90:37:c5:ff:1e:35:bb:53:bf:
        14:39:c3:3b:d4:8d:52:5b:01:bf:e6:1d:c4:3e:97:b6:58:c0:
        b4:a0:c1:4d:f4:25:bb:1c:e1:d9:ec:40:77:bd:8d:8b:83:80:
        4d:6d:4a:66:a2:d9:93:d0:2a:ed:d4:25:c3:90:fd:98:6f:ca:
        dd:e9:b3:e2:ef:81:81:d3:99:4c:61:0e:cd:20:8a:92:f3:af:
        82:d1:d8:d8:fd:61:27:da:2e:68:ad:6e:9f:6c:90:60:ef:d5:
        85:80:3f:5d:72:33:ee:c4:91:56:ec:39:ac:18:2f:61:65:c3:
        03:f7:a6:05:6d:74:05:35:f3:a9:ce:52:c8:ab:a8:36:e3:16:
        4d:d5:b1:95:5c:ab:c1:29:be:99:99:0b:e3:32:44:05:6a:63:
        6e:a0:86:f6:78:bd:f3:d2:fe:cb:e2:c0:22:b9:11:dd:9d:26:
        00:2c:9b:39:67:9f:34:e5:78:59:64:10:8b:64:d1:78:09:c0:
        96:a4:27:48:4d:2e:96:91:8c:fb:f2:51:1a:29:70:8a:46:4e:
        c5:06:42:17:be:10:73:fc:de:6b:68:1d:cc:bc:2f:01:b3:03:
        da:ca:5c:5d:f4:58:2b:1e:f7:9a:69:b0:82:bb:ed:80:1d:92:
        de:98:2c:e3
';

        my $err = __checkCerts($res, $ref);
        
        if($err == 0) {
            print "OK\n";
        } else {
            print "ERROR\n";
        }
    }
}

sub __checkCerts {
    my $o = shift;
    my $r = shift;


    my @original = split(/\n/, $o);
    my @reference = split(/\n/, $r);
    
    my $err = 0;
    my $last = "";
    for( my $i = 0; $i < scalar(@original); $i++) {
        
        my $orig = $original[$i];
        my $ref  = $reference[$i];
        
        $orig =~ s/^\s*//;
        $orig =~ s/\s*$//;
        $ref =~ s/^\s*//;
        $ref =~ s/\s*$//;
        
        if($last eq "Signature Algorithm: md5WithRSAEncryption" &&
           $orig =~ /^[[:xdigit:]:]+$/) {
            next;
        }
        if($last eq "Signature Algorithm: sha1WithRSAEncryption" &&
           $orig =~ /^[[:xdigit:]:]+$/) {
            next;
        }
        
        if($last eq "Modulus (2048 bit):" &&
           $orig =~ /^[[:xdigit:]:]+$/) {
            next;
        }
        
        if($orig =~ /^Not Before:/ && $ref =~ /^Not Before:/) {
            next;
        }
        if($orig =~ /^Not After :/ && $ref =~ /^Not After :/) {
            next;
        }
        
        if($last =~ /^X509v3 Subject Key Identifier:/ &&
           $orig =~ /^[[:xdigit:]:]+$/) {
            next;
            }
        if($last =~ /X509v3 Authority Key Identifier:/ &&
           $orig =~ /^keyid:[[:xdigit:]:]+$/) {
            next;
        }
        
        # specials for CRLs
        if($orig =~ /^Last Update:/ && $ref =~ /^Last Update:/) {
            next;
        }
        if($orig =~ /^Next Update:/ && $ref =~ /^Next Update:/) {
            next;
        }
        if($orig =~ /^Revocation Date:/ && $ref =~ /^Revocation Date:/) {
            next;
        }
        
        if($orig ne $ref) {
            $err = $err + 1;
            print STDERR "Found differences:\n";
            print STDERR "ORIG:'$orig'\n";
            print STDERR "REF :'$ref'\n";
            print STDERR "LAST:'$last'\n";
        }
        
        $last = $orig;
    }
    return $err;
}

sub T46_ReadRequest {
    print STDERR "------------------- T46_ReadRequest ---------------------\n";
    print "------------------- T46_ReadRequest ---------------------\n";
    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => 'Test1_SuSE_CA',
                    'type'   => $type,
                    'request' => $req3
                   };
       
        my $res = YaPI::CaManagement->ReadRequest($data);
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

sub T47_ReadRequestList() {
    print STDERR "------------------- T47_ReadRequestList ---------------------\n";
    print "------------------- T47_ReadRequestList ---------------------\n";
    use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
    my $start = [gettimeofday];   
    my $data = {
                'caName' => 'Test2_SuSE_CA'
               };
    
    my $res = YaPI::CaManagement->ReadRequestList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK: time=".tv_interval($start)."\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T48_ImportRequest {
    print STDERR "------------------- T48_ImportRequest ---------------------\n";
    print "------------------- T48_ImportRequest ---------------------\n";

    my $req1 = "
-----BEGIN CERTIFICATE REQUEST-----
MIIDeDCCAmACAQAwdDELMAkGA1UEBhMCREUxFjAUBgNVBAoTDVNVU0UgTElOVVgg
QUcxEzARBgNVBAsTClJELUNPTS1BUFAxGTAXBgNVBAMTEEFkcmlhbiBTY2hyb2V0
ZXIxHTAbBgkqhkiG9w0BCQEWDmFkcmlhbkBzdXNlLmRlMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAyrHyX3xQtEO0VCbysNxvWclMrLUjCQ9jT1E8NzNz
tuJkrK4g6jB5+0L0K7ch0kFeFLFtGJhTQNcRXK4XXXcFEdncBjg+/7xfS3Nfc70c
JFxiJSD8FvU+/ms+z6p7tjid933W9qQlecQ8ZNBnh+ctyrv8/XXQXg3q5hocBzRl
P5iD9M9Av0Cc5zLZKg4ZR67JyST2PgTe3vrqdCWCrlDBabrb5kJ2NbJmMaxvKvfg
QnOwNLX88q/2i9fVZNbSAJyGAI6mm3/DW511lEAA6qxT0p7nOSaspwKYhamWzxEO
nyyBxSe5NMUZ65ZwJ6AFkcBI7csvVbqATA6hllJm/tfKDwIDAQABoIG+MIG7Bgkq
hkiG9w0BCQ4xga0wgaowHQYDVR0OBBYEFM+0QxOhgDNlKPnaOHo4yEkR+f4MMCwG
A1UdEQQlMCOBEWFkcmlhbkBub3ZlbGwuY29tgQ5hZHJpYW5Ac3VzZS5kZTAwBglg
hkgBhvhCAQ0EIxYhWWFTVCBHZW5lcmF0ZWQgQ2xpZW50IENlcnRpZmljYXRlMBEG
CWCGSAGG+EIBAQQEAwIEsDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG
9w0BAQUFAAOCAQEAghco4Q/hR3+j8l23wLHseavJ6O9v5/MyexTeWo3qek5hLcKv
yjSn1WDrH8ZlAoFXE3IAvheHxz6ZsDQWIN5pgrJK5PVV/CyUC7JEFqM5QjoAzvY+
EOpuxGi4jEB6BCl7N8k172HmU8bmEX8GHTLocS2NUJwCuxy+Ua+9WjZhNK9DjdX1
VOFmvsVH6RwrxuOJmBSLPW0gQeIne0ONxdbDxuMmHrrBt7Ay4pWWtonFjCt6/5ul
nwR1IKGnTcEx4CkTLp4lTISAj/2tE8jMPmTnGEO7dnkX2wW7Eb0Z5gDsVTzGh580
/NKGapmM80ejfdrgrMlBjdG23yaN4qTGRPgvWg==
-----END CERTIFICATE REQUEST-----
";

    my $data = {
                'caName' => 'Test1_SuSE_CA',
                'data' => $req1
               };
    
    my $res = YaPI::CaManagement->ImportRequest($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
        $req4 = $res;
    }
}

sub T49_DeleteRequest {
    print STDERR "------------------- T49_DeleteRequest ---------------------\n";
    print "------------------- T49_DeleteRequest ---------------------\n";

    my $data = {
                'caName'   => 'Test1_SuSE_CA',
                'request'  => $req4,
                'caPasswd' => 'system'
               };
    
    my $res = YaPI::CaManagement->DeleteRequest($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T50_ImportCA {
    print STDERR "------------------- T50_ImportCA ---------------------\n";
    print "------------------- T50_ImportCA ---------------------\n";

    my $data = {
                'caName'       => 'Test4_SuSE_CA',
                'caCertificate'=> "/var/lib/CAM/Test1_SuSE_CA/cacert.pem",
                'caKey'        => '/var/lib/CAM/Test1_SuSE_CA/cacert.key'
               };
    
    my $res = YaPI::CaManagement->ImportCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}
