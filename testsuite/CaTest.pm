package CaTest;
#use warnings;

use MIME::Base64;

BEGIN {
    $TYPEINFO{run} = ["function", "void"];
    push @INC, '/usr/share/YaST2/modules/';
}
use YaPI::CaManagement;
use Locale::gettext;
use POSIX ();     # Needed for setlocale()

use Data::Dumper;

POSIX::setlocale(LC_MESSAGES, "");
textdomain("caManagement");

my $exampleCA = "";
my $exampleReq = "";
my $exampleCert = "";

sub run {
#    test_Interface();
#    test_Version();
#    test_Capabilities();
#    test_AddRootCA();
    test_ReadCAList();
#    test_AddRootCA2();
#    test_ReadCertificateDefaults();
#    test_ReadCertificateDefaults2();
#    test_ReadCA();
#    test_AddRequest();
#    test_issueCertificate();
#    test_AddCertificate();
#    test_AddCertificate2();
    test_ReadCertificateList();
#    test_ReadCertificate();
#    test_RevokeCertificate();

#    test_AddCRL();
#    test_ReadCRL();
#    test_ExportCA();
#    test_ExportCertificate();
#    test_ExportCRL();
#    test_Verify();

#    test_AddSubCA();
#    test_ExportCAToLDAP();
#    test_ExportCRLToLDAP();
#    test_UpdateDB();
#    test_CreateManyCerts();
#    test_ListManyCerts('215152321042820');
#    test_WriteCertificateDefaults();
#    test_ReadLDAPExportDefaults();
#    test_ReadLDAPExportDefaults2();
#    test_InitLDAPcaManagement();
    test_ExportCertificateToLDAP();

# dummy_test();
    return 1;
}

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
    exit 1;
}

sub test_Interface {
    my $interface = YaPI::CaManagement->Interface();
    if( not defined $interface ) {
        my $msg = YaPI::CaManagement->Error();
        print STDERR "ERROR Interface: \n";
        printError($err);
    } else {
        print STDERR "SUCCESS Interface: \n";
        print STDERR Data::Dumper->Dump($interface)."\n";
    }
    
}

sub test_ReadCAList {
    my $caList = YaPI::CaManagement->ReadCAList();
    if( not defined $caList ) {
        my $msg = YaPI::CaManagement->Error();
        print STDERR "ERROR ReadCaList: \n";
        printError($err);
    } else {
        print STDERR "SUCCESS ReadCaList: \n";
        foreach (@$caList) {
            print STDERR "$_\n";
            $exampleCA = $_;
        } 
    }
}

sub test_AddRootCA {
    my $caName = join("", localtime(time));
    my $data = {
                'caName'                => $caName,
                'keyPasswd'             => 'system',
                'commonName'            => 'My CA',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '3650',
                'countryName'           => 'DE',
                'localityName'          => 'Nuernberg',
                'organizationName'      => 'My GmbH',
                'basicConstraints'      => 'critical, CA:true',
                'crlDistributionPoints' => 'URI:http://my.linux.tux/',
               };
    print STDERR "trying to call YaPI::CaManagement->AddRootCA with caName = '$caName'\n";

    my $res = YaPI::CaManagement->AddRootCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
}

sub test_AddRootCA2 {
    my $caName = join("", localtime(time));
    my $data = {
                'caName'                => $caName,
                'keyPasswd'             => 'system',
                'commonName'            => 'My CA',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '1024',
                'days'                  => '3650',
                'countryName'           => 'US',
                'localityName'          => 'Nuernberg',
                'organizationName'      => 'My GmbH',
                'basicConstraints'      => 'critical, CA:true',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=$caName%2Cou=CA%2Cdc=suse%2Cdc=de",
                'nsComment'             => "\"trulla die waldfee\""
               };
    print STDERR "trying to call YaPI::CaManagement->AddRootCA with caName = '$caName'\n";
    
    my $res = YaPI::CaManagement->AddRootCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
}

sub test_ReadCertificateDefaults {

    foreach my $certType ("ca", "client", "server") {
        my $data = {
                    'caName'    => $exampleCA,
                    'certType'  => $certType
                   };
        print STDERR "trying to call YaPI::CaManagement->ReadCertificateDefaults($certType)\n";
        print STDERR "with caName = '$exampleCA'\n";
        
        my $res = YaPI::CaManagement->ReadCertificateDefaults($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub test_ReadCertificateDefaults2 {
    
    my $data = {
                'certType'  => 'ca'
               };
    print STDERR "trying to call YaPI::CaManagement->ReadCertificateDefaults(ca)\n";
    print STDERR "=> Root CA defaults\n";

    my $res = YaPI::CaManagement->ReadCertificateDefaults($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub test_ReadCA {

    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => $exampleCA,
                    'type'   => $type
                   };
        print STDERR "trying to call YaPI::CaManagement->ReadCA($type)\n";
        print STDERR "with caName = '$exampleCA'\n";
        
        my $res = YaPI::CaManagement->ReadCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub test_AddRequest {
    my $data = {
                'caName'                => $exampleCA,
                'keyPasswd'             => 'system',
                'commonName'            => 'My Request5',
                'emailAddress'          => 'my2@tait.linux.tux',
                'keyLength'             => '2048',
                'days'                  => '365',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux/OU=hallo',
                'nsComment'             => "\"heide witzka, herr Kapitän\""
               };
    print STDERR "trying to call YaPI::CaManagement->AddRequest with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->AddRequest($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        $exampleReq = $res;
        print STDERR "OK: '$res'\n";
    }
}

sub test_issueCertificate {
    my $data = {
                'caName'                => $exampleCA,
                'request'               => $exampleReq,
                'certType'              => 'client',
                'caPasswd'              => 'system',
                'days'                  => '365',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=$caName%2Cou=CA%2Cdc=suse%2Cdc=de",
                'nsComment'             => "\"Heide Witzka, Herr Kapitän\"",
               };
    print STDERR "trying to call YaPI::CaManagement->IssueCertificate with caName = '$exampleCA'\n";
    print STDERR "and reqest '$exampleReq'\n";
    
    my $res = YaPI::CaManagement->IssueCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK: '$res'\n";
        $res =~ /^[[:xdigit:]]+:(.*)$/;
        print STDERR decode_base64($1)."\n";
    }
}

sub test_AddCertificate {
    my $data = {
                'caName'                => $exampleCA,
                'certType'              => 'client',
                'keyPasswd'             => 'system',
                'caPasswd'              => 'system',
                'commonName'            => 'My Request new1',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '365',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux Tux GmbH',
                'days'                  => '365',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=$caName%2Cou=CA%2Cdc=suse%2Cdc=de",
                'nsComment'             => "\"Heide Witzka, Herr Kapitän\"",
               };
    print STDERR "trying to call YaPI::CaManagement->AddCertificate with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->AddCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK: '$res'\n";
    }
}

sub test_ReadCertificateList {

    my $data = {
                caName => $exampleCA,
                caPasswd => "system"
               };

    print STDERR "trying to call YaPI::CaManagement->ReadCertificateList()\n";
    print STDERR "with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        $exampleCert = $res->[0]->{'certificate'};
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub test_ReadCertificate {

    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => $exampleCA,
                    'type'   => $type,
                    'certificate' => $exampleCert
                   };
        print STDERR "trying to call YaPI::CaManagement->ReadCertificate($type)\n";
        print STDERR "with caName = '$exampleCA' and certificate = '$exampleCert'\n";
        
        my $res = YaPI::CaManagement->ReadCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub test_RevokeCertificate {

    my $data = {
                'caName'      => $exampleCA,
                'caPasswd'    => 'system',
                'certificate' => $exampleCert
               };
    print STDERR "trying to call YaPI::CaManagement->RevokeCertificate()\n";
    print STDERR "with caName = '$exampleCA' and certificate = '$exampleCert'\n";
    
    my $res = YaPI::CaManagement->RevokeCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "Revoke successful\n";
    }
}

sub test_AddCRL {
    my $data = {
                'caName'      => $exampleCA,
                'caPasswd'    => 'system',
                'days'        => 8
               };
    print STDERR "trying to call YaPI::CaManagement->AddCRL()\n";
    print STDERR "with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->AddCRL($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "AddCRL successful\n";
    }
}

sub test_ReadCRL {

    foreach my $type ("parsed", "plain") {
        my $data = {
                    'caName' => $exampleCA,
                    'type'   => $type,
                   };
        print STDERR "trying to call YaPI::CaManagement->ReadCRL($type)\n";
        print STDERR "with caName = '$exampleCA' \n";
        
        my $res = YaPI::CaManagement->ReadCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub test_ExportCA {
    foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12", "PKCS12_CHAIN") {
        my $data = {
                    'caName' => $exampleCA,
                    'exportFormat' => $ef,
                    'caPasswd' => "system",
                   };
        if($ef =~ /^PKCS12/) {
            $data->{'P12Password'} = "tralla";
        }
        print STDERR "trying to call YaPI::CaManagement->ExportCA($ef)\n";
        print STDERR "with caName = '$exampleCA' \n";
    
        my $res = YaPI::CaManagement->ExportCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            if(! open(OUT, "> /tmp/mc/certs/CA_$ef")) {
                print STDERR "OPEN_FAILED\n";
            }
            print OUT $res;
            close OUT;
            print STDERR "OK\n";
        }
        $data->{'destinationFile'} = "/tmp/mc/certs/DF_CA_$ef";
        $res = YaPI::CaManagement->ExportCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR "OK\n";
        }
    }
}

sub test_ExportCertificate {

    foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12", "PKCS12_CHAIN") {
        my $data = {
                    'caName' => $exampleCA,
                    'certificate' => $exampleCert,
                    'exportFormat' => $ef,
                    'keyPasswd' => "system",
                   };
        if($ef =~ /^PKCS12/) {
            $data->{'P12Password'} = "tralla";
        }
        print STDERR "trying to call YaPI::CaManagement->ExportCertificate($ef)\n";
        print STDERR "with caName = '$exampleCA' \n";
    
        my $res = YaPI::CaManagement->ExportCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            if(! open(OUT, "> /tmp/mc/certs/CRT_$ef")) {
                print STDERR "OPEN_FAILED\n";
            }
            print OUT $res;
            close OUT;
            print STDERR "OK\n";
        }
        $data->{'destinationFile'} = "/tmp/mc/certs/DF_CRT_$ef";
        $res = YaPI::CaManagement->ExportCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR "OK\n";
        }
    }
}

sub test_ExportCRL {
    foreach my $ef ("PEM", "DER") {
        my $data = {
                    'caName' => $exampleCA,
                    'exportFormat' => $ef,
                   };
        print STDERR "trying to call YaPI::CaManagement->ExportCRL($ef)\n";
        print STDERR "with caName = '$exampleCA' \n";
    
        my $res = YaPI::CaManagement->ExportCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            if(! open(OUT, "> /tmp/mc/certs/CRL_$ef")) {
                print STDERR "OPEN_FAILED\n";
            }
            print OUT $res;
            close OUT;
            print STDERR "OK\n";
        }
        $data->{'destinationFile'} = "/tmp/mc/certs/DF_CRL_$ef";
        $res = YaPI::CaManagement->ExportCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR "OK\n";
        }

    }
}

sub test_Verify {

    my $data = {
                caName => $exampleCA,
                caPasswd => "system"
               };
    
    print STDERR "trying to call YaPI::CaManagement->ReadCertificateList()\n";
    print STDERR "with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {

        foreach my $cert (@$res) {
            $data = {
                     caName => $exampleCA, 
                     certificate => $cert->{'certificate'} 
                    };

            print STDERR "trying to call YaPI::CaManagement->Verify(".$cert->{'certificate'}.")\n";

            my $Vret = YaPI::CaManagement->Verify($data);
            if(not defined $Vret) {
                printError(YaPI::CaManagement->Error());
            } else {
                print STDERR "$Vret\n";
            }
        }
    }
}

sub test_Version {

    my $version = YaPI::CaManagement->Version();
    print STDERR "VERSION: $version\n";
}

sub test_Capabilities {
 
    foreach my $cap ("SLES9", "USER") {
        print YaPI::CaManagement->Supports($cap) ? "supports $cap\n" : "NO $cap\n";
    }
}

sub test_AddSubCA {
    my $newCaName = join("", localtime(time));
    my $data = {
                'caName'                => $exampleCA,
                'newCaName'             => $newCaName,
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
    print STDERR "trying to call YaPI::CaManagement->AddSubCA with caName = '$exampleCA'\n";
    print STDERR "and newCaName = '$newCaName'\n";

    my $res = YaPI::CaManagement->AddSubCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
}

sub test_ExportCAToLDAP {
    my $data = {
                caName => $exampleCA,
                ldapHostname => 'tait.suse.de',
                ldapPort => 389,
                destinationDN => "ou=PKI,dc=suse,dc=de",
                BindDN => "uid=cyrus,dc=suse,dc=de",
                password => "system"
               };
    print STDERR "trying to call YaPI::CaManagement->ExportCAToLDAP with caName = '$exampleCA'\n";

    my $res = YaPI::CaManagement->ExportCAToLDAP($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }

}

sub test_ExportCRLToLDAP {
    my $data = {
                caName => $exampleCA,
                ldapHostname => 'tait.suse.de',
                ldapPort => 389,
                destinationDN => "ou=PKI,dc=suse,dc=de",
                BindDN => "uid=cyrus,dc=suse,dc=de",
                password => "system"
               };
    print STDERR "trying to call YaPI::CaManagement->ExportCRLToLDAP with caName = '$exampleCA'\n";

    my $res = YaPI::CaManagement->ExportCRLToLDAP($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
}

sub test_UpdateDB {

    foreach my $pass ( "system", "false" ) {
        my $data = {
                    caName => $exampleCA,
                    caPasswd => $pass
                   };
        
        print STDERR "trying to call YaPI::CaManagement->UpdateDB with caName = '$exampleCA'\n";
        
        my $res = YaPI::CaManagement->UpdateDB($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR "OK\n";
        }
    }
}


sub test_CreateManyCerts {
    my $caName = join("", localtime(time));
    my $data = {
                'caName'                => $caName,
                'keyPasswd'             => 'system',
                'commonName'            => 'My CA',
                'emailAddress'          => 'my@linux.tux',
                'keyLength'             => '2048',
                'days'                  => '3650',
                'countryName'           => 'DE',
                'localityName'          => 'Nuernberg',
                'organizationName'      => 'My GmbH',
                'basicConstraints'      => 'critical, CA:true',
                'crlDistributionPoints' => 'URI:http://my.linux.tux/',
               };
    print STDERR "trying to call YaPI::CaManagement->AddRootCA with caName = '$caName'\n";
    
    my $res = YaPI::CaManagement->AddRootCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
    
    for(my $i = 0; $i < 200; $i++) {
        
        my $data = {
                    'caName'                => $caName,
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
        print STDERR "trying to call YaPI::CaManagement->AddCertificate with caName = '$caName'\n";
        
        my $res = YaPI::CaManagement->AddCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = YaPI::CaManagement->Error();
            printError($err);
        } else {
            print STDERR "OK: '$res'\n";
        }
    } 
}

sub test_ListManyCerts {
    my $caName = shift;

    use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
    $start = [gettimeofday];   
    my $data = {
                caName => $caName,
                caPasswd => "system"
               };
    
    print STDERR "trying to call YaPI::CaManagement->ReadCertificateList()\n";
    print STDERR "with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print "time=".tv_interval($start)."\n";
        #print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub test_WriteCertificateDefaults {

    my $data = {
                'caName'                => $exampleCA,
                'certType'              => 'server',
                'basicConstraints'      => 'critical, CA:FALSE',
                'nsComment'             => '"SuSE Certificate"',
                'crlDistributionPoints' => 'URI:http://www.suse.de/CA/crl.pem',
               };
    print STDERR "trying to call YaPI::CaManagement->WriteCertificateDefaults with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->WriteCertificateDefaults($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
}

sub test_AddCertificate2 {

    my $data = {
                'caName'                => $exampleCA,
                'certType'              => 'client',
                'keyPasswd'             => 'system',
                'caPasswd'              => 'system',
                'commonName'            => 'My Request new1',
                'emailAddress'          => 'my@linux.tux',
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
                'authorityKeyIdentifier' => 'issuer, keyid',
                'subjectAltName'        => 'email:me@linux.tux, URI:http://www.linux.tux/, DNS:tait.linux.tux, RID:1.2.3.4, IP:10.10.0.161',
                'issuerAltName'         => 'email:iss@linux.tux, URI:http://www.linux.tux/, DNS:hermes.linux.tux, RID:1.7.9.1.1.4.5.7.1, IP:10.10.0.8',
                'nsBaseUrl'             => 'http://www.linux.tux/',
                'nsRevocationUrl'       => 'http://www.linux.tux/',
                'nsCaRevocationUrl'     => 'http://www.linux.tux/',
                'nsRenewalUrl'          => 'http://www.linux.tux/',
                'nsCaPolicyUrl'         => 'http://www.linux.tux/',
                'nsSslServerName'       => 'tait.suse.de',
                'extendedKeyUsage'      => 'emailProtection, msSGC, nsSGC',
                'authorityInfoAccess'   => 'OCSP;URI:http://ocsp.my.host/',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=$caName%2Cou=CA%2Cdc=suse%2Cdc=de",
               };
    print STDERR "trying to call YaPI::CaManagement->AddCertificate with caName = '$exampleCA'\n";
    
    my $res = YaPI::CaManagement->AddCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK: '$res'\n";
    }
}

sub test_ReadLDAPExportDefaults {

    my $res = YaPI::CaManagement->ReadLDAPExportDefaults({ type => "ca" });
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

}

sub test_ReadLDAPExportDefaults2 {

    my $res = YaPI::CaManagement->ReadLDAPExportDefaults({ type => "certificate",
                                                           commonName => "Michael Calmer"});
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub test_InitLDAPcaManagement {

    my $res = YaPI::CaManagement->InitLDAPcaManagement({ ldapPasswd => "system" });
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK \n";
    }
    
}

sub test_ExportCertificateToLDAP {

    my $data = {
                caName        => $exampleCA,
                certificate   => $exampleCert,
                ldapHostname  => 'tait.suse.de',
                ldapPort      => 389,
                destinationDN => "uid=mc,ou=people,dc=suse,dc=de",
                BindDN        => "uid=cyrus,dc=suse,dc=de",
                ldapPasswd    => "system",
                keyPasswd     => "system",
                p12Passwd     => "System"
            };

    my $res = YaPI::CaManagement->ExportCertificateToLDAP($data);
    if( not defined $res ) {
        # error
        print STDERR "Fehler\n";
        my $err = YaPI::CaManagement->Error();
        printError($err);
    } else {
        print STDERR "OK\n";
    }
}

sub dummy_test {

    use strict;
    use Data::Dumper;
    use YaST::YCP;
    use ycp;
    
    YaST::YCP::Import ("SCR");
    
    SCR->Execute(".ldap", {"hostname" => "ldap.suse.de",
                           "port"     => 389});
    
    SCR->Execute(".ldap.bind", {});
    
    my $ldapret = SCR->Read(".ldap.search", {
                                             "base_dn" => "dc=suse,dc=de",
                                             "filter" => "(& (objectclass=inetOrgPerson) (cn=x*))",
                                             "scope" => 2,
                                             "not_found_ok" => 1,
                                             "dn_only" => 1
                                            });
    
    if (! defined $ldapret) {
        my $ldapERR = SCR->Read(".ldap.error");
        print STDERR $ldapERR->{'code'}." : ".$ldapERR->{'msg'}."\n";
    }
    print Data::Dumper->Dump([$ldapret])."\n";
}

1;

