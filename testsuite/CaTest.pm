package CaTest;
#use warnings;

use MIME::Base64;

BEGIN {
    $TYPEINFO{run} = ["function", "void"];
    push @INC, '/usr/share/YaST2/modules/';
}
use CaManagement;
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
#    test_AddRootCA();
    test_ReadCAList();
#    test_AddRootCA2();
#    test_ReadCertificateDefaults();
#    test_ReadCertificateDefaults2();
#    test_ReadCA();
#    test_AddRequest();
#    test_issueCertificate();
#    test_AddCertificate();
    test_ReadCertificateList();
#    test_ReadCertificate();
#    test_RevokeCertificate();
#    test_AddCRL();
#    test_ReadCRL();
#    test_ExportCA();
    test_ExportCertificate();

    return 1;
}

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
}

sub test_Interface {
    my $interface = CaManagement->Interface();
    if( not defined $interface ) {
        my $msg = CaManagement->Error();
        print STDERR "ERROR Interface: \n";
        printError($err);
    } else {
        print STDERR "SUCCESS Interface: \n";
        print STDERR Data::Dumper->Dump($interface)."\n";
    }
    
}

sub test_ReadCAList {
    my $caList = CaManagement->ReadCAList();
    if( not defined $caList ) {
        my $msg = CaManagement->Error();
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
                'crlDistributionPoints' => 'URI:http://my.linux.tux/',
               };
    print STDERR "trying to call YaST::caManagement->AddRootCA with caName = '$caName'\n";

    my $res = CaManagement->AddRootCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=$caName%2Cou=CA%2Cdc=suse%2Cdc=de",
                'nsComment'             => "\"trulla die waldfee\""
               };
    print STDERR "trying to call YaST::caManagement->AddRootCA with caName = '$caName'\n";
    
    my $res = CaManagement->AddRootCA($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
        print STDERR "trying to call YaST::caManagement->ReadCertificateDefaults($certType)\n";
        print STDERR "with caName = '$exampleCA'\n";
        
        my $res = CaManagement->ReadCertificateDefaults($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = CaManagement->Error();
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
    print STDERR "trying to call YaST::caManagement->ReadCertificateDefaults(ca)\n";
    print STDERR "=> Root CA defaults\n";

    my $res = CaManagement->ReadCertificateDefaults($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
        print STDERR "trying to call YaST::caManagement->ReadCA($type)\n";
        print STDERR "with caName = '$exampleCA'\n";
        
        my $res = CaManagement->ReadCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = CaManagement->Error();
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
    print STDERR "trying to call YaST::caManagement->AddRequest with caName = '$exampleCA'\n";
    
    my $res = CaManagement->AddRequest($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
    print STDERR "trying to call YaST::caManagement->IssueCertificate with caName = '$exampleCA'\n";
    
    my $res = CaManagement->IssueCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
                'commonName'            => 'My Request11',
                'emailAddress'          => 'my2@tait.linux.tux',
                'keyLength'             => '2048',
                'days'                  => '365',
                'countryName'           => 'DE',
                'localityName'          => 'Nuremberg',
                'stateOrProvinceName'   => 'Bavaria',
                'organizationalUnitName'=> 'IT Abteilung',
                'organizationName'      => 'My Linux Tux / Inc',
                'days'                  => '365',
                'crlDistributionPoints' => "URI:ldap://my.linux.tux/?cn=$caName%2Cou=CA%2Cdc=suse%2Cdc=de",
                'nsComment'             => "\"Heide Witzka, Herr Kapitän\"",
               };
    print STDERR "trying to call YaST::caManagement->AddCertificate with caName = '$exampleCA'\n";
    
    my $res = CaManagement->AddCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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

    print STDERR "trying to call YaST::caManagement->ReadCertificateList()\n";
    print STDERR "with caName = '$exampleCA'\n";
    
    my $res = CaManagement->ReadCertificateList($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
        printError($err);
    } else {
        $exampleCert = $res->[1]->{'certificate'};
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
        print STDERR "trying to call YaST::caManagement->ReadCertificate($type)\n";
        print STDERR "with caName = '$exampleCA' and certificate = '$exampleCert'\n";
        
        my $res = CaManagement->ReadCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = CaManagement->Error();
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
    print STDERR "trying to call YaST::caManagement->RevokeCertificate()\n";
    print STDERR "with caName = '$exampleCA' and certificate = '$exampleCert'\n";
    
    my $res = CaManagement->RevokeCertificate($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
    print STDERR "trying to call YaST::caManagement->AddCRL()\n";
    print STDERR "with caName = '$exampleCA'\n";
    
    my $res = CaManagement->AddCRL($data);
    if( not defined $res ) {
        print STDERR "Fehler\n";
        my $err = CaManagement->Error();
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
        print STDERR "trying to call YaST::caManagement->ReadCRL($type)\n";
        print STDERR "with caName = '$exampleCA' \n";
        
        my $res = CaManagement->ReadCRL($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = CaManagement->Error();
            printError($err);
        } else {
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub test_ExportCA {
    foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12") {#, "PKCS12_CHAIN") {
        my $data = {
                    'caName' => $exampleCA,
                    'exportFormat' => $ef,
                    'caPasswd' => "system",
                   };
        if($ef =~ /^PKCS12/) {
            $data->{'P12Password'} = "tralla";
        }
        print STDERR "trying to call YaST::caManagement->ExportCA($ef)\n";
        print STDERR "with caName = '$exampleCA' \n";
    
        my $res = CaManagement->ExportCA($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = CaManagement->Error();
            printError($err);
        } else {
            if(! open(OUT, "> /tmp/mc/certs/$ef")) {
                print STDERR "OPEN_FAILED\n";
            }
            print OUT $res;
            close OUT;
        }
    }
}

sub test_ExportCertificate {

    foreach my $ef ("PEM_CERT", "PEM_CERT_KEY", "PEM_CERT_ENCKEY","DER_CERT", "PKCS12") {
        my $data = {
                    'caName' => $exampleCA,
                    'certificate' => $exampleCert,
                    'exportFormat' => $ef,
                    'keyPasswd' => "system",
                   };
        if($ef =~ /^PKCS12/) {
            $data->{'P12Password'} = "tralla";
        }
        print STDERR "trying to call YaST::caManagement->ExportCertificate($ef)\n";
        print STDERR "with caName = '$exampleCA' \n";
    
        my $res = CaManagement->ExportCertificate($data);
        if( not defined $res ) {
            print STDERR "Fehler\n";
            my $err = CaManagement->Error();
            printError($err);
        } else {
            if(! open(OUT, "> /tmp/mc/certs/CRT_$ef")) {
                print STDERR "OPEN_FAILED\n";
            }
            print OUT $res;
            close OUT;
        }
    }
}

1;
