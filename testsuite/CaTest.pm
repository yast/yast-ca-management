package CaTest;
#use warnings;

BEGIN {
    $TYPEINFO{run} = ["function", "void"];
    push @INC, '/usr/share/YaST2/modules/';
}
use CaManagement;
use Locale::gettext;
use POSIX ();     # Needed for setlocale()

POSIX::setlocale(LC_MESSAGES, "");
textdomain("caManagement");

sub run {
#    test_ReadCAList();
#    test_AddRootCA();
    test_AddRootCA2();
    
    return 1;
}

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
}

sub test_ReadCAList {
    my @caList = CaManagement->ReadCAList();
    if( not defined @caList ) {
        my $msg = CaManagement->Error();
        print STDERR "ERROR ReadCaList: \n";
        printError($err);
    } else {
        print STDERR "SUCCESS ReadCaList: \n";
        foreach (@caList) {
            print STDERR "$_\n";
        } 
    }
}

sub test_AddRootCA {
    my $caName = join("", localtime(time));
    $data = {
             'caName'                => $caName,
             'keyPasswd'             => 'system',
             'commonName'            => 'My CA',
             'emailAddress'          => 'my@linux.tux',
             'keyLength'             => '1024',
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
    $data = {
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

1;
