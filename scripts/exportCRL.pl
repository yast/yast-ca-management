#! /usr/bin/perl -w

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

use strict;
use Getopt::Long;
use YaPI::CaManagement;
use Data::Dumper;


my $err;
my $msg;
my $res;
my $config     = undef;
my $help       = undef;
my %conf = ();


Getopt::Long::Configure("no_ignore_case", "no_auto_abbrev");
my $result = GetOptions ("config|c=s"  => \$config,
                         "help|?|h"    => \$help);

if($help || !$result) {
    print "usage: $0 -c <config-file> \n";
    print "\n";
    print "-c, --config     Path to configfile\n";
    print "-?, --help, -h   This help\n";
    exit;
}

if (!$config) {
    print "Can not operate without a configfile. See '$0 -h' for help\n";
    exit 1;
}

if (! -e $config) {
    print "Configuration file $config does not exist.";
    exit 1;
}


#
# read config file
#
if (! open(CONF,"< $config"))
{
    print "Can not open configuration file $config .";
    exit 1;
}

while (<CONF>)
{
    if ($_ =~ /^\s*([a-zA-Z0-9_-]+)\s*=\s*(\S*)\s*$/) 
    {
        if (defined $1 && $1 ne '') 
        {
            if (not defined $2) {$2 = "";}
            $conf{"$1"}="$2";
        }
    }
}
close CONF;

if ( not exists $conf{"caname"}     ||
     not exists $conf{"capassword"}
   )
{
    print "CA information (name or password) is missing in config file $config .";
    exit 1;
}

if ($conf{"ldap_port"} eq "") { $conf{"ldap_port"} = 389; }



#
# reading default values for specified CRL
#
$res = YaPI::CaManagement->ReadCRLDefaults({caName => $conf{"caname"}, caPasswd  => $conf{"capassword"} });
if( not defined $res ) {
    $err = YaPI::CaManagement->Error();
    $msg = $err->{summary};
    $msg .= "[".$err->{description}."]" if(defined $err->{description});
    print $msg;
}


#
# generating new CRL
#
my $data = {
            'caName'      => $conf{"caname"},
            'caPasswd'    => $conf{"capassword"},
            'days'        => $res->{days}
            };
if (! defined ${$data}{days}  ||  ${$data}{days} eq '') { ${$data}{days} = 30; }

$res = YaPI::CaManagement->AddCRL($data);
if( not defined $res ) {
    $err = YaPI::CaManagement->Error();
    $msg = $err->{summary};
    $msg .= "[".$err->{description}."]" if(defined $err->{description});
    print $msg;
}

#
# export new CRL to LDAP if configured
#
if ($conf{"export_ldap"} eq "true")
{
    $data = {
             'caName'        => $conf{"caname"},
             'ldapHostname'  => $conf{"ldap_hostname"},
             'ldapPort'      => $conf{"ldap_port"},
             'destinationDN' => $conf{"ldap_dn"},
             'BindDN'        => $conf{"ldap_binddn"},
             'ldapPasswd'    => $conf{"ldap_password"}
            };

    $res = YaPI::CaManagement->ExportCRLToLDAP($data);
    if( not defined $res ) {
        $err = YaPI::CaManagement->Error();
        $msg = $err->{summary};
        $msg .= "[".$err->{description}."]" if(defined $err->{description});
        print $msg;
    }
}


#
# export new CRL to file if configured
#
if ($conf{"export_file"} eq "true")
{
    $data = {
               'caName'          => $conf{"caname"},
               'caPasswd'        => $conf{"capassword"},
               'exportFormat'    => uc($conf{"crlfileformat"}),
               'destinationFile' => $conf{"crlfilename"}
            };

    $res = YaPI::CaManagement->ExportCRL($data);
    if( not defined $res ) {
        $err = YaPI::CaManagement->Error();
        $msg = $err->{summary};
        $msg .= "[".$err->{description}."]" if(defined $err->{description});
        return $msg;
    }
}
