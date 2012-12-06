#! /usr/bin/perl -w
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ****************************************************************************/
#

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

use strict;
use Getopt::Long;
use YaPI::CaManagement;


my $err    = undef;
my $msg    = undef;
my $res    = undef;
my $config = undef;
my $help   = undef;
my %conf   = ();


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
$res = YaPI::CaManagement->ReadCRLDefaults({'caName' => $conf{"caname"}, 'caPasswd'  => $conf{"capassword"} });
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
            'days'        => $res->{"days"}
            };
if (! defined ${$data}{"days"}  ||  ${$data}{"days"} eq '') { ${$data}{"days"} = 30; }

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
        print $msg;
    }
}

if (not defined $msg)
{ exit 0; }
else
{ exit 1; }
