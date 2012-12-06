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
use Config::IniFiles;
use Getopt::Long;
use YaPI::CaManagement;

my $config     = '/etc/generateCRL.conf';
my $help       = undef;

my @toDo = ();

Getopt::Long::Configure("no_ignore_case", "no_auto_abbrev");
my $result = GetOptions ("config|c=s"  => \$config,
                         "help|?|h"    => \$help);

if($help || !$result) {
    print "usage: generateCRL.pl [-c path] \n";
    print "\n";
    print "-c, --config     Path to configfile (default: /etc/generateCRL.conf)\n";
    print "-?, --help, -h   This help\n";
    exit;
}

my $cfg = new Config::IniFiles( -file => $config );
if(!defined $cfg) {
    die "Can not read the configfile:\n @Config::IniFiles::errors\n";
}

@toDo = $cfg->Sections();

foreach my $gencrl (@toDo) {

    print "Process '$gencrl' ... ";
    my $ret = doit($gencrl);
    if($ret eq "") {
        print "done\n";
    } else {
        print "failed\n$ret\n";
    }
}


sub doit {
    my $caName = shift;

    my $caPasswd   = $cfg->val($caName, "caPasswd");
    my $host       = $cfg->val($caName, "ldapHostname");
    my $port       = $cfg->val($caName, "ldapPort", 389);
    my $destDN     = $cfg->val($caName, "destinationDN");
    my $bindDN     = $cfg->val($caName, "bindDN");
    my $ldapPasswd = $cfg->val($caName, "ldapPasswd");
    my $err;
    my $msg;

    my $res = YaPI::CaManagement->ReadCRLDefaults({'caName' => $caName, 'caPasswd'    => $caPasswd});
    if( not defined $res ) {
        $err = YaPI::CaManagement->Error();
        $msg = $err->{summary};
        $msg .= "[".$err->{description}."]" if(defined $err->{description});
        return $msg;
    }

    my $data = {
                'caName'      => $caName,
                'caPasswd'    => $caPasswd,
                'days'        => $res->{days}
               };

    $res = YaPI::CaManagement->AddCRL($data);
    if( not defined $res ) {
        $err = YaPI::CaManagement->Error();
        $msg = $err->{summary};
        $msg .= "[".$err->{description}."]" if(defined $err->{description});
        return $msg;
    }

    $data = {
             caName        => $caName,
             ldapHostname  => $host,
             ldapPort      => $port,
             destinationDN => $destDN,
             BindDN        => $bindDN,
             ldapPasswd    => $ldapPasswd
            };

    $res = YaPI::CaManagement->ExportCRLToLDAP($data);
    if( not defined $res ) {
        $err = YaPI::CaManagement->Error();
        $msg = $err->{summary};
        $msg .= "[".$err->{description}."]" if(defined $err->{description});
        return $msg;
    }

    return "";
}
