package YaPI;

BEGIN {
    push @INC, '/usr/share/YaST2/modules';
}

use strict;
use YaST::YCP;
use ycp;

our %TYPEINFO;
my %__error = ();
my $VERSION = "";
our @CAPABILITIES = ();

BEGIN { $TYPEINFO{Interface} = ["function", "any"]; }
sub Interface {
    my $self = shift;
    my @ret = ();

    my $var = "\%$self"."::TYPEINFO";
    my %TI = eval $var;

    foreach my $k (keys %TYPEINFO) {
        $TI{$k} = $TYPEINFO{$k};
    }

    foreach my $funcName (sort keys %TI) {
        my @dummy = @{$TI{$funcName}};
        my $hash = {};

        $hash->{'functionName'} = $funcName;
        $hash->{'return'}       = $dummy[1];
        splice(@dummy, 0, 2);
        $hash->{'argument'} = \@dummy;
        push @ret, $hash;
    }
    return \@ret;
}

BEGIN { $TYPEINFO{Version} = ["function", "string"]; }
sub Version {
    my $self = shift;

    my $var = "\$$self"."::VERSION";
    my $v = eval $var;

    return $v;
}

BEGIN { $TYPEINFO{Supports} = ["function", "boolean", "string"]; }
sub Supports {
    my $self = shift;
    my $cap  = shift;

    my $var = "\@$self"."::CAPABILITIES";
    my @c = eval $var;

    foreach my $k (@CAPABILITIES) {
        push @c, $k;
    }
    
    return !!grep( ($_ eq $cap), @c);
}


BEGIN { $TYPEINFO{SetError} = ["function", "boolean", ["map", "string", "any" ]]; }
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
        y2error($__error{code});
    }
    return undef;
}

BEGIN { $TYPEINFO{Error} = ["function", ["map", "string", "any"] ]; }
sub Error {
    my $self = shift;
    return \%__error;
}

1;
