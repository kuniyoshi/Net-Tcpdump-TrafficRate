use 5.10.0;
use strict;
use warnings;
package Net::Tcpdump::TrafficRate;
use Data::Dumper;
use Readonly;

Readonly my $RE => qr{
    \A
    (?<datetime>\d+:\d+:\d+\.\d+) \s
    IP \s
    (?<source_ip_port>[.\d]+) \s
    [>] \s
    (?<destination_ip_port>[.\d]+): \s
    .*
    \s length \s (?<length>\d+)
}msx;

our $VERBOSE;

sub __split_into_ip_and_port {
    my $ip_port = shift;
    my @nums = split m{\.}, $ip_port;
    my $ip = join q{.}, @nums[ 0 .. 3 ];
    my $port = $nums[4];
    return ( $ip, $port );
}


sub __parse_line {
    my $line         = shift;
    my $cardinal_ip  = shift;
    my $get_role_sub = shift;
    my %packet;

    if ( $line !~ m{$RE} ) {
        return;
    }
    else {
        %packet = %+;
        @packet{ qw( source_ip source_port ) }           = __split_into_ip_and_port( $packet{source_ip_port} );
        @packet{ qw( destination_ip destination_port ) } = __split_into_ip_and_port( $packet{destination_ip_port} );

        $packet{length} += 20; # add header size
    }

    return %packet;
}

sub read_tcpdump {
    my( $filename, $cardinal_ip ) = @_;
    my %in;
    my %out;

    open my $FH, "tcpdump -n -nn -r $filename |"
        or die "Could not run tcpdump from filename[$filename]: $!";

    while ( <$FH> ) {
        chomp( my $line = $_ );

        my %packet = __parse_line( $line, $cardinal_ip );

        warn "Could not parse [$line]"
            if $VERBOSE && !%packet;

        next
            unless %packet;

        if ( $packet{source_ip} eq $cardinal_ip ) {
            $out{ $packet{destination_ip} } += $packet{length};
        }
        elsif ( $packet{destination_ip} eq $cardinal_ip ) {
            $in{ $packet{source_ip} } += $packet{length};
        }
        else {
            warn "unknown ip ", Data::Dumper->new( [ \%packet ] )->Terse( 1 )->Sortkeys( 1 )->Indent( 0 )->Dump
                if $VERBOSE;
        }
    }

    close $FH
        or die "Could not close tcpdump: $!";

    return { in => \%in, out => \%out };
}

1;
