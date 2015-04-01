#!/usr/bin/perl -s
use 5.10.0;
use utf8;
use strict;
use warnings;
use open qw( :std :utf8 );
use autodie qw( open close );
use Data::Dumper;
use Memoize;
use List::Util qw( sum first );
use Path::Class ( );
use lib "lib";
use Net::Tcpdump::TrafficRate;

memoize "get_role";

$Data::Dumper::Terse    = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

our $ip_host_map;
our $role_prefix;
our $dumpfile;
our $cardinal;
our $verbose;

die "usage: $0 [-verbose] -ip_host_map=<map file> -role_prefix=<prefix file> -dumpfile=<dumpfile> -cardinal=<dumpfile from what host>"
    if !$ip_host_map || !$role_prefix || !$dumpfile || !$cardinal;

$Net::Tcpdump::TrafficRate::VERBOSE = $verbose;

my %host   = read_map( $ip_host_map );
my %ip     = reverse %host;
my %role   = read_role( $role_prefix );

my $align_size_ref = Net::Tcpdump::TrafficRate::read_tcpdump( $dumpfile, $ip{ $cardinal } );
my %in  = %{ $align_size_ref->{in} };
my %out = %{ $align_size_ref->{out} };

merge_by_role( \%in );
convert_to_rate( \%in );
say "in";
print_rate_tidy( \%in );

merge_by_role( \%out );
convert_to_rate( \%out );
say "out";
print_rate_tidy( \%out );

exit;

sub print_rate_tidy {
    my $size_ref = shift;
    for my $key ( sort keys %{ $size_ref } ) {
        printf "%s: %.4f\n", $key, $size_ref->{ $key };
    }
    return;
}

sub convert_to_rate {
    my $size_ref = shift;
    my $sum = sum( values %{ $size_ref } );
    $_ /= $sum
        for values %{ $size_ref };
    return;
}

sub merge_by_role {
    my $size_ref = shift;
    for my $ip ( keys %{ $size_ref } ) {
        $size_ref->{ get_role( $host{ $ip } ) } += delete $size_ref->{ $ip };
    }
    return;
}

sub get_role {
    my $name = shift
        or return "other";

    my $prefix = first { 0 == index $name, $_ } keys %role;

    if ( !$prefix ) {
        warn "unknown"
            if $verbose;
        return "other";
    }

    return $role{ $prefix };
}

sub read_role {
    my $filename = shift;
    my %role;

    my @lines = Path::Class::file( $filename )->slurp( chomp => 1 );

    for my $line ( @lines ) {
        my( $prefix, $role ) = split m{\t}, $line;
        $role{ $prefix } = $role;
    }

    return %role;
}

sub read_map {
    my $filename = shift;
    my %map;

    my @lines = Path::Class::file( $filename )->slurp( chomp => 1 );

    for my $line ( @lines ) {
        my( $key, $value ) = split m{\t}, $line;

        $map{ $key } = $value;
    }

    return %map;
}
