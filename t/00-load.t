#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Net::DNS::Packet' ) || print "Bail out!\n";
}

diag( "Testing Net::DNS::Packet $Net::DNS::Packet::VERSION, Perl $], $^X" );

1;
