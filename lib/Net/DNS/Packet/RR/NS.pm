package Net::DNS::Packet::RR::NS;

use strict;
use warnings;
use Carp;

use overload '""' => 'stringify';

use Net::DNS::Packet::Name;

sub new($$$) {
    my $class = shift;
    my $raw_data = shift;
    my $offset = shift;
    my $length = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    $self->{'_ns'} = Net::DNS::Packet::Name->new($raw_data, $offset);
    return $self;
}

sub f_nsdname() {
    my $self = shift;
    return $self->{'_ns'};
}

sub stringify() {
    my $self = shift;
    return $self->f_nsdname->stringify;
}
1;
