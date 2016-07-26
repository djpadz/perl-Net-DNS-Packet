package Net::DNS::Packet::RR::PTR;

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
    $self->{'_ptr'} = Net::DNS::Packet::Name->new($raw_data, $offset);
    return $self;
}

sub f_ptrdname() {
    my $self = shift;
    return $self->{'_ptr'};
}

sub stringify() {
    my $self = shift;
    return $self->f_ptrdname->stringify;
}
1;
