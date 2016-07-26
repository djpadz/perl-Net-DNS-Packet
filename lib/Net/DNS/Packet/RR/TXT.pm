package Net::DNS::Packet::RR::TXT;

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
    ($self->{'_txt'}) = unpack("x[$offset] A[$length]", $raw_data);
    return $self;
}

sub f_txt() {
    my $self = shift;
    return $self->{'_txt'};
}

sub stringify() {
    my $self = shift;
    return $self->f_txt;
}
1;
