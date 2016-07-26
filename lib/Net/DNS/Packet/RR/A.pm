package Net::DNS::Packet::RR::A;

use strict;
use warnings;
use Carp;

use overload '""' => 'stringify';

sub new($$$) {
    my $class = shift;
    my $raw_data = shift;
    my $offset = shift;
    my $length = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    ($self->{'_a'}) = unpack("x[$offset] N", $raw_data);
    return $self;
}

sub f_a() {
    my $self = shift;
    return $self->{'_a'};
}

sub stringify() {
    my $self = shift;
    my @bytes = unpack('CCCC', $self->f_a);
    return sprintf('%d.%d.%d.%d', @bytes);
}
1;
