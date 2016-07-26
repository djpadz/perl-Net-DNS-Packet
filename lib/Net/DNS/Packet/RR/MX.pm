package Net::DNS::Packet::RR::MX;

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
    ($self->{'_pref'}) = unpack("x[$offset] n", $raw_data);
    $offset += 2;
    $self->{'_mx'} = Net::DNS::Packet::Name->new($raw_data, $offset);
    return $self;
}

sub f_preference() {
    my $self = shift;
    return $self->{'_pref'};
}

sub f_exchange() {
    my $self = shift;
    return $self->{'_mx'};
}

sub stringify() {
    my $self = shift;
    return sprintf '%d %s', $self->f_preference, $self->f_exchange->stringify;
}
1;
