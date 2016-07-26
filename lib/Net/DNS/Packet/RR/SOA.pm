package Net::DNS::Packet::RR::SOA;

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
    my $mname = Net::DNS::Packet::Name->new($raw_data, $offset);
    $offset = $mname->end_offset;
    my $rname = Net::DNS::Packet::Name->new($raw_data, $offset);
    $offset = $rname->end_offset;
    my @longs = unpack("x[$offset] N5", $raw_data);
    return unless @longs == 5;
    $self->{'_mname'} = $mname;
    $self->{'_rname'} = $rname;
    ($self->{'_ser'}, $self->{'_ref'}, $self->{'_ret'}, $self->{'_exp'}, $self->{'_min'}) = @longs;
    return $self;
}

sub f_mname() {
    my $self = shift;
    return $self->{'_mname'};
}

sub f_rname() {
    my $self = shift;
    return $self->{'_rname'};
}

sub f_serial() {
    my $self = shift;
    return $self->{'_ser'};
}

sub f_refresh() {
    my $self = shift;
    return $self->{'_ref'};
}

sub f_retry() {
    my $self = shift;
    return $self->{'_ret'};
}

sub f_expire() {
    my $self = shift;
    return $self->{'_exp'};
}

sub f_minimum() {
    my $self = shift;
    return $self->{'_min'};
}

sub stringify() {
    my $self = shift;
    return sprintf '%s %s (%d %d %d %d %d)', $self->f_mname->stringify, $self->f_rname->stringify, $self->f_serial, $self->f_refresh, $self->f_retry, $self->f_expire, $self->f_minimum;
}
1;
