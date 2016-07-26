package Net::DNS::Packet::RR::AAAA;

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
    my @shorts = unpack("x[$offset] n8", $raw_data);
    return unless @shorts == 8;
    $self->{'_aaaa'} = \@shorts;
    return $self;
}

sub f_aaaa() {
    my $self = shift;
    return $self->{'_aaaa'};
}

sub stringify() {
    my $self = shift;
    my @bytes = unpack('CCCC', $self->f_a);
    return join(':', map { sprintf('%x', $_) } @{$self->{'_aaaa'}});
}

1;
