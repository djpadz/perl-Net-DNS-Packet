package Net::DNS::Packet;

use strict;
use warnings;
use Carp;

use Net::DNS::Packet::FlagsAndCodes;
use Net::DNS::Packet::Question;
use Net::DNS::Packet::RR;

use overload '""' => 'stringify';

our $VERSION = 1.00;

sub new($) {
    my $class = shift;
    my $raw_data = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    $self->{'_raw'} = $raw_data;
    my @shorts = unpack('n6', $raw_data);
    return unless @shorts == 6;
    $self->{'_id'} = shift @shorts;
    $self->{'_fc'} = Net::DNS::Packet::FlagsAndCodes->new(shift @shorts);
    $self->{'_qdc'} = shift @shorts;
    $self->{'_anc'} = shift @shorts;
    $self->{'_nsc'} = shift @shorts;
    $self->{'_arc'} = shift @shorts;
    my $offset = 12;
    foreach (1..$self->{'_qdc'}) {
        my $q = Net::DNS::Packet::Question->new($raw_data, $offset);
        push @{$self->{'_q'}}, $q;
        $offset = $q->end_offset;
    }
    foreach my $t ('_anc', '_nsc', '_arc') {
        my ($ak) = $t =~ /^(_..)/;
        foreach (1..$self->{$t}) {
            my $rr = Net::DNS::Packet::RR->new($raw_data, $offset);
            push @{$self->{$ak}}, $rr;
            $offset = $rr->end_offset;
        }
    }
    return $self;
}

sub f_raw() {
    my $self = shift;
    return $self->{'_raw'};
}

sub f_id() {
    my $self = shift;
    return $self->{'_id'};
}

sub f_fc() {
    my $self = shift;
    return $self->{'_fc'};
}

sub f_qdcount() {
    my $self = shift;
    return $self->{'_qdc'};
}

sub f_ancount() {
    my $self = shift;
    return $self->{'_anc'};
}

sub f_nscount() {
    my $self = shift;
    return $self->{'_nsc'};
}

sub f_arcount() {
    my $self = shift;
    return $self->{'_arc'};
}

sub f_q() {
    my $self = shift;
    return $self->{'_q'};
}

sub f_an() {
    my $self = shift;
    return $self->{'_an'};
}

sub f_ns() {
    my $self = shift;
    return $self->{'_ns'};
}

sub f_ar() {
    my $self = shift;
    return $self->{'_ar'};
}

sub stringify() {
    my $self = shift;
    my $ret = sprintf 'id=%d; fc=%s; qc=%d; anc=%d; nsc=%d; arc=%d', $self->f_id, $self->f_fc->stringify, $self->f_qdcount, $self->f_ancount, $self->f_nscount, $self->f_arcount;
    foreach my $t ('_q', '_an', '_ns', '_ar') {
        my ($l) = $t =~ /^_(.*)/;
        $l = uc $l;
        next unless $self->{$t};
        foreach (@{$self->{$t}}) {
            $ret .= sprintf "\n\t%s: %s", $l, $_->stringify;
        }
    }
    return $ret;
}

1;
