package Net::DNS::Packet::FlagsAndCodes;

use strict;
use warnings;
use Carp;

my @OPCODES = qw/QUERY IQUERY STATUS (reserved) NOTIFY UPDATE/;

my @RCODES = qw/NOERR FORMERR SERVFAIL NXDOMAIN NOTIMP REFUSED YXDOMAIN TXRRSET NXRRSET NOTAUTH NOTZONE/;

sub new($) {
    my $class = shift;
    my $fc = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    $self->{'_raw'} = $fc;
    $self->{'_qr'} = ($fc >> 15) & 0x01;
    $self->{'_op'} = ($fc >> 11) & 0x0f;
    $self->{'_aa'} = ($fc >> 10) & 0x01;
    $self->{'_tc'} = ($fc >> 9) & 0x01;
    $self->{'_rd'} = ($fc >> 8) & 0x01;
    $self->{'_ra'} = ($fc >> 7) & 0x01;
    $self->{'_zero'} = ($fc >> 4) & 0x07;
    $self->{'_rcode'} = $fc & 0x0f;
    return $self;
}

sub f_raw() {
    my $self = shift;
    return $self->{'_raw'};
}

sub f_qr() {
    my $self = shift;
    return $self->{'_qr'};
}

sub is_query() {
    my $self = shift;
    return ! $self->f_qr;
}

sub is_response() {
    my $self = shift;
    return $self->f_qr;
}

sub f_opcode() {
    my $self = shift;
    return $self->{'_op'};
}

sub f_opcode_s() {
    my $self = shift;
    return $OPCODES[$self->f_opcode] ? $OPCODES[$self->f_opcode] : '???';
}

sub f_aa() {
    my $self = shift;
    return $self->{'_aa'};
}

sub is_authoritative() {
    my $self = shift;
    return $self->f_aa;
}

sub f_tc() {
    my $self = shift;
    return $self->{'_tc'};
}

sub is_truncated() {
    my $self = shift;
    return $self->f_tc;
}

sub f_rd() {
    my $self = shift;
    return $self->{'_rd'};
}

sub is_recursion_desired() {
    my $self = shift;
    return $self->f_rd;
}

sub f_zero() {
    my $self = shift;
    return $self->{'_zero'};
}

sub f_rcode() {
    my $self = shift;
    return $self->{'_rcode'};
}

sub f_rcode_s() {
    my $self = shift;
    return $RCODES[$self->f_rcode] ? $RCODES[$self->f_rcode] : '???';
}
1;
