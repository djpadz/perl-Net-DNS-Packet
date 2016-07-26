package Net::DNS::Packet::Question;

use strict;
use warnings;
use Carp;

use overload '""' => 'stringify';

use Net::DNS::Packet::Name;
use Net::DNS::Packet::RR;

my %QTYPES = %Net::DNS::Packet::RR::TYPES;
$QTYPES{251} = 'IXFR';
$QTYPES{252} = 'AXFR';
$QTYPES{253} = 'MAILB';
$QTYPES{254} = 'MAILA';
$QTYPES{255} = '*';

my @CLASSES = qw/?? IN CS CH HS/;

sub new($) {
    my $class = shift;
    my $raw_data = shift;
    my $offset = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    $self->{'_name'} = Net::DNS::Packet::Name->new($raw_data, $offset);
    $offset = $self->{'_name'}->end_offset;
    my @shorts = unpack("x[$offset] n2", $raw_data);
    return unless @shorts == 2;
    ($self->{'_qt'}, $self->{'_qc'}) = @shorts;
    $offset += 4;
    $self->{'_end_offset'} = $offset;
    return $self;
}

sub f_name() {
    my $self = shift;
    return $self->{'_name'};
}

sub f_name_s() {
    my $self = shift;
    return $self->f_name->stringify;
}

sub f_qtype() {
    my $self = shift;
    return $self->{'_qt'};
}

sub f_qtype_s() {
    my $self = shift;
    my $qt = $self->f_qtype;
    return $QTYPES{$qt} ? $QTYPES{$qt} : "??? ($qt)";
}

sub f_qclass() {
    my $self = shift;
    return $self->{'_qc'};
}

sub f_qclass_s() {
    my $self = shift;
    my $qc = $self->f_qclass;
    return '*' if $qc == 255;
    return $CLASSES[$qc] ? $CLASSES[$qc] : "??? ($qc)";
}

sub end_offset() {
    my $self = shift;
    return $self->{'_end_offset'};
}

sub stringify() {
    my $self = shift;
    return sprintf '%s %s %s', $self->f_name_s, $self->f_qclass_s, $self->f_qtype_s;
}
1;
