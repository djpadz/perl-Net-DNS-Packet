package Net::DNS::Packet::RR;

use strict;
use warnings;
use Carp;

use overload '""' => 'stringify';

use Net::DNS::Packet::RR::A;
use Net::DNS::Packet::RR::AAAA;
use Net::DNS::Packet::RR::NS;
use Net::DNS::Packet::RR::CNAME;
use Net::DNS::Packet::RR::SOA;
use Net::DNS::Packet::RR::PTR;
use Net::DNS::Packet::RR::MX;
use Net::DNS::Packet::RR::TXT;

my @CLASSES = qw/?? IN CS CH HS/;

our %TYPES = (
    1 => 'A',
    2 => 'NS',
    5 => 'CNAME',
    6 => 'SOA',
    12 => 'PTR',
    15 => 'MX',
    16 => 'TXT',
    28 => 'AAAA',
);

sub new($$) {
    my $class = shift;
    my $raw_data = shift;
    my $offset = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    $self->{'_name'} = Net::DNS::Packet::Name->new($raw_data, $offset);
    $offset = $self->{'_name'}->end_offset;
    my @nums = unpack("x[$offset] nnNn", $raw_data);
    return unless @nums == 4;
    ($self->{'_type'}, $self->{'_class'}, $self->{'_ttl'}, $self->{'_rdlength'}) = @nums;
    $offset += 10;
    $self->{'_end_offset'} = $offset + $self->{'_rdlength'};
    if ($self->f_type_s !~ /^\?\?\?/) {
        no strict 'refs';
        my $klass = 'Net::DNS::Packet::RR::' . $self->f_type_s;
        $self->{'_rdata'} = $klass->new($raw_data, $offset, $self->{'_rdlength'});
    }
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

sub f_type() {
    my $self = shift;
    return $self->{'_type'};
}

sub f_type_s() {
    my $self = shift;
    my $ft = $self->f_type;
    return $TYPES{$ft} ? $TYPES{$ft} : "??? ($ft)";
}

sub f_class() {
    my $self = shift;
    return $self->{'_class'};
}

sub f_class_s() {
    my $self = shift;
    my $fc = $self->f_class;
    return $CLASSES[$fc] ? $CLASSES[$fc] : "??? ($fc)";
}

sub f_ttl() {
    my $self = shift;
    return $self->{'_ttl'};
}

sub f_rdlength() {
    my $self = shift;
    return $self->{'_rdlength'};
}

sub f_rdata() {
    my $self = shift;
    return $self->{'_rdata'};
}

sub end_offset() {
    my $self = shift;
    return $self->{'_end_offset'};
}

sub stringify() {
    my $self = shift;
    return sprintf '%s %d %s %s %s', $self->f_name, $self->f_ttl, $self->f_class_s, $self->f_type_s, $self->{'_rdata'} ? $self->{'_rdata'}->stringify : '???';
}

1;
