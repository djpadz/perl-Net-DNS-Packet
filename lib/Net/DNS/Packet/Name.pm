package Net::DNS::Packet::Name;

use strict;
use warnings;
use Carp;

use overload '""' => 'stringify';

sub _get_strings($$);
sub _get_strings($$) {
    my $bindat = shift;
    my $ptr = shift;
    my @strings;
    while (1) {
        my ($len) = unpack("x[$ptr] C", $bindat);
        last unless $len;
        if ($len > 63) {
            my ($val) = unpack("x[$ptr] n", $bindat);
            $val &= 0x3fff;
            push @strings, @{_get_strings($bindat, $val)};
            ++$ptr;
            last;
        }
        ++$ptr;
        my ($str) = unpack("x[$ptr] A[$len]", $bindat);
        push @strings, $str;
        $ptr += length($str);
    }
    return (++$ptr, \@strings);
}

sub new($$) {
    my $class = shift;
    my $raw_data = shift;
    my $offset = shift;
    croak 'Constructor called on existing object instead of class' if ref $class;
    my $self = {};
    bless $self, $class;
    my ($end_offset, $strings) = _get_strings($raw_data, $offset);
    $self->{'_strings'} = $strings;
    $self->{'_end_offset'} = $end_offset;
    return $self;
}

sub strings() {
    my $self = shift;
    my @strings = @{$self->{'_strings'}};
    return wantarray ? @strings : \@strings;
}

sub stringify() {
    my $self = shift;
    return join('.', @{$self->strings});
}

sub end_offset() {
    my $self = shift;
    return $self->{'_end_offset'};
}
1;
