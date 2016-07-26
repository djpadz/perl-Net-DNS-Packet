use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME		=> 'Net::DNS::Packet',
	DISTNAME	=> 'Net-DNS-Packet',
	AUTHOR		=> 'Dj Padzensky <djpadz@padz.net>',
	ABSTRACT	=> 'DNS Packet Picker Aparter',
	VERSION_FROM	=> 'lib/Net/DNS/Packet.pm',
	LICENSE		=> 'BSD',
);
