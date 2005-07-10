package Crypt::Dining;

use strict;
use warnings;
use vars qw($VERSION $PORT $PACKETSZ);
# use Data::Dumper;
use IO::Socket::INET;
use Crypt::Random qw(makerandom);
use YAML;
use Net::Address::IPv4::Local;

$VERSION = '1.00';
$PORT = 17355;
$PACKETSZ = 1024;

sub new {
	my $class = shift;
	my $self = ($#_ == 0) ? { %{ (shift) } } : { @_ };

	unless ($self->{LocalPort}) {
		$self->{LocalPort} = $PORT;
	}

	unless ($self->{LocalAddr}) {
		$self->{LocalAddr} = Net::Address::IPv4::Local->public;
	}

	my $this = $self->{LocalAddr} . ":" . $self->{LocalPort};

	my @peers = @{ $self->{Peers} };
	foreach (0..$#peers) {
		$peers[$_] .= ":$PORT" unless $peers[$_] =~ /:/;
	}
	@peers = sort { $a cmp $b } @peers;

	my $next = $peers[0];
	my $prev = $peers[-1];
	PEER: foreach (@peers) {
		if ($this lt $_) {
			$next = $_;
			last PEER;
		}
		$prev = $_;
	}

	# print "Peers are " . Dumper(\@peers);
	# print "Prev is $prev\n";
	# print "This is $this\n";
	# print "Next is $next\n";

	$self->{Peers} = \@peers;

	$prev =~ m/(.*):(.*)/
		or die "No address:port in $prev";
	$self->{PrevAddr} = $1;
	$self->{PrevPort} = $2;

	$next =~ m/(.*):(.*)/
		or die "No address:port in $next";
	$self->{NextAddr} = $1;
	$self->{NextPort} = $2;

	return bless $self, $class;
}

sub socket_udp {
	my ($self) = @_;
	unless ($self->{SocketUdp}) {
		$self->{SocketUdp} = new IO::Socket::INET(
			Proto		=> "udp",
			LocalAddr	=> $self->{LocalAddr},
			LocalPort	=> $self->{LocalPort},
			ReuseAddr	=> 1,
			# Listen		=> 5,
		)
			or die "socket: $self->{LocalAddr}:$self->{LocalPort}: $!";
	}
	return $self->{SocketUdp};
}

sub listen_prev {
	my ($self) = @_;
	$self->socket_udp();
}

sub send_next {
	my ($self, $data) = @_;
	my $socket = $self->socket_udp();
	my $addr = sockaddr_in($self->{NextPort}, inet_aton($self->{NextAddr}));
	return $socket->send($data, 0, $addr);
}

sub send_all {
	my ($self, $data) = @_;
	my $socket = $self->socket_udp();
	foreach (@{ $self->{Peers} }) {
		m/(.*):(.*)/ or die "Invalid peer: $_: No host:port";
		my ($host, $port) = ($1, $2);
		my $addr = sockaddr_in($port, inet_aton($host));
		$socket->send($data, 0, $addr);
	}
}

sub recv_prev {
	my ($self) = @_;
	my $socket = $self->socket_udp();

	my $data;
	my $addr = $socket->recv($data, $PACKETSZ);
	my ($port, $iaddr) = sockaddr_in($addr);
	die "Unexpected packet from $iaddr"
			unless $iaddr eq $self->{PrevAddr};
	return $data;
}

sub recv_all {
	my ($self) = @_;
	my $socket = $self->socket_udp();

	my %data;
	foreach (@{ $self->{Peers} }) {
		my $data;
		my $addr = $socket->recv($data, $PACKETSZ);
		$data{$_} = $data;
	}

	return %data;
}

sub round {
	my ($self, $message) = @_;

	my $random = makerandom(
		Size		=> 8 * $PACKETSZ,	# 1Kb
		Strength	=> 0,
	);

	my %packet = (
		Type	=> "coin",
		Value	=> $random,
	);
	$self->send_next(Dump(\%packet));

	my $packetref = Load($self->recv_prev());
	die "Didn't get a coin packet"
			unless $packetref->{Type} eq 'coin';
	die "Bad length for received coin data"
			unless $packetref->{Value} eq $PACKETSZ;
	my $store = $packetref->{Value} ^ $random;
	$store ^= $message if $message;

	%packet = (
		Type	=> "hand",
		Value	=> $store,
	);
	$self->send_all(Dump(\%packet));

	my %answers = $self->recv_all();
	my $answer = $store;
	foreach (keys %answers) {
		$packetref = Load($answers{$_});
		die "Didn't get a hand packet from $_"
				unless $packetref->{Type} eq 'hand';
		die "Bad length for received hand data"
				unless $packetref->{Value} eq $PACKETSZ;
		$answer ^= $packetref->{Value};
	}

	return $answer;
}

=head1 NAME

Crypt::Dining - The Dining Cryptographers' Protocol

=head1 SYNOPSIS

	my $dc = new Crypt::Dining(
		LocalAddr	=> '123.45.6.7',
		Peers		=> [ '123.45.6.8', ... ],
			);
	my $answer = $dc->round;
	my $answer = $dc->round("hello");

=head1 DESCRIPTION

The dining cryptographers' protocol is documented in Bruce
Schneier's book as a kind of "cryptographic ouija board". It works
as follows:

A number of cryptographers are dining at a circular table. At the end
of the meal, the waiter is summoned and asked for the bill. He replies,
"Thank you, sir. The bill has been paid." The cryptographers now have
the problem of working out whether someone at the table paid the bill,
or whether the NSA has paid it as some sort of veiled threat. The
protocol proceeds.

Each cryptographer flips a coin, and shows the result ONLY to the
participant on his RIGHT. Each cryptographer then compares his coin
with that on his LEFT, and raises his hand if they show different
faces. If any participant paid the bill, he "cheats" and does the
opposite, that is, he raises his hand if the coins show the same
face. Now, the hands are counted. An odd number means that someone
at the table paid the bill. An even number means that the NSA paid.

=head1 ASSUMPTIONS AND IMPLEMENTATION

At most one person "cheats" at any time, otherwise the message is
scrambled. Detecting scrambling is only possible with multi-bit
messages containing a checksum.

The comparison operator described above is the XOR operator on
single-bit values. If the protocol is performed with multi-bit
messages, then the XOR is still used.

=head1 WIKIPEDIA DESCRIPTION

The following description is copied from
L<http://en.wikipedia.org/wiki/Dining_cryptographers_protocol> and
is redistributed under the GNU Free Documentation License. It is
a very slightly different protocol to that implemented here, but the
result is the same.

The dining cryptographers protocol is a method of anonymous
communication. It offers untraceability of both the sender and the
recipient.

The method is as follows: two or more cryptographers arrange
themselves around a circular dinner table, with menus hiding the
interaction of each pair of adjacent cryptographers from the rest.
Each adjacent pair picks a random number in private. Then each
cryptographer announces publicly the difference between the number
on his right and the number on his left, adding a message if he
wants to transmit one. All cryptographers then add up the publicly
announced numbers. If the sum is 0, no one sent a message. If the
sum is a valid message, one cryptographer transmitted a message. If
the sum is invalid, more than one cryptographer tried to transmit a
message; they wait a random time and try again.

=head1 BUGS

If the send_*() and recv_*() methods are overridden to use TCP sockets
with very large messages, deadlock may occur around the ring unless
something intelligent is done with select().

=head1 SEE ALSO

L<http://en.wikipedia.org/wiki/Dining_cryptographers_protocol>,
L<Crypt::Chimera> - another cryptographic curiosity.

=head1 COPYRIGHT

Copyright (c) 2005 Shevek. All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
