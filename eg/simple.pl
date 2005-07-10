use strict;
use warnings;
use Crypt::Dining;

my $dc = new Crypt::Dining(
	# LocalAddr	=> '192.168.3.16',
	Peers		=> [ '123.45.6.67', '62.53.7.2', '12.6.3.123' ],
);

$dc->round;
