# test persistent http connection with request filter

use strict;
use warnings;

my @lengths = (251, 16384, 0, 1, 2, 3, 4, 5);
our %args = (
    client => {
	# relayd closes the connection on the first blocked request
	func => sub { eval { http_client(@_) }; warn $@ },
	lengths => \@lengths,
	loggrep => qr/Client missing http 2 response/,
    },
    relayd => {
	protocol => [ "http",
	    'request path filter "/2"',
	],
	loggrep => qr/rejecting request/,
    },
    server => {
	func => \&http_server,
    },
    lengths => [251, 16384, 0, 1],
    md5 => "bc3a3f39af35fe5b1687903da2b00c7f",
);

1;
