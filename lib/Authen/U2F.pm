package Authen::U2F;

# ABSTRACT: FIDO U2F library

use 5.010;
use warnings;
use strict;

use namespace::sweep;

use Types::Standard -types;
use Type::Params qw(compile);

use Math::Random::Secure qw(irand);
use MIME::Base64 qw(encode_base64);

sub generate_challenge {
  state $check = compile(
    ClassName,
  );
  my ($class) = $check->(@_);

  my $raw = pack "L*", map { irand } 1..8;
  my $challenge = encode_base64url($raw);
  return $challenge;
}

1;
