package Authen::U2F;

# ABSTRACT: FIDO U2F library

use 5.010;
use warnings;
use strict;

use namespace::sweep;

use Types::Standard -types, qw(slurpy);
use Type::Params qw(compile);
use Try::Tiny;
use Carp qw(croak);

use Math::Random::Secure qw(irand);
use MIME::Base64 qw(encode_base64url decode_base64url);
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use Digest::SHA qw(sha256);
use JSON qw(decode_json);

use parent 'Exporter::Tiny';
our @EXPORT_OK = qw(u2f_challenge u2f_registration_verify u2f_signature_verify);

sub u2f_challenge           { __PACKAGE__->challenge(@_) }
sub u2f_registration_verify { __PACKAGE__->registration_verify(@_) }
sub u2f_signature_verify    { __PACKAGE__->signature_verify(@_) }

sub challenge {
  state $check = compile(
    ClassName,
  );
  my ($class) = $check->(@_);

  my $raw = pack "L*", map { irand } 1..8;
  my $challenge = encode_base64url($raw);
  return $challenge;
}

sub registration_verify {
  state $check = compile(
    ClassName,
    slurpy Dict[
      challenge         => Str,
      app_id            => Str,
      origin            => Str,
      registration_data => Str,
      client_data       => Str,
    ],
  );
  my ($class, $args) = $check->(@_);

  my $client_data = decode_base64url($args->{client_data});
  croak "couldn't decode client data; not valid Base64-URL?"
    unless $client_data;

  {
    my $data = decode_json($client_data);
    croak "invalid client data (challenge doesn't match)"
      unless $data->{challenge} eq $args->{challenge};
    croak "invalid client data (origin doesn't match)"
      unless $data->{origin} eq $args->{origin};
  }

  my $reg_data = decode_base64url($args->{registration_data});
  croak "couldn't decode registration data; not valid Base64-URL?"
    unless $reg_data;

  # $reg_data is packed like so:
  #
  # 1-byte  reserved (0x05)
  # 65-byte public key
  # 1-byte  key handle length
  #         key handle
  #         attestation cert
  #           2-byte DER type
  #           2-byte DER length
  #           DER payload
  #         signature

  my ($reserved, $key, $handle, $certtype, $certlen, $certsig) = unpack 'a a65 C/a n n a*', $reg_data;

  croak "invalid registration data (reserved byte != 0x05)"
    unless $reserved eq chr(0x05);

  croak "invalid registration data (key length != 65)"
    unless length($key) == 65;

  # extract the cert payload from the trailing data and repack
  my $certraw = substr $certsig, 0, $certlen;
  croak "invalid registration data (incorrect cert length)"
    unless length($certraw) == $certlen;
  my $cert = pack "n n a*", $certtype, $certlen, $certraw;

  # signature at end of the trailing data
  my $sig  = substr $certsig, $certlen;

  my $x509 = try {
    Crypt::OpenSSL::X509->new_from_string($cert, Crypt::OpenSSL::X509::FORMAT_ASN1);
  }
  catch {
    croak "invalid registration data (certificate parse failure: $_)";
  };

  my $pkec = try {
    Crypt::PK::ECC->new(\$x509->pubkey);
  }
  catch {
    croak "invalid registration data (certificate public key parse failure: $_)";
  };

  # signature data. sha256 of:
  #
  # 1-byte  reserved (0x00)
  # 32-byte sha256(app ID)                      (application parameter)
  # 32-byte sha256(client data (JSON-encoded))  (challenge parameter)
  #         key handle
  # 65-byte key

  my $app_id_sha = sha256($args->{app_id});
  my $challenge_sha = sha256($client_data);

  my $sigdata = pack "x a32 a32 a* a65", $app_id_sha, $challenge_sha, $handle, $key;
  my $sigdata_sha = sha256($sigdata);

  $pkec->verify_hash($sig, $sigdata_sha)
    or croak "invalid registration data (signature verification failed)";

  my $enc_key = encode_base64url($key);
  my $enc_handle = encode_base64url($handle);

  return ($enc_handle, $enc_key);
}

sub signature_verify {
  state $check = compile(
    ClassName,
    slurpy Dict[
      challenge      => Str,
      app_id         => Str,
      origin         => Str,
      key_handle     => Str,
      key            => Str,
      signature_data => Str,
      client_data    => Str,
    ],
  );
  my ($class, $args) = $check->(@_);

  my $key = decode_base64url($args->{key});
  croak "couldn't decode key; not valid Base64-URL?"
    unless $key;

  my $pkec = Crypt::PK::ECC->new;
  try {
    $pkec->import_key_raw($key, "nistp256");
  }
  catch {
    croak "invalid key argument (parse failure: $_)";
  };

  my $client_data = decode_base64url($args->{client_data});
  croak "couldn't decode client data; not valid Base64-URL?"
    unless $client_data;

  {
    my $data = decode_json($client_data);
    croak "invalid client data (challenge doesn't match)"
      unless $data->{challenge} eq $args->{challenge};
    croak "invalid client data (origin doesn't match)"
      unless $data->{origin} eq $args->{origin};
  }

  my $sign_data = decode_base64url($args->{signature_data});
  croak "couldn't decode signature data; not valid Base64-URL?"
    unless $sign_data;

  # $sig_data is packed like so
  #
  # 1-byte  user presence
  # 4-byte  counter (big-endian)
  #         signature

  my ($presence, $counter, $sig) = unpack 'a N a*', $sign_data;

  # XXX presence check

  # XXX counter check

  # signature data. sha256 of:
  #
  # 32-byte sha256(app ID)                      (application parameter)
  # 1-byte  user presence
  # 4-byte  counter (big endian)
  # 32-byte sha256(client data (JSON-encoded))  (challenge parameter)

  my $app_id_sha = sha256($args->{app_id});
  my $challenge_sha = sha256($client_data);

  my $sigdata = pack "a32 a N a32", $app_id_sha, $presence, $counter, $challenge_sha;
  my $sigdata_sha = sha256($sigdata);

  $pkec->verify_hash($sig, $sigdata_sha)
    or croak "invalid signature data (signature verification failed)";

  return;
}

1;
