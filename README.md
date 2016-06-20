[![Build Status](https://secure.travis-ci.org/robn/Authen-U2F.png)](http://travis-ci.org/robn/Authen-U2F)

# NAME

Authen-U2F - FIDO U2F library

# SYNOPSIS

    use Authen::U2F qw(
      u2f_challenge
      u2f_registration_verify
      u2f_signature_verify);

    # Create a challenge to send to the U2F host
    my $challenge = u2f_challenge;

    # Process a registration response from the U2F host
    my ($key_handle, $key) = u2f_registration_verify(
      challenge         => $challenge,
      app_id            => $app_id,
      origin            => $origin,
      registration_data => $registration_data,
      client_data       => $client_data,
    );

    # Process a signing (authentication) response from the U2F host
    u2f_signature_verify(
      challenge      => $challenge,
      app_id         => $app_id,
      origin         => $origin,
      key_handle     => $key_handle,
      key            => $key,
      signature_data => $signature_data,
      client_data    => $client_data,
    );

    # Or, if you don't like to clutter up your namespace
    my $challenge = Authen::U2F->challenge;
    my ($key_handle, $key) = Authen::U2F->registration_verify(...);
    Authen::U2F->signature_verify(...);

# DESCRIPTION

This module provides the tools you need to add support for U2F in your
application.

It's expected that you know the basics of U2F. More information about this can
be found at [Yubico](https://www.yubico.com/about/background/fido/) and
[FIDO](https://fidoalliance.org/specifications/overview/).

This module does not handle the wire encoding of U2F challenges and response,
as these are different depending on the U2F host you're using and the style of
your application. In the `examples` dir there are scripts that implement the
1.0 wire format, used by [Yubico's libu2f-host](https://developers.yubico.com/libu2f-host/),
and a Plack application that works with
[Google's JavaScript module](https://github.com/google/u2f-ref-code/blob/master/u2f-gae-demo/war/js/u2f-api.js).

Sadly, the documentation around U2F is rather more confusing than it should be,
and this short description is probably not making things better. Please improve
this or write something about U2F so we can improve application security
everywhere.

# FUNCTIONS

There are three functions: One for generating challenges for the host to sign,
and one for processing the responses from the two types of signing requests U2F
supports.

There's straight function interface and a class method interface. Both do
exactly the same thing; which you use depends onhow much verbosity you like vs
how much namespace clutter you like. Only the functional interface is mentioned
in this section; see the [SYNOPSIS](https://metacpan.org/pod/SYNOPSIS) for the details.

## u2f\_challenge

    my $challenge = u2f_challenge;

Creates a challenge. A challenge is 256 cryptographically-secure random bits.

## u2f\_registration\_verify

Verify a registration response from the host against the challenge. If the
verification is successful, returns the key handle and public key of the device
that signed the challenge. If it fails, this function croaks with an error.

Takes the following options, all required:

- challenge

    The challenge originally given to the host.

- app\_id

    The application ID.

- origin

    The browser location origin. This is typically the same as the application ID.

- registration\_data

    The registration data blob from the host.

- client\_data

    The client data blob from the host.

## u2f\_signature\_verify

Verify a signature (authentication) response from the host against the
challenge. If the verification is successful, the user has presented a valid
device and is now authenticated. If the verification fails, this function
croaks with an error.

Takes the following options, all required.

- challenge

    The challenge originally given to the host.

- app\_id

    The application ID.

- origin

    The browser location origin. This is typically the same as the application ID.

- key\_handle

    The handle of the key that was used to sign the challenge.

- key

    The stored public key associated with the handle.

- signature\_data

    The signature data blob from the host.

- client\_data

    The client data blob from the host.

# SUPPORT

## Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at [https://github.com/robn/Authen-U2F/issues](https://github.com/robn/Authen-U2F/issues).
You will be notified automatically of any progress on your issue.

## Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.

[https://github.com/robn/Authen-U2F](https://github.com/robn/Authen-U2F)

    git clone https://github.com/robn/Authen-U2F.git

# AUTHORS

- Robert Norris <rob@eatenbyagrue.org>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2016 by Robert Norris.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
