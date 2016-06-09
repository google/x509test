X.509 Test
==========

This project helps with the testing of X.509 PKIX (RFC5280) implementations,
by providing test certificates and automation.

The original idea for this project was to work through the text of
[RFC5280](third_party/ietf/rfc5280.txt) and create an invalid test certificate
corresponding to each MUST or SHOULD clause in the RFC.  These invalid
certificates are then signed by a fake CA, and fed to a number of TLS
implementations to see whether they are accepted.

Prerequisites
-------------

This project relies on the `ascii2der` and `der2ascii` tools from the
[der-ascii](https://github.com/google/der-ascii) open source project being in
the `PATH`.  It also requires the `openssl` binary to be present (although a
locally built version can be used, see below).

Operation
---------

The project is built from the top-level [`Makefile`](Makefile), where the
master `check` target will:

 - Create a private key (`ca/fake-ca.private.pem`) for the fake CA, and build
   a corresponding CA certificate (in `ca/fake-ca.cert`).
 - Build a complete certificate for each test case (in `tbs/*.tbs`), signed by
   the fake CA (in `certs/*.pem`).
 - Run each certificate through various different TLS implementations, saving
   the output (in `results/$TOOL/$TLS/*.out`).
 - Emit a summary of verification failures.

By default, this process will attempt to use installed versions of the TLS
tools in the `PATH`, but this depends on the `TLS` environment value.

 - `TLS=installed` uses installed versions of the TLS tools
 - `TLS=tip` uses locally-built versions of the TLS tools, based on their
   current code versions, expected to exist in
   `third_party/tip/instroot/bin/`.
 - `TLS=stable` uses locally-built versions of the TLS tools, based on their
   most recent stable versions, expected to exist in
   `third_party/stable/instroot/bin/`.

Local TLS Builds
----------------

The `make deps` target will attempt to provide the TLS tools for the project.
If `TLS=stable` this attempts to perform a Debian install of the relevant
packages; if `TLS` is `tip` or `stable`, it will attempt to:

  - Download the relevant source code (the `make tls-tip-src` or `make
    tls-stable-src` target) locally.
  - Build the source code (the `make tls-tip-bld` or `make tls-stable-bld`
    target).
  - Install the built binaries to the local `third_party/$TLS/instroot/bin/`
    directory (the `make tls-tip-inst` or `make tls-stable-inst` target).


Project Layout
--------------

The project is organized as follows.

 - The `tbs/` directory holds the test certificates, in the form of ASCII
   files suitable for feeding to the
   [`ascii2der`]((https://github.com/google/der-ascii) tool. These
   certificates are in the form of the `TBSCertificate` ASN.1 type, and they
   pull in shared common fragments (from the `tbs/fragment/` subdirectory)
   using a `#include` extension to the ASCII format.
 - The `scripts/` directory holds scripts that allow the certificates to be
   fed to the different TLS implementations and their results checked.
 - The `cfg/` directory holds additional configuration files, e.g. for
   controlling OpenSSL's certificate generation process.
 - The `third_party/` directory holds code and resources that are external to
   the project.
    - `third_party/ietf/` holds local copies of the relevant specifications
      and RFCs.
    - `third_party/tip/` holds downloaded copies of TLS implementations, using
      the most current available code.
    - `third_party/stable/` holds downloaded copies of TLS implementations, using
      the most recent stable releases.
    - `third_party/common/` holds common build infrastructure for local copies
      of TLS implementations.

Disclaimer
----------

This is not an official Google product.
