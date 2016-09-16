X.509 Test
==========

This project helps with the testing of X.509 PKIX (RFC5280) implementations,
by providing test certificates and automation.

The original idea for this project was to work through the text of
[RFC5280](third_party/ietf/rfc5280.txt) and create an invalid test certificate
corresponding to each MUST or SHOULD clause in the RFC.  These invalid
certificates are then signed by a fake CA, and can be fed to various TLS
implementations to see whether they are accepted.

Prerequisites
-------------

This project relies on the following tools being present in the `PATH`:

 - the `ascii2der` and `der2ascii` tools from the [der-ascii](https://github.com/google/der-ascii) open source project
 - the `openssl` binary.

Operation
---------

The project is built from the top-level [`Makefile`](Makefile), where the
master `check` target will:

 - Create a private key (`ca/fake-ca.private.pem`) for the fake CA, and build
   a corresponding CA certificate (in `ca/fake-ca.cert`).
 - Build a complete certificate for each test case (in `tbs/*.tbs`), signed by
   the fake CA (in `certs/` or `certs2/`).
 - Run each certificate through various different TLS implementations, saving
   the output (in `results/$TOOL/*.out`).
 - Emit a summary of verification failures.

Project Layout
--------------

The project is organized as follows.

 - The `tbs/` directory holds the test certificates, in the form of ASCII
   files suitable for feeding to the
   [`ascii2der`]((https://github.com/google/der-ascii) tool. These
   certificates are in the form of the `TBSCertificate` ASN.1 type, and they
   pull in shared common fragments (from the `tbs/fragment/` subdirectory)
   using a `#include` extension to the ASCII format.
 - The `tbs2/` directory holds pairs of certificates where the leaf
   certificate (`*.leaf.tbs`) is signed by an intermediate CA certificate
   (`*.ca.tbs`).
 - The `scripts/` directory holds scripts that allow the certificates to be
   fed to the different TLS implementations and their results checked.
 - The `cfg/` directory holds additional configuration files, e.g. for
   controlling OpenSSL's certificate generation process.
 - The `third_party/ietf/` holds local copies of the relevant specifications
   and RFCs.

Disclaimer
----------

This is not an official Google product.
