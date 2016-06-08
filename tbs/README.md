Naming Conventions
==================

This directory holds files with suffix `.tbs`.  These files hold the inner
content of a certificate, specifically a `TBSCertificate` ASN.1 type, encoded
as ASCII in a form suitable for the ascii2der tool.

Certificate files have the following naming convention:

 - Certificates named with a leading `ok-` are assumed to be valid certificates.
 - Certificates named with a leading `xf-` are have some kind of error in
   their contents.  A description of the error is included in the
   `organizationName` of the `subject`, and a reference to the relevant spec
   section is included in the `locality` of the `subject`.

The `fragment` subdirectory holds common ASCII fragments of certificates,
which are pulled in with an additional `#include <filename>` directive.
