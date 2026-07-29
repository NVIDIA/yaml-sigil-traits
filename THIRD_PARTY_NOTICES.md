# Third-Party Notices

NVIDIA-authored `yaml-sigil-traits` material is licensed under the Apache
License 2.0. The following notices apply only to the identified third-party
material. That material remains subject to its source terms and is not
relicensed under Apache-2.0.

Identification of a source does not imply affiliation with or endorsement by
its authors, publishers, standards organizations, or copyright holders.
`yaml-sigil-traits` is not an IETF RFC, an IRTF publication, or a Standards
for Efficient Cryptography Group (SECG) publication.

## Pinned YamlSigil specification

The `source-spec/` git submodule is a pinned checkout of the separately
licensed `yaml-sigil-spec` repository. It contains standards text, conformance
test-vector material, and additional third-party content that is not part of
the `yaml-sigil-traits` crate package.

The complete notices for material inside that submodule are retained in
[`source-spec/THIRD_PARTY_NOTICES.md`](source-spec/THIRD_PARTY_NOTICES.md).
Keep that file with every distributed copy of an initialized `source-spec/`
submodule.

The crate source mirrors standard and specification identifiers and implements
public-key format admissibility helpers. It does not embed the RFC 8032 section
7.1 test-vector values, the RFC 4648 alphabet or test-vector tables, or the
Standards for Efficient Cryptography 2 (SEC 2) domain-parameter table.

## RFC 8032 material

The crate's `AlgorithmId::Ed25519` vocabulary refers to Ed25519 as specified
for YamlSigil. The pinned specification submodule contains RFC 8032 section 7.1
test-vector values. Those values are third-party RFC test-vector material used
with attribution under the applicable BCP 78 and IETF Trust framework, not
material relicensed under Apache-2.0.

RFC 8032 is an IRTF Stream RFC. Section 8(g) of the IETF Trust Legal
Provisions in effect when RFC 8032 was published states that the provisions
for IETF Code Components do not apply to documents in the IRTF Document
Stream. This repository does not characterize the section 7.1 values as IETF
Code Components or apply the Revised BSD License to them.

Copyright (c) 2017 IETF Trust and the persons identified as the document
authors. All rights reserved.

RFC 8032 states that the document is subject to BCP 78 and the IETF Trust's
Legal Provisions Relating to IETF Documents in effect on its publication
date. Section 7(a) of those provisions supplies this warranty disclaimer:

> ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN
> "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR
> IS SPONSORED BY (IF ANY), THE INTERNET SOCIETY, THE IETF TRUST, THE
> INTERNET ENGINEERING TASK FORCE AND ANY APPLICABLE MANAGERS OF ALTERNATE
> STREAM DOCUMENTS, AS DEFINED IN SECTION 8 BELOW, DISCLAIM ALL WARRANTIES,
> EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE
> OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED
> WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

Source: Simon Josefsson and Ilari Liusvaara, RFC 8032, *Edwards-Curve Digital
Signature Algorithm (EdDSA)*, January 2017:

- RFC information and copyright notice:
  <https://www.rfc-editor.org/info/rfc8032/>.
- Section 7.1 test vectors:
  <https://www.rfc-editor.org/rfc/rfc8032#section-7.1>.
- BCP 78: <https://www.rfc-editor.org/info/bcp78>.
- IETF Trust Legal Provisions, version 5.0:
  <https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/>.

The names of the document authors, the Crypto Forum Research Group, the IRTF,
the IETF, the IETF Trust, and the RFC Editor are not used to endorse or promote
`yaml-sigil-traits`. No affiliation, sponsorship, or endorsement is claimed or
implied.

## RFC 4648 material

The crate package does not include an RFC 4648 encoder, alphabet table, or test
vectors. The pinned specification submodule uses the canonical-encoding rules,
base64url alphabet, and test values from RFC 4648 sections 3, 5, and 10.
RFC 4648 section 15 provides these copying conditions for the abstract and
sections 1, 3, 8, 10, 12, 13, and 14:

> Copyright (c) 2000-2006 Simon Josefsson
>
> Regarding the abstract and sections 1, 3, 8, 10, 12, 13, and 14 of this
> document, that were written by Simon Josefsson ("the author", for the
> remainder of this section), the author makes no guarantees and is not
> responsible for any damage resulting from its use. The author grants
> irrevocable permission to anyone to use, modify, and distribute it in any
> way that does not diminish the rights of anyone else to use, modify, and
> distribute it, provided that redistributed derivative works do not contain
> misleading author or version information and do not falsely purport to be
> IETF RFC documents. Derivative works need not be licensed under similar
> terms.

RFC 4648 also includes this full copyright and warranty statement:

> Copyright (C) The Internet Society (2006).
>
> This document is subject to the rights, licenses and restrictions contained
> in BCP 78, and except as set forth therein, the authors retain all their
> rights.
>
> This document and the information contained herein are provided on an
> "AS IS" basis and THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR
> IS SPONSORED BY (IF ANY), THE INTERNET SOCIETY AND THE INTERNET ENGINEERING
> TASK FORCE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT
> LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT
> INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS
> FOR A PARTICULAR PURPOSE.

Source: Simon Josefsson, RFC 4648, *The Base16, Base32, and Base64 Data
Encodings*, October 2006, <https://www.rfc-editor.org/rfc/rfc4648>.

## Standards for Efficient Cryptography

The crate's P-256 public-key helper follows point-encoding behavior from
*Standards for Efficient Cryptography 1 (SEC 1)*, Version 2.0. Its
`AlgorithmId::EcdsaP256Sha256` vocabulary refers to secp256r1/P-256. The pinned
specification submodule contains the domain parameters from
*Standards for Efficient Cryptography 2 (SEC 2)*, Version 2.0.

The front page of *Standards for Efficient Cryptography 1 (SEC 1)* carries
this notice:

> Copyright © 2009 Certicom Corp.
>
> License to copy this document is granted provided it is identified as
> "Standards for Efficient Cryptography 1 (SEC 1)", in all material mentioning
> or referencing it.

The front page of *Standards for Efficient Cryptography 2 (SEC 2)* carries
this notice:

> Copyright © 2010 Certicom Corp.
>
> License to copy this document is granted provided it is identified as
> "Standards for Efficient Cryptography 2 (SEC 2)", in all material mentioning
> or referencing it.

Section 1.5, "Intellectual Property," of *Standards for Efficient Cryptography
1 (SEC 1)* states:

> The reader's attention is called to the possibility that compliance with
> this document may require use of an invention covered by patent rights. By
> publication of this document, no position is taken with respect to the
> validity of this claim or of any patent rights in connection therewith. The
> patent holder(s) may have filed with the SECG a statement of willingness to
> grant a license under these rights on reasonable and nondiscriminatory terms
> and conditions to applicants desiring to obtain such a license. Additional
> details may be obtained from the patent holder and from the SECG website,
> <http://www.secg.org>.

Section 1.4, "Intellectual Property," of *Standards for Efficient Cryptography
2 (SEC 2)* states:

> The reader's attention is called to the possibility that compliance with
> this document may require use of an invention covered by patent rights. By
> publication of this document, no position is taken with respect to the
> validity of this claim or of any patent rights in connection therewith. The
> patent holder(s) may have filed with the SECG a statement of willingness to
> grant a license under these rights on fair, reasonable and nondiscriminatory
> terms and conditions to applicants desiring to obtain such a license.
> Additional details may be obtained from the patent holder and from the SECG
> website, <http://www.secg.org>.

Sources:

- *Standards for Efficient Cryptography 1 (SEC 1): Elliptic Curve
  Cryptography*, Version 2.0, May 21, 2009,
  <https://www.secg.org/sec1-v2.pdf>.
- *Standards for Efficient Cryptography 2 (SEC 2): Recommended Elliptic Curve
  Domain Parameters*, Version 2.0, January 27, 2010,
  <https://www.secg.org/sec2-v2.pdf>.

The SEC 1 and SEC 2 material is not relicensed under Apache-2.0.
`yaml-sigil-traits` is not affiliated with, sponsored by, or endorsed by SECG
or Certicom Corp.
