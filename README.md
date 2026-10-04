# package pkcs12

[![Documentation](https://pkg.go.dev/badge/software.sslmate.com/src/go-pkcs12)](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12)

    import "software.sslmate.com/src/go-pkcs12" 

Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
It is intended for decoding DER-encoded P12/PFX files for use with the `crypto/tls`
package, and for encoding P12/PFX files for use by legacy applications which
do not support newer formats.  Since PKCS#12 uses weak encryption
primitives, it SHOULD NOT be used for new applications.

Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
allows BER encoding.  This is because encoding/asn1 only supports DER.

This package is forked from `golang.org/x/crypto/pkcs12`, which is frozen.
The implementation is distilled from https://tools.ietf.org/html/rfc7292
and referenced documents.

## Import Path

Note that although the source code and issue tracker for this package are hosted
on GitHub, the import path is:

    software.sslmate.com/src/go-pkcs12 

Please be sure to use this path when you `go get` and `import` this package.

## Decoding with a policy

The policy-aware entry points (`DecodeChainWithPolicy`, `DecodeWithPolicy`,
`DecodeTrustStoreWithPolicy`, and `ToPEMWithPolicy`) validate a PFX against a
`Policy` before deriving any keys.  The policy can restrict the permitted MAC
and encryption OIDs, cap KDF iteration counts both per derivation and
cumulatively across the MAC, every encrypted SafeContents and every shrouded
key, bound salt lengths, and limit the container structure size.  Because all
visible parameters are checked first, a crafted PFX cannot trigger expensive
key derivation before it is rejected.

`DefaultPolicy()` provides modern defaults (PBES2/PBKDF2/HMAC-SHA-2, SHA-2
MACs and PBMAC1 only; bounded iterations, salts and container size).  A nil
policy is permissive and behaves like the corresponding non-policy entry
point.

## Report Issues / Send Patches

Open an issue or PR at https://github.com/SSLMate/go-pkcs12
