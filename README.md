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

Before a PFX can be decoded, keys must be derived from the password using a
KDF whose iteration count is chosen by the (possibly untrusted) file.  To
avoid accepting unsupported algorithms or performing unexpectedly expensive
KDF work, decode with [DecodeChainWithPolicy] (or [DecodeWithPolicy] /
[DecodeTrustStoreWithPolicy]) and supply a [Policy]:

```go
import "software.sslmate.com/src/go-pkcs12"

policy := &pkcs12.Policy{
    MaxKDFIterations:     1_000_000,
    MaxTotalKDFWork:      10_000_000,
    MinSaltLength:        16,
    MaxSafeContents:      16,
    MaxSafeBags:          64,
}
key, cert, caCerts, err := pkcs12.DecodeChainWithPolicy(policy, pfxData, password)
```

`MacAlgorithms` and `EncryptionAlgorithms` optionally hold allow-listed OIDs
(an empty/nil slice allows every algorithm the library knows how to decode);
unknown OIDs are always rejected.

The policy is applied **before any keys are derived**.  Every parameter that
can be checked without decrypting is validated first (MAC/encryption OIDs,
per-invocation and cumulative KDF iteration counts, salt lengths, and
container sizes), so a non-conforming PFX is rejected before any expensive
computation.  KDF work is accumulated across the MAC, all encrypted safe
contents, and all shrouded key bags rather than being reset per layer; a
legacy PBE invocation is charged twice (key and IV) while PBKDF2 is charged
once.

Passing the policy does not verify integrity: the MAC is still checked exactly
as in the regular entry points, and a wrong password still returns
`ErrIncorrectPassword`.  Integer overflows, negative values, malformed
parameters, unknown algorithms, and policy rejections are reported as
distinct errors wrapping `ErrIntegerOverflow`, `ErrNegativeValue`,
`ErrMalformedParameter`, `ErrUnknownAlgorithm`, and `ErrPolicyRejected`
respectively.  Error messages never contain the password or decrypted data.

The existing `Decode`, `DecodeChain`, and `DecodeTrustStore` functions remain
unrestricted and unchanged, and the library's default/encoder algorithms are
not modified.

## Report Issues / Send Patches

Open an issue or PR at https://github.com/SSLMate/go-pkcs12
