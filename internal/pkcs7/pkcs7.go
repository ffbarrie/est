// Package pkcs7 implements the minimal subset of PKCS#7 (RFC 2315) needed by
// RFC 7030: a degenerate, certificates-only SignedData ContentInfo, with no
// signer, no signature, and no encapsulated content. This is the wire format
// EST uses for /cacerts responses and for the certificate returned by
// /simpleenroll and /simplereenroll.
//
// Structures are built/parsed with golang.org/x/crypto/cryptobyte rather than
// encoding/asn1's struct-tag-driven (un)marshaling: the nesting of
// Builder.AddASN1/String.ReadASN1 calls mirrors the ASN.1 module text
// directly (an EXPLICIT tag is a nested AddASN1 call; an IMPLICIT tag is a
// context tag used in place of the universal one), which is easier to verify
// against the RFC by inspection than a struct-tag encoding of the same
// structure.
package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// EncodeCertsOnly builds a DER-encoded degenerate PKCS#7 SignedData
// ContentInfo containing certs, per RFC 7030 (certs-only response used by
// /cacerts, /simpleenroll and /simplereenroll):
//
//	ContentInfo ::= SEQUENCE {
//	  contentType   id-signedData,
//	  content       [0] EXPLICIT SignedData }
//
//	SignedData ::= SEQUENCE {
//	  version           INTEGER (1),
//	  digestAlgorithms  SET (empty),
//	  contentInfo       SEQUENCE { contentType id-data },
//	  certificates      [0] IMPLICIT SET OF Certificate,
//	  signerInfos       SET (empty) }
func EncodeCertsOnly(certs []*x509.Certificate) ([]byte, error) {
	for _, c := range certs {
		if c == nil || len(c.Raw) == 0 {
			return nil, errors.New("pkcs7: certificate has no raw DER encoding")
		}
	}

	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { // ContentInfo
		b.AddASN1ObjectIdentifier(oidSignedData)
		b.AddASN1(casn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // content [0] EXPLICIT
			b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignedData
				b.AddASN1Int64(1)                                       // version
				b.AddASN1(casn1.SET, func(b *cryptobyte.Builder) {})    // digestAlgorithms
				b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { // contentInfo
					b.AddASN1ObjectIdentifier(oidData)
				})
				b.AddASN1(casn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // certificates [0] IMPLICIT
					for _, c := range certs {
						b.AddBytes(c.Raw)
					}
				})
				b.AddASN1(casn1.SET, func(b *cryptobyte.Builder) {}) // signerInfos
			})
		})
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("pkcs7: marshal: %w", err)
	}
	return der, nil
}

// DecodeCertsOnly parses a DER-encoded degenerate PKCS#7 SignedData
// ContentInfo and returns the embedded certificates.
func DecodeCertsOnly(der []byte) ([]*x509.Certificate, error) {
	input := cryptobyte.String(der)

	var contentInfo cryptobyte.String
	if !input.ReadASN1(&contentInfo, casn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("pkcs7: invalid contentInfo")
	}

	var contentType asn1.ObjectIdentifier
	if !contentInfo.ReadASN1ObjectIdentifier(&contentType) {
		return nil, errors.New("pkcs7: invalid contentType")
	}
	if !contentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkcs7: unexpected content type %v", contentType)
	}

	var explicitContent cryptobyte.String
	if !contentInfo.ReadASN1(&explicitContent, casn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errors.New("pkcs7: missing content")
	}

	var signedData cryptobyte.String
	if !explicitContent.ReadASN1(&signedData, casn1.SEQUENCE) {
		return nil, errors.New("pkcs7: invalid signedData")
	}

	var version int64
	if !signedData.ReadASN1Int64WithTag(&version, casn1.INTEGER) {
		return nil, errors.New("pkcs7: invalid version")
	}

	var digestAlgorithms cryptobyte.String
	if !signedData.ReadASN1(&digestAlgorithms, casn1.SET) {
		return nil, errors.New("pkcs7: invalid digestAlgorithms")
	}

	var encapContentInfo cryptobyte.String
	if !signedData.ReadASN1(&encapContentInfo, casn1.SEQUENCE) {
		return nil, errors.New("pkcs7: invalid contentInfo")
	}

	var certificates cryptobyte.String
	var hasCertificates bool
	if !signedData.ReadOptionalASN1(&certificates, &hasCertificates, casn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, errors.New("pkcs7: invalid certificates field")
	}
	if !hasCertificates {
		return nil, errors.New("pkcs7: no certificates field present")
	}

	var certs []*x509.Certificate
	for !certificates.Empty() {
		// Each certificate is self-length-delimited DER; ReadASN1Element
		// reads one complete TLV (its own tag+length+content) so trailing
		// siblings in certificates don't confuse the parser.
		var certElement cryptobyte.String
		if !certificates.ReadASN1Element(&certElement, casn1.SEQUENCE) {
			return nil, errors.New("pkcs7: parse embedded certificate: malformed element")
		}
		cert, err := x509.ParseCertificate(certElement)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: parse embedded certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}
