// Package pkcs7 implements the minimal subset of PKCS#7 (RFC 2315) needed by
// RFC 7030: a degenerate, certificates-only SignedData ContentInfo, with no
// signer, no signature, and no encapsulated content. This is the wire format
// EST uses for /cacerts responses and for the certificate returned by
// /simpleenroll and /simplereenroll.
package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// contentInfo is the outer PKCS#7 envelope: a content type OID plus an
// explicitly-tagged [0] content whose structure depends on that type.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// encapsulatedContentInfo mirrors contentInfo but is used inside SignedData,
// where content is always absent for a certs-only structure.
type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is RFC 2315's SignedData with certificates, crls and
// signerInfos left empty/absent except for the certificates we carry.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	ContentInfo      encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

// EncodeCertsOnly builds a DER-encoded degenerate PKCS#7 SignedData
// ContentInfo containing certs, per RFC 7030 (certs-only response used by
// /cacerts, /simpleenroll and /simplereenroll).
func EncodeCertsOnly(certs []*x509.Certificate) ([]byte, error) {
	var certBytes []byte
	for _, c := range certs {
		if c == nil || len(c.Raw) == 0 {
			return nil, errors.New("pkcs7: certificate has no raw DER encoding")
		}
		certBytes = append(certBytes, c.Raw...)
	}

	certificates := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certBytes,
	}

	emptySet := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: emptySet,
		ContentInfo:      encapsulatedContentInfo{ContentType: oidData},
		Certificates:     certificates,
		SignerInfos:      emptySet,
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: marshal signedData: %w", err)
	}

	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	der, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: marshal contentInfo: %w", err)
	}
	return der, nil
}

// DecodeCertsOnly parses a DER-encoded degenerate PKCS#7 SignedData
// ContentInfo and returns the embedded certificates.
func DecodeCertsOnly(der []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: unmarshal contentInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs7: trailing data after contentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkcs7: unexpected content type %v", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("pkcs7: unmarshal signedData: %w", err)
	}

	if sd.Certificates.Tag != 0 || sd.Certificates.Class != asn1.ClassContextSpecific {
		return nil, errors.New("pkcs7: no certificates field present")
	}

	var certs []*x509.Certificate
	remaining := sd.Certificates.Bytes
	for len(remaining) > 0 {
		// Each certificate in the set is self-length-delimited DER; find
		// where it ends via a raw ASN.1 unmarshal, then parse exactly that
		// slice so trailing siblings in remaining don't confuse the parser.
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &raw)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: parse embedded certificate: %w", err)
		}
		certLen := len(remaining) - len(rest)
		cert, err := x509.ParseCertificate(remaining[:certLen])
		if err != nil {
			return nil, fmt.Errorf("pkcs7: parse embedded certificate: %w", err)
		}
		certs = append(certs, cert)
		remaining = rest
	}

	return certs, nil
}
