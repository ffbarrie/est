// Package csrattrs builds the DER-encoded CsrAttrs response for EST's
// GET /csrattrs endpoint (RFC 7030 §4.5.2, as clarified by RFC 8951 §4 and
// extended by RFC 9908). It supports both the classic "list of OIDs and
// attributes" mechanism and RFC 9908's CertificationRequestInfoTemplate
// mechanism, encoded together in a single response.
//
// Structures are built with golang.org/x/crypto/cryptobyte rather than
// encoding/asn1's struct-tag-driven marshaling: the nesting of
// Builder.AddASN1 calls mirrors the ASN.1 module text directly (an
// EXPLICIT tag is a nested AddASN1 call; an IMPLICIT tag is a context tag
// used in place of the universal one), which is easier to verify against
// the RFC by inspection than a struct-tag encoding of the same structure —
// see internal/pkcs7 for the same rationale in more detail. The one
// exception is marshalExtensions, which builds a plain RFC 5280 Extensions
// SEQUENCE via crypto/x509/pkix.Extension + encoding/asn1.Marshal: that was
// never hand-rolled tag arithmetic (it's the same reflection-based struct
// marshaling crypto/x509 itself uses for real certificate extensions), so
// it isn't part of what this migration addresses.
package csrattrs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OIDs defined by PKCS#9 (RFC 2985) and RFC 9908 Appendix A.
const (
	oidChallengePassword                = "1.2.840.113549.1.9.7"
	oidExtensionReq                     = "1.2.840.113549.1.9.14"
	oidCertificationRequestInfoTemplate = "1.2.840.113549.1.9.16.2.61"
	oidExtensionReqTemplate             = "1.2.840.113549.1.9.16.2.62"
)

// Options describes the CSR attributes a server wants to advertise.
// A zero-value Options encodes to no response at all (Encode returns nil).
type Options struct {
	// ChallengePassword requests that the client include a challengePassword
	// attribute in its CSR (RFC 7030 §3.5 identity/POP linking).
	ChallengePassword bool

	// KeyAlgorithm, if set, requires a specific public key type (and
	// optionally its parameters) via the classic attribute mechanism.
	KeyAlgorithm *KeyAlgorithm

	// RequiredExtensions, if non-empty, becomes a single id-ExtensionReq
	// attribute carrying a full Extensions SEQUENCE (every value present).
	RequiredExtensions []Extension

	// ExtraOIDs are additional bare OIDs to include, in order — RFC 7030
	// §4.5.2 models a CsrAttrs entry as "zero or more OIDs or attributes",
	// and not every such OID has (or needs) named sugar here. Typical uses:
	// a required signature algorithm OID, or a descriptive attribute OID
	// such as RFC 2307's macAddress.
	ExtraOIDs []string

	// Template, if set, becomes a CertificationRequestInfoTemplate
	// attribute (RFC 9908 §3.4).
	Template *Template
}

// KeyAlgorithm requires a specific public key type. Exactly one of
// CurveOID or RSAModulusBits should be set (or neither, to require the
// algorithm with no further constraint).
type KeyAlgorithm struct {
	OID            string // key type OID, e.g. ecPublicKey or rsaEncryption
	CurveOID       string // set when OID is an EC key type
	RSAModulusBits int    // set when OID is rsaEncryption
}

// Extension is a fully specified X.509 extension requirement (used for the
// classic id-ExtensionReq attribute, where every value is mandatory).
type Extension struct {
	OID      string
	Critical bool
	ValueHex string // required; hex-encoded DER extnValue
}

// Template is RFC 9908 §3.4's CertificationRequestInfoTemplate: a partially
// filled-in CSR whose blanks the client is expected to complete.
type Template struct {
	// Subject, if non-nil, dictates the CSR's subject RDN sequence. Each
	// RDN with a nil Value is left for the client to fill in.
	Subject []RDN

	// KeyType, if set, constrains the public key type. v1 supports EC only
	// (CurveOID); RSAModulusBits is rejected by Validate — a template
	// placeholder RSA key requires embedding a syntactically valid
	// placeholder public key of the desired modulus length, which is a
	// separate problem from everything else here. Use the top-level
	// Options.KeyAlgorithm for an RSA size requirement instead.
	KeyType *KeyAlgorithm

	// Extensions, if non-empty, becomes the template's single extension
	// attribute. Per RFC 9908 §3.4: if every entry has a non-nil ValueHex,
	// it is encoded as id-ExtensionReq (full values); if any ValueHex is
	// nil, it is encoded as id-aa-extensionReqTemplate instead.
	Extensions []TemplateExtension
}

// RDN is one relative distinguished name entry in a subject template.
type RDN struct {
	OID   string
	Value *string // nil = client fills in; non-nil (including "") = dictated
}

// TemplateExtension is an extension requirement inside a Template, whose
// value may be left for the client to fill in.
type TemplateExtension struct {
	OID      string
	Critical bool
	ValueHex *string // nil = extnValue absent (client fills in)
}

// Validate reports any configuration that Encode cannot express.
func (o Options) Validate() error {
	if o.KeyAlgorithm != nil && o.KeyAlgorithm.CurveOID != "" && o.KeyAlgorithm.RSAModulusBits != 0 {
		return errors.New("csrattrs: key_algorithm cannot set both a curve OID and an RSA modulus size")
	}
	if o.Template != nil && o.Template.KeyType != nil {
		if o.Template.KeyType.RSAModulusBits != 0 {
			return errors.New("csrattrs: template key type does not support an RSA modulus size (use the top-level key_algorithm instead)")
		}
		if o.Template.KeyType.CurveOID == "" {
			return errors.New("csrattrs: template key type requires a curve OID")
		}
	}
	return nil
}

func isEmpty(opts Options) bool {
	return !opts.ChallengePassword &&
		opts.KeyAlgorithm == nil &&
		len(opts.RequiredExtensions) == 0 &&
		len(opts.ExtraOIDs) == 0 &&
		opts.Template == nil
}

// Encode returns the DER-encoded CsrAttrs SEQUENCE for opts, or (nil, nil)
// if opts is entirely empty — callers should respond with HTTP 204 in that
// case rather than an empty-but-present SEQUENCE (RFC 7030 §4.5.2 treats
// the two as equivalent; 204 needs no encoding at all).
func Encode(opts Options) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if isEmpty(opts) {
		return nil, nil
	}

	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { // CsrAttrs
		if opts.ChallengePassword {
			addOID(b, oidChallengePassword)
		}
		if opts.KeyAlgorithm != nil {
			addKeyAlgorithmAttribute(b, *opts.KeyAlgorithm)
		}
		if len(opts.RequiredExtensions) > 0 {
			addExtensionReqAttribute(b, opts.RequiredExtensions)
		}
		for _, oidStr := range opts.ExtraOIDs {
			addOID(b, oidStr)
		}
		if opts.Template != nil {
			addAttribute(b, oidCertificationRequestInfoTemplate, func(b *cryptobyte.Builder) {
				addTemplate(b, *opts.Template)
			})
		}
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("csrattrs: %w", err)
	}
	return der, nil
}

func parseOID(dotted string) (asn1.ObjectIdentifier, error) {
	fields := strings.Split(dotted, ".")
	oid := make(asn1.ObjectIdentifier, len(fields))
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q: %w", dotted, err)
		}
		oid[i] = n
	}
	return oid, nil
}

// addOID writes an OBJECT IDENTIFIER, either as a bare AttrOrOID "oid"
// choice at the top level, or as the "type" field of an Attribute. Invalid
// OID strings are reported through b (via SetError) rather than returned
// directly, since this is called from deep inside nested AddASN1 closures;
// the error ultimately surfaces from the top-level Builder.Bytes() call.
func addOID(b *cryptobyte.Builder, dotted string) {
	oid, err := parseOID(dotted)
	if err != nil {
		b.SetError(err)
		return
	}
	b.AddASN1ObjectIdentifier(oid)
}

// addAttribute builds an Attribute { type OID, values SET OF <value> }
// (the "attribute" CHOICE alternative). addValue writes the single
// values-SET member; nil means an empty SET (algorithm required, no
// further constraint — see addKeyAlgorithmAttribute).
func addAttribute(b *cryptobyte.Builder, oidStr string, addValue func(b *cryptobyte.Builder)) {
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addOID(b, oidStr)
		b.AddASN1(casn1.SET, func(b *cryptobyte.Builder) {
			if addValue != nil {
				addValue(b)
			}
		})
	})
}

func addKeyAlgorithmAttribute(b *cryptobyte.Builder, ka KeyAlgorithm) {
	switch {
	case ka.CurveOID != "":
		addAttribute(b, ka.OID, func(b *cryptobyte.Builder) { addOID(b, ka.CurveOID) })
	case ka.RSAModulusBits != 0:
		addAttribute(b, ka.OID, func(b *cryptobyte.Builder) { b.AddASN1Int64(int64(ka.RSAModulusBits)) })
	default:
		addAttribute(b, ka.OID, nil)
	}
}

// marshalExtensions builds a plain RFC 5280 Extensions SEQUENCE (every
// value mandatory), reusing crypto/x509/pkix.Extension's existing
// encoding/asn1 support rather than reimplementing it (see package doc).
func marshalExtensions(exts []Extension) ([]byte, error) {
	pkixExts := make([]pkix.Extension, len(exts))
	for i, e := range exts {
		oid, err := parseOID(e.OID)
		if err != nil {
			return nil, fmt.Errorf("extension %d: %w", i, err)
		}
		value, err := hex.DecodeString(e.ValueHex)
		if err != nil {
			return nil, fmt.Errorf("extension %d: invalid value_hex: %w", i, err)
		}
		pkixExts[i] = pkix.Extension{Id: oid, Critical: e.Critical, Value: value}
	}
	return asn1.Marshal(pkixExts)
}

func addExtensionReqAttribute(b *cryptobyte.Builder, exts []Extension) {
	extsDER, err := marshalExtensions(exts)
	if err != nil {
		b.SetError(fmt.Errorf("required_extensions: %w", err))
		return
	}
	addAttribute(b, oidExtensionReq, func(b *cryptobyte.Builder) { b.AddBytes(extsDER) })
}

// addExtensionTemplate writes one ExtensionTemplate SEQUENCE, omitting
// Critical when false (DEFAULT FALSE) and omitting the extnValue OCTET
// STRING entirely when ValueHex is nil.
func addExtensionTemplate(b *cryptobyte.Builder, e TemplateExtension) {
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addOID(b, e.OID)
		if e.Critical {
			b.AddASN1Boolean(true)
		}
		if e.ValueHex != nil {
			value, err := hex.DecodeString(*e.ValueHex)
			if err != nil {
				b.SetError(fmt.Errorf("invalid value_hex: %w", err))
				return
			}
			b.AddASN1OctetString(value)
		}
	})
}

func addExtensionReqTemplateAttribute(b *cryptobyte.Builder, exts []TemplateExtension) {
	addAttribute(b, oidExtensionReqTemplate, func(b *cryptobyte.Builder) {
		b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { // ExtensionTemplates
			for _, e := range exts {
				addExtensionTemplate(b, e)
			}
		})
	})
}

// addTemplate writes a CertificationRequestInfoTemplate SEQUENCE:
//
//	SEQUENCE {
//	  version       INTEGER { v1(0) }
//	  subject       NameTemplate OPTIONAL          -- untagged, no [n]
//	  subjectPKInfo [0] SubjectPublicKeyInfoTemplate OPTIONAL
//	  attributes    [1] Attributes{{ CRIAttributes }}  -- always present
//	}
func addTemplate(b *cryptobyte.Builder, t Template) {
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0) // version
		if len(t.Subject) > 0 {
			addSubjectTemplate(b, t.Subject)
		}
		if t.KeyType != nil {
			addSubjectPKInfoTemplate(b, *t.KeyType)
		}
		addTemplateAttributes(b, t.Extensions)
	})
}

// addSubjectTemplate writes the (untagged) NameTemplate field: a SEQUENCE
// OF RelativeDistinguishedNameTemplate, one SET per RDN, each containing a
// single SingleAttributeTemplate whose value is omitted when the RDN's
// Value is nil.
func addSubjectTemplate(b *cryptobyte.Builder, rdns []RDN) {
	b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, rdn := range rdns {
			b.AddASN1(casn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
					addOID(b, rdn.OID)
					if rdn.Value != nil {
						b.AddASN1(casn1.UTF8String, func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(*rdn.Value))
						})
					}
				})
			})
		}
	})
}

// addSubjectPKInfoTemplate writes the [0] IMPLICIT SubjectPublicKeyInfoTemplate
// field, always omitting the OPTIONAL subjectPublicKey BIT STRING (v1 does
// not support the RSA placeholder-key case; see Template.KeyType's doc).
func addSubjectPKInfoTemplate(b *cryptobyte.Builder, ka KeyAlgorithm) {
	b.AddASN1(casn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) { // AlgorithmIdentifier
			addOID(b, ka.OID)
			if ka.CurveOID != "" {
				addOID(b, ka.CurveOID)
			}
		})
	})
}

// addTemplateAttributes writes the [1] IMPLICIT attributes field: a SET OF
// Attribute (empty when exts is empty), containing at most one
// extension-requirement attribute per the RFC 9908 §3.4 MUST rule: use
// id-ExtensionReq when every extension's value is present, or
// id-aa-extensionReqTemplate when any value is left for the client.
func addTemplateAttributes(b *cryptobyte.Builder, exts []TemplateExtension) {
	b.AddASN1(casn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		if len(exts) == 0 {
			return
		}
		allPresent := true
		for _, e := range exts {
			if e.ValueHex == nil {
				allPresent = false
				break
			}
		}
		if allPresent {
			full := make([]Extension, len(exts))
			for i, e := range exts {
				full[i] = Extension{OID: e.OID, Critical: e.Critical, ValueHex: *e.ValueHex}
			}
			addExtensionReqAttribute(b, full)
		} else {
			addExtensionReqTemplateAttribute(b, exts)
		}
	})
}
