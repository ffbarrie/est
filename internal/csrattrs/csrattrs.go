// Package csrattrs builds the DER-encoded CsrAttrs response for EST's
// GET /csrattrs endpoint (RFC 7030 §4.5.2, as clarified by RFC 8951 §4 and
// extended by RFC 9908). It supports both the classic "list of OIDs and
// attributes" mechanism and RFC 9908's CertificationRequestInfoTemplate
// mechanism, encoded together in a single response.
//
// Every structure here is built by hand-assembling already-DER-encoded
// child values via three small primitives (sequence, set, implicitTag)
// rather than relying on encoding/asn1's struct-tag-driven OPTIONAL/tag
// handling, which proved easy to get subtly wrong for explicit/implicit
// context tags during development of internal/pkcs7. This trades a bit of
// verbosity for encodings whose shape is fully explicit and easy to verify
// byte-for-byte against the RFC's own worked examples.
package csrattrs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// Encode returns the DER-encoded CsrAttrs SEQUENCE for opts, or (nil, nil)
// if opts is entirely empty — callers should respond with HTTP 204 in that
// case rather than an empty-but-present SEQUENCE (RFC 7030 §4.5.2 treats
// the two as equivalent; 204 needs no encoding at all).
func Encode(opts Options) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	var items [][]byte

	if opts.ChallengePassword {
		d, err := marshalOIDItem(oidChallengePassword)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: challenge_password: %w", err)
		}
		items = append(items, d)
	}

	if opts.KeyAlgorithm != nil {
		d, err := marshalKeyAlgorithmAttribute(*opts.KeyAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: key_algorithm: %w", err)
		}
		items = append(items, d)
	}

	if len(opts.RequiredExtensions) > 0 {
		d, err := marshalExtensionReqAttribute(opts.RequiredExtensions)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: required_extensions: %w", err)
		}
		items = append(items, d)
	}

	for i, oidStr := range opts.ExtraOIDs {
		d, err := marshalOIDItem(oidStr)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: extra_oids[%d]: %w", i, err)
		}
		items = append(items, d)
	}

	if opts.Template != nil {
		templateDER, err := buildTemplate(*opts.Template)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: template: %w", err)
		}
		d, err := marshalAttribute(oidCertificationRequestInfoTemplate, templateDER)
		if err != nil {
			return nil, fmt.Errorf("csrattrs: template: %w", err)
		}
		items = append(items, d)
	}

	if len(items) == 0 {
		return nil, nil
	}
	return sequence(items...)
}

// --- ASN.1 primitives ---
//
// Each wraps already-DER-encoded child values in a universal SEQUENCE/SET,
// or overrides a compound value's tag for an IMPLICIT context tag.

func sequence(parts ...[]byte) ([]byte, error) {
	return wrap(asn1.ClassUniversal, asn1.TagSequence, parts)
}

func set(parts ...[]byte) ([]byte, error) {
	return wrap(asn1.ClassUniversal, asn1.TagSet, parts)
}

func implicitTag(class, tag int, content []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: content})
}

func wrap(class, tag int, parts [][]byte) ([]byte, error) {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: content})
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

func marshalOID(dotted string) ([]byte, error) {
	oid, err := parseOID(dotted)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(oid)
}

// marshalOIDItem builds a bare-OID AttrOrOID entry (the "oid" CHOICE
// alternative): an untagged OBJECT IDENTIFIER, exactly as it appears at
// the top level of the CsrAttrs SEQUENCE.
func marshalOIDItem(dotted string) ([]byte, error) {
	return marshalOID(dotted)
}

// marshalAttribute builds an Attribute { type OID, values SET OF <valueDER> }
// (the "attribute" CHOICE alternative).
func marshalAttribute(oidStr string, valueDER ...[]byte) ([]byte, error) {
	oidDER, err := marshalOID(oidStr)
	if err != nil {
		return nil, err
	}
	valuesDER, err := set(valueDER...)
	if err != nil {
		return nil, err
	}
	return sequence(oidDER, valuesDER)
}

func marshalKeyAlgorithmAttribute(ka KeyAlgorithm) ([]byte, error) {
	var valueDER []byte
	var err error
	switch {
	case ka.CurveOID != "":
		valueDER, err = marshalOID(ka.CurveOID)
	case ka.RSAModulusBits != 0:
		valueDER, err = asn1.Marshal(ka.RSAModulusBits)
	}
	if err != nil {
		return nil, err
	}
	if valueDER != nil {
		return marshalAttribute(ka.OID, valueDER)
	}
	return marshalAttribute(ka.OID) // empty values SET: algorithm required, no further constraint
}

// marshalExtensions builds a plain RFC 5280 Extensions SEQUENCE (every
// value mandatory), reusing crypto/x509/pkix.Extension's existing
// encoding/asn1 support rather than reimplementing it.
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

func marshalExtensionReqAttribute(exts []Extension) ([]byte, error) {
	extsDER, err := marshalExtensions(exts)
	if err != nil {
		return nil, err
	}
	return marshalAttribute(oidExtensionReq, extsDER)
}

// marshalExtensionTemplate builds one ExtensionTemplate SEQUENCE, omitting
// Critical when false (DEFAULT FALSE) and omitting the extnValue OCTET
// STRING entirely when ValueHex is nil.
func marshalExtensionTemplate(e TemplateExtension) ([]byte, error) {
	oidDER, err := marshalOID(e.OID)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{oidDER}
	if e.Critical {
		critDER, err := asn1.Marshal(true)
		if err != nil {
			return nil, err
		}
		parts = append(parts, critDER)
	}
	if e.ValueHex != nil {
		value, err := hex.DecodeString(*e.ValueHex)
		if err != nil {
			return nil, fmt.Errorf("invalid value_hex: %w", err)
		}
		valDER, err := asn1.Marshal(value)
		if err != nil {
			return nil, err
		}
		parts = append(parts, valDER)
	}
	return sequence(parts...)
}

func marshalExtensionReqTemplateAttribute(exts []TemplateExtension) ([]byte, error) {
	var extDERs [][]byte
	for i, e := range exts {
		d, err := marshalExtensionTemplate(e)
		if err != nil {
			return nil, fmt.Errorf("extension %d: %w", i, err)
		}
		extDERs = append(extDERs, d)
	}
	extsSeqDER, err := sequence(extDERs...)
	if err != nil {
		return nil, err
	}
	return marshalAttribute(oidExtensionReqTemplate, extsSeqDER)
}

// buildTemplate builds a CertificationRequestInfoTemplate SEQUENCE:
//
//	SEQUENCE {
//	  version       INTEGER { v1(0) }
//	  subject       NameTemplate OPTIONAL          -- untagged, no [n]
//	  subjectPKInfo [0] SubjectPublicKeyInfoTemplate OPTIONAL
//	  attributes    [1] Attributes{{ CRIAttributes }}  -- always present
//	}
func buildTemplate(t Template) ([]byte, error) {
	versionDER, err := asn1.Marshal(0)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{versionDER}

	if len(t.Subject) > 0 {
		subjectDER, err := buildSubjectTemplate(t.Subject)
		if err != nil {
			return nil, fmt.Errorf("subject: %w", err)
		}
		parts = append(parts, subjectDER)
	}

	if t.KeyType != nil {
		pkInfoDER, err := buildSubjectPKInfoTemplate(*t.KeyType)
		if err != nil {
			return nil, fmt.Errorf("key type: %w", err)
		}
		parts = append(parts, pkInfoDER)
	}

	attrsDER, err := buildTemplateAttributes(t.Extensions)
	if err != nil {
		return nil, fmt.Errorf("extensions: %w", err)
	}
	parts = append(parts, attrsDER)

	return sequence(parts...)
}

// buildSubjectTemplate builds the (untagged) NameTemplate field: a
// SEQUENCE OF RelativeDistinguishedNameTemplate, one SET per RDN, each
// containing a single SingleAttributeTemplate whose value is omitted when
// the RDN's Value is nil.
func buildSubjectTemplate(rdns []RDN) ([]byte, error) {
	var rdnDERs [][]byte
	for i, rdn := range rdns {
		oidDER, err := marshalOID(rdn.OID)
		if err != nil {
			return nil, fmt.Errorf("rdn %d: %w", i, err)
		}
		parts := [][]byte{oidDER}
		if rdn.Value != nil {
			valDER, err := asn1.MarshalWithParams(*rdn.Value, "utf8")
			if err != nil {
				return nil, fmt.Errorf("rdn %d: %w", i, err)
			}
			parts = append(parts, valDER)
		}
		attrDER, err := sequence(parts...)
		if err != nil {
			return nil, fmt.Errorf("rdn %d: %w", i, err)
		}
		rdnSetDER, err := set(attrDER)
		if err != nil {
			return nil, fmt.Errorf("rdn %d: %w", i, err)
		}
		rdnDERs = append(rdnDERs, rdnSetDER)
	}
	return sequence(rdnDERs...)
}

// buildSubjectPKInfoTemplate builds the [0] IMPLICIT SubjectPublicKeyInfoTemplate
// field, always omitting the OPTIONAL subjectPublicKey BIT STRING (v1 does
// not support the RSA placeholder-key case; see Template.KeyType's doc).
func buildSubjectPKInfoTemplate(ka KeyAlgorithm) ([]byte, error) {
	algOIDDER, err := marshalOID(ka.OID)
	if err != nil {
		return nil, err
	}
	algParts := [][]byte{algOIDDER}
	if ka.CurveOID != "" {
		curveDER, err := marshalOID(ka.CurveOID)
		if err != nil {
			return nil, err
		}
		algParts = append(algParts, curveDER)
	}
	algIDDER, err := sequence(algParts...)
	if err != nil {
		return nil, err
	}
	return implicitTag(asn1.ClassContextSpecific, 0, algIDDER)
}

// buildTemplateAttributes builds the [1] IMPLICIT attributes field: a SET
// OF Attribute (empty when exts is empty), containing at most one
// extension-requirement attribute per the RFC 9908 §3.4 MUST rule: use
// id-ExtensionReq when every extension's value is present, or
// id-aa-extensionReqTemplate when any value is left for the client.
func buildTemplateAttributes(exts []TemplateExtension) ([]byte, error) {
	var content []byte
	if len(exts) > 0 {
		allPresent := true
		for _, e := range exts {
			if e.ValueHex == nil {
				allPresent = false
				break
			}
		}

		var attrDER []byte
		var err error
		if allPresent {
			full := make([]Extension, len(exts))
			for i, e := range exts {
				full[i] = Extension{OID: e.OID, Critical: e.Critical, ValueHex: *e.ValueHex}
			}
			attrDER, err = marshalExtensionReqAttribute(full)
		} else {
			attrDER, err = marshalExtensionReqTemplateAttribute(exts)
		}
		if err != nil {
			return nil, err
		}
		content = attrDER
	}
	return implicitTag(asn1.ClassContextSpecific, 1, content)
}
