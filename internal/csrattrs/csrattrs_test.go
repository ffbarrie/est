package csrattrs

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// decodeFixture base64-decodes an RFC-provided example (given as
// multi-line base64 text in the RFC) into DER bytes.
func decodeFixture(t *testing.T, b64 string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return der
}

// asn1Attribute mirrors the classic Attribute{type, values} shape for
// test-only decoding of golden fixtures (production code never decodes).
type asn1Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// firstExtensionValueHex decodes a golden id-ExtensionReq attribute fixture
// (the DER of one Attribute, as extracted from a top-level RawValue) and
// returns the first Extension's extnValue as a hex string, so tests can
// build an equivalent Options from the RFC's own bytes instead of
// hand-transcribing hex offsets out of an ASN.1 dump.
func firstExtensionValueHex(t *testing.T, attrDER []byte) string {
	t.Helper()
	var attr asn1Attribute
	if _, err := asn1.Unmarshal(attrDER, &attr); err != nil {
		t.Fatalf("unmarshal attribute: %v", err)
	}
	var exts []pkix.Extension
	if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &exts); err != nil {
		t.Fatalf("unmarshal extensions: %v", err)
	}
	return hex.EncodeToString(exts[0].Value)
}

// topLevelItems decodes a CsrAttrs SEQUENCE into its top-level AttrOrOID
// elements as raw values, for fixture inspection.
func topLevelItems(t *testing.T, der []byte) []asn1.RawValue {
	t.Helper()
	var items []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &items); err != nil {
		t.Fatalf("unmarshal CsrAttrs: %v", err)
	}
	return items
}

func TestEncode_Empty(t *testing.T) {
	der, err := Encode(Options{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if der != nil {
		t.Errorf("Encode(empty) = %x, want nil", der)
	}
}

// TestEncode_RFC9908Examples reproduces RFC 9908 §5.1, 5.2, 5.4, 5.5, and
// 5.6 byte-for-byte from the RFC's own base64 fixtures. §5.3 is skipped:
// its base64 and ASN.1 dump are byte-identical to §5.6 in the published
// RFC text (a copy-paste error — §5.3's prose describes a subjectAltName
// example that its actual bytes don't contain), so it isn't a usable
// fixture for what it claims to demonstrate.
func TestEncode_RFC9908Examples(t *testing.T) {
	t.Run("5.1 ACP subjectAltName via id-ExtensionReq", func(t *testing.T) {
		want := decodeFixture(t, `
			MGgwZgYJKoZIhvcNAQkOMVkwVzBVBgNVHREBAf8ESzBJoEcG
			CCsGAQUFBwgKoDsWOXJmYzg5OTQrZmQ3MzlmYzIzYzM0NDAx
			MTIyMzM0NDU1MDAwMDAwMDArQGFjcC5leGFtcGxlLmNvbQ==
		`)

		items := topLevelItems(t, want)
		if len(items) != 1 {
			t.Fatalf("fixture has %d top-level items, want 1", len(items))
		}
		valueHex := firstExtensionValueHex(t, items[0].FullBytes)

		got, err := Encode(Options{
			RequiredExtensions: []Extension{
				{OID: "2.5.29.17", Critical: true, ValueHex: valueHex},
			},
		})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("DER mismatch:\n got  %x\n want %x", got, want)
		}
	})

	t.Run("5.2 original RFC 7030 example (corrected)", func(t *testing.T) {
		want := decodeFixture(t, `
			MDIGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiBgcr
			BgEBAQEWBggqhkjOPQQDAw==
		`)

		got, err := Encode(Options{
			ChallengePassword: true,
			KeyAlgorithm:      &KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.3.132.0.34"},
			ExtraOIDs: []string{
				"1.3.6.1.1.1.1.22",    // macAddress (RFC 2307)
				"1.2.840.10045.4.3.3", // ecdsaWithSHA384
			},
		})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("DER mismatch:\n got  %x\n want %x", got, want)
		}
	})

	t.Run("5.4 RSA 4096 with SHA-256", func(t *testing.T) {
		want := decodeFixture(t, `
			MCkGCSqGSIb3DQEJBzARBgkqhkiG9w0BAQExBAICEAAGCSqG
			SIb3DQEBCw==
		`)

		got, err := Encode(Options{
			ChallengePassword: true,
			KeyAlgorithm:      &KeyAlgorithm{OID: "1.2.840.113549.1.1.1", RSAModulusBits: 4096},
			ExtraOIDs:         []string{"1.2.840.113549.1.1.11"}, // sha256WithRSAEncryption
		})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("DER mismatch:\n got  %x\n want %x", got, want)
		}
	})

	t.Run("5.5 EC p384 with serial number and SHA-384", func(t *testing.T) {
		want := decodeFixture(t, `
			MC4GCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiBgNV
			BAUGCCqGSM49BAMD
		`)

		got, err := Encode(Options{
			ChallengePassword: true,
			KeyAlgorithm:      &KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.3.132.0.34"},
			ExtraOIDs: []string{
				"2.5.4.5",             // serialNumber
				"1.2.840.10045.4.3.3", // ecdsaWithSHA384
			},
		})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("DER mismatch:\n got  %x\n want %x", got, want)
		}
	})

	t.Run("5.6 EC p521 with friendly name, favorite drink, serial number, SHA-512", func(t *testing.T) {
		want := decodeFixture(t, `
			MEUGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAjBgkq
			hkiG9w0BCRQGCgmSJomT8ixkAQUGA1UEBQYIKoZIzj0EAwQ=
		`)

		got, err := Encode(Options{
			ChallengePassword: true,
			KeyAlgorithm:      &KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.3.132.0.35"},
			ExtraOIDs: []string{
				"1.2.840.113549.1.9.20",     // friendlyName
				"0.9.2342.19200300.100.1.5", // favoriteDrink
				"2.5.4.5",                   // serialNumber
				"1.2.840.10045.4.3.4",       // ecdsaWithSHA512
			},
		})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("DER mismatch:\n got  %x\n want %x", got, want)
		}
	})
}

func TestValidate_ConflictingKeyAlgorithmParams(t *testing.T) {
	opts := Options{KeyAlgorithm: &KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.3.132.0.34", RSAModulusBits: 2048}}
	if err := opts.Validate(); err == nil {
		t.Error("Validate: expected error for both curve_oid and rsa_modulus_bits set, got nil")
	}
}

func TestValidate_TemplateRejectsRSAModulusBits(t *testing.T) {
	opts := Options{Template: &Template{KeyType: &KeyAlgorithm{OID: "1.2.840.113549.1.1.1", RSAModulusBits: 4096}}}
	if err := opts.Validate(); err == nil {
		t.Error("Validate: expected error for template RSA modulus bits, got nil")
	}
}

func TestValidate_TemplateKeyTypeRequiresCurve(t *testing.T) {
	opts := Options{Template: &Template{KeyType: &KeyAlgorithm{OID: "1.2.840.10045.2.1"}}}
	if err := opts.Validate(); err == nil {
		t.Error("Validate: expected error for template key type without a curve OID, got nil")
	}
}

// asn1parse runs `openssl asn1parse` over der and returns its text output,
// used as an independent structural oracle for the template mechanism
// (RFC 9908's §3.4 worked example is given as an ASN.1 dump, not raw
// bytes, so there is no ready-made byte fixture to compare against —
// unlike internal/pkcs7's golden test, openssl is used here to check
// structure/nesting rather than exact bytes).
func asn1parse(t *testing.T, der []byte) string {
	t.Helper()
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available, skipping structural check")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "csrattrs.der")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatalf("write der: %v", err)
	}
	out, err := exec.Command(opensslPath, "asn1parse", "-inform", "DER", "-in", path).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse: %v\n%s", err, out)
	}
	return string(out)
}

func TestEncode_Template(t *testing.T) {
	t.Run("subject with dictated and blank RDNs, EC key type, full extension values", func(t *testing.T) {
		dept := "myDept"
		group := "myGroup"
		sanHex := "3009820777772e636f6d8700" // arbitrary well-formed placeholder GeneralNames bytes for structural testing

		der, err := Encode(Options{Template: &Template{
			Subject: []RDN{
				{OID: "2.5.4.3", Value: nil},     // commonName, client fills in
				{OID: "2.5.4.11", Value: &dept},  // organizationalUnitName = "myDept"
				{OID: "2.5.4.11", Value: &group}, // organizationalUnitName = "myGroup"
			},
			KeyType: &KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.2.840.10045.3.1.7"}, // secp256r1
			Extensions: []TemplateExtension{
				{OID: "2.5.29.17", ValueHex: &sanHex}, // subjectAltName, value present
			},
		}})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		// OpenSSL's object database doesn't know the RFC 9908 OIDs by name
		// (id-aa-certificationRequestInfoTemplate, id-aa-extensionReqTemplate),
		// so asn1parse prints them as dotted decimal; id-ExtensionReq (an
		// older, well-known PKCS#9 OID) prints as "Extension Request".
		out := asn1parse(t, der)
		for _, want := range []string{
			oidCertificationRequestInfoTemplate,
			"commonName",
			"myDept",
			"myGroup",
			"prime256v1", // OpenSSL's name for secp256r1 / 1.2.840.10045.3.1.7
			"Extension Request",
			"X509v3 Subject Alternative Name",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("asn1parse output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("extension with absent value uses id-aa-extensionReqTemplate", func(t *testing.T) {
		der, err := Encode(Options{Template: &Template{
			Extensions: []TemplateExtension{
				{OID: "2.5.29.17", ValueHex: nil}, // subjectAltName, client fills in
			},
		}})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		out := asn1parse(t, der)
		if !strings.Contains(out, oidExtensionReqTemplate) {
			t.Errorf("asn1parse output missing %s (id-aa-extensionReqTemplate):\n%s", oidExtensionReqTemplate, out)
		}
		if strings.Contains(out, "Extension Request") || strings.Contains(out, oidExtensionReq) {
			t.Errorf("expected id-ExtensionReq NOT to appear when a value is absent:\n%s", out)
		}
	})

	t.Run("mixed present/absent extension values still uses template attribute", func(t *testing.T) {
		present := "0500"
		der, err := Encode(Options{Template: &Template{
			Extensions: []TemplateExtension{
				{OID: "2.5.29.15", Critical: true, ValueHex: &present}, // keyUsage, value present
				{OID: "2.5.29.37", ValueHex: nil},                      // extKeyUsage, client fills in
			},
		}})
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		out := asn1parse(t, der)
		if !strings.Contains(out, oidExtensionReqTemplate) {
			t.Errorf("asn1parse output missing %s (id-aa-extensionReqTemplate):\n%s", oidExtensionReqTemplate, out)
		}
	})
}
