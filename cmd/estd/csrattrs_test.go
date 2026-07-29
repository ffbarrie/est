package main

import (
	"reflect"
	"testing"

	"github.com/ffbarrie/est/internal/config"
	"github.com/ffbarrie/est/internal/csrattrs"
)

func TestCsrAttrsOptions_Nil(t *testing.T) {
	got := csrAttrsOptions(nil)
	if !reflect.DeepEqual(got, csrattrs.Options{}) {
		t.Errorf("csrAttrsOptions(nil) = %+v, want zero value", got)
	}
}

func TestCsrAttrsOptions_FullTranslation(t *testing.T) {
	dictated := "myDept"
	blankValue := (*string)(nil)
	presentHex := "0500"

	cfg := &config.CSRAttrsConfig{
		ChallengePassword: true,
		KeyAlgorithm:      &config.KeyAlgorithmConfig{OID: "1.2.840.10045.2.1", CurveOID: "1.3.132.0.34"},
		RequiredExtensions: []config.ExtensionConfig{
			{OID: "2.5.29.17", Critical: true, ValueHex: "3009820777772e636f6d"},
		},
		ExtraOIDs: []string{"1.2.840.10045.4.3.3"},
		Template: &config.TemplateConfig{
			Subject: []config.RDNConfig{
				{OID: "2.5.4.3", Value: blankValue},
				{OID: "2.5.4.11", Value: &dictated},
			},
			KeyType: &config.KeyAlgorithmConfig{OID: "1.2.840.10045.2.1", CurveOID: "1.2.840.10045.3.1.7"},
			Extensions: []config.TemplateExtensionConfig{
				{OID: "2.5.29.17", ValueHex: nil},
				{OID: "2.5.29.15", Critical: true, ValueHex: &presentHex},
			},
		},
	}

	got := csrAttrsOptions(cfg)

	want := csrattrs.Options{
		ChallengePassword: true,
		KeyAlgorithm:      &csrattrs.KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.3.132.0.34"},
		RequiredExtensions: []csrattrs.Extension{
			{OID: "2.5.29.17", Critical: true, ValueHex: "3009820777772e636f6d"},
		},
		ExtraOIDs: []string{"1.2.840.10045.4.3.3"},
		Template: &csrattrs.Template{
			Subject: []csrattrs.RDN{
				{OID: "2.5.4.3", Value: nil},
				{OID: "2.5.4.11", Value: &dictated},
			},
			KeyType: &csrattrs.KeyAlgorithm{OID: "1.2.840.10045.2.1", CurveOID: "1.2.840.10045.3.1.7"},
			Extensions: []csrattrs.TemplateExtension{
				{OID: "2.5.29.17", ValueHex: nil},
				{OID: "2.5.29.15", Critical: true, ValueHex: &presentHex},
			},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("csrAttrsOptions() mismatch:\n got  %+v\n want %+v", got, want)
	}

	// Confirm the pointer semantics actually survived the translation
	// (nil = client fills in, non-nil = dictated), not just that
	// reflect.DeepEqual happened to consider them equal.
	if got.Template.Subject[0].Value != nil {
		t.Errorf("Subject[0].Value = %v, want nil (client fills in)", *got.Template.Subject[0].Value)
	}
	if got.Template.Subject[1].Value == nil || *got.Template.Subject[1].Value != "myDept" {
		t.Errorf("Subject[1].Value = %v, want \"myDept\"", got.Template.Subject[1].Value)
	}
	if got.Template.Extensions[0].ValueHex != nil {
		t.Errorf("Extensions[0].ValueHex = %v, want nil (client fills in)", *got.Template.Extensions[0].ValueHex)
	}
	if got.Template.Extensions[1].ValueHex == nil || *got.Template.Extensions[1].ValueHex != "0500" {
		t.Errorf("Extensions[1].ValueHex = %v, want \"0500\"", got.Template.Extensions[1].ValueHex)
	}

	// And the result must actually be encodable end-to-end.
	if _, err := csrattrs.Encode(got); err != nil {
		t.Errorf("csrattrs.Encode(translated options): %v", err)
	}
}
