package main

import (
	"github.com/ffbarrie/est/internal/config"
	"github.com/ffbarrie/est/internal/csrattrs"
)

// csrAttrsOptions translates the on-disk config shape into
// csrattrs.Options. cfg may be nil (no csr_attrs section configured).
func csrAttrsOptions(cfg *config.CSRAttrsConfig) csrattrs.Options {
	if cfg == nil {
		return csrattrs.Options{}
	}

	opts := csrattrs.Options{
		ChallengePassword: cfg.ChallengePassword,
		ExtraOIDs:         cfg.ExtraOIDs,
	}

	if cfg.KeyAlgorithm != nil {
		opts.KeyAlgorithm = &csrattrs.KeyAlgorithm{
			OID:            cfg.KeyAlgorithm.OID,
			CurveOID:       cfg.KeyAlgorithm.CurveOID,
			RSAModulusBits: cfg.KeyAlgorithm.RSAModulusBits,
		}
	}

	for _, e := range cfg.RequiredExtensions {
		opts.RequiredExtensions = append(opts.RequiredExtensions, csrattrs.Extension{
			OID:      e.OID,
			Critical: e.Critical,
			ValueHex: e.ValueHex,
		})
	}

	if cfg.Template != nil {
		tmpl := &csrattrs.Template{}

		for _, r := range cfg.Template.Subject {
			tmpl.Subject = append(tmpl.Subject, csrattrs.RDN{OID: r.OID, Value: r.Value})
		}

		if cfg.Template.KeyType != nil {
			tmpl.KeyType = &csrattrs.KeyAlgorithm{
				OID:            cfg.Template.KeyType.OID,
				CurveOID:       cfg.Template.KeyType.CurveOID,
				RSAModulusBits: cfg.Template.KeyType.RSAModulusBits,
			}
		}

		for _, e := range cfg.Template.Extensions {
			tmpl.Extensions = append(tmpl.Extensions, csrattrs.TemplateExtension{
				OID:      e.OID,
				Critical: e.Critical,
				ValueHex: e.ValueHex,
			})
		}

		opts.Template = tmpl
	}

	return opts
}
