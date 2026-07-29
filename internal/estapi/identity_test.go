package estapi

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
	"testing"
)

func TestIdentitiesMatch(t *testing.T) {
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse URL %q: %v", s, err)
		}
		return u
	}

	base := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "client01.example.test"},
		DNSNames:    []string{"a.example.test", "b.example.test"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
	}

	cases := []struct {
		name string
		peer *x509.Certificate
		csr  *x509.CertificateRequest
		want bool
	}{
		{
			name: "identical CN and SAN",
			peer: base,
			csr: &x509.CertificateRequest{
				Subject:     pkix.Name{CommonName: "client01.example.test"},
				DNSNames:    []string{"a.example.test", "b.example.test"},
				IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
			},
			want: true,
		},
		{
			name: "SAN order doesn't matter",
			peer: base,
			csr: &x509.CertificateRequest{
				Subject:     pkix.Name{CommonName: "client01.example.test"},
				DNSNames:    []string{"b.example.test", "a.example.test"},
				IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
			},
			want: true,
		},
		{
			name: "different CN, identical SAN",
			peer: base,
			csr: &x509.CertificateRequest{
				Subject:     pkix.Name{CommonName: "someone-else.example.test"},
				DNSNames:    []string{"a.example.test", "b.example.test"},
				IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
			},
			want: false,
		},
		{
			name: "same CN, extra DNS name in CSR",
			peer: base,
			csr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "client01.example.test"},
				DNSNames: []string{"a.example.test", "b.example.test", "c.example.test"},
			},
			want: false,
		},
		{
			name: "same CN, missing IP in CSR",
			peer: base,
			csr: &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "client01.example.test"},
				DNSNames: []string{"a.example.test", "b.example.test"},
			},
			want: false,
		},
		{
			name: "same CN, both empty SAN",
			peer: &x509.Certificate{Subject: pkix.Name{CommonName: "client02.example.test"}},
			csr:  &x509.CertificateRequest{Subject: pkix.Name{CommonName: "client02.example.test"}},
			want: true,
		},
		{
			name: "same CN and SAN, URIs also match",
			peer: &x509.Certificate{
				Subject: pkix.Name{CommonName: "client03.example.test"},
				URIs:    []*url.URL{mustURL("spiffe://example.test/client03")},
			},
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "client03.example.test"},
				URIs:    []*url.URL{mustURL("spiffe://example.test/client03")},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := identitiesMatch(tc.peer, tc.csr); got != tc.want {
				t.Errorf("identitiesMatch() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSanSet_OrderAndDuplicateSensitivity(t *testing.T) {
	a := sanSet([]string{"a.example.test", "b.example.test"}, nil, nil, nil)
	b := sanSet([]string{"b.example.test", "a.example.test"}, nil, nil, nil)
	if a != b {
		t.Errorf("sanSet not order-insensitive:\n a=%q\n b=%q", a, b)
	}

	// sanSet is a sorted-multiset comparison, not true set semantics: a
	// duplicated entry is not deduplicated, so it changes the result. This
	// test locks in that (documented) behavior rather than silently
	// treating duplicates as equivalent to a single occurrence.
	single := sanSet([]string{"a.example.test"}, nil, nil, nil)
	duplicated := sanSet([]string{"a.example.test", "a.example.test"}, nil, nil, nil)
	if single == duplicated {
		t.Error("sanSet treated a duplicated entry as equivalent to a single occurrence")
	}
}
