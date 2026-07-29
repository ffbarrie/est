package estapi

import (
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
)

// errNoPeerCertificate indicates the request arrived over TLS without a
// client certificate, which /simpleenroll and /simplereenroll require.
var errNoPeerCertificate = errors.New("estapi: no client certificate presented")

// peerCertificate returns the authenticated client certificate for r, or
// errNoPeerCertificate if none was presented. Presented certificates have
// already been chain-verified by the TLS layer (BuildTLSConfig sets
// ClientCAs and VerifyClientCertIfGiven), so its mere presence here means
// it is trusted.
func peerCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errNoPeerCertificate
	}
	return r.TLS.PeerCertificates[0], nil
}

// identitiesMatch reports whether csr requests the same identity as peer:
// an exact CommonName match and an identical SAN set (DNSNames,
// IPAddresses, EmailAddresses and URIs, compared as a set). This is the
// deliberately simple v1 policy for /simplereenroll — anything else is
// rejected rather than partially honored.
func identitiesMatch(peer *x509.Certificate, csr *x509.CertificateRequest) bool {
	if peer.Subject.CommonName != csr.Subject.CommonName {
		return false
	}
	return sanSet(peer.DNSNames, peer.IPAddresses, peer.EmailAddresses, peer.URIs) ==
		sanSet(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs)
}

// sanSet renders a certificate's/CSR's SAN fields as a single, order- and
// duplicate-insensitive string for equality comparison.
func sanSet(dnsNames []string, ips []net.IP, emails []string, uris []*url.URL) string {
	var items []string
	for _, d := range dnsNames {
		items = append(items, "dns:"+d)
	}
	for _, ip := range ips {
		items = append(items, "ip:"+ip.String())
	}
	for _, e := range emails {
		items = append(items, "email:"+e)
	}
	for _, u := range uris {
		items = append(items, "uri:"+u.String())
	}
	sort.Strings(items)
	out := ""
	for _, it := range items {
		out += it + "\n"
	}
	return out
}
