package certhelper

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
)

type sum224 [sha256.Size224]byte

var pemCertRegexp = regexp.MustCompile(`-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END CERTIFICATE-----`)

//https://curl.se/ca/cacert.pem

//go:embed cacert.pem
var root_ca_pem []byte

var (
	RootCAPool           = x509.NewCertPool()
	rootSum              = make(map[sum224]bool)
	root_ca_certificates []*x509.Certificate
)

func init() {
	for _, match := range pemCertRegexp.FindAllStringSubmatch(string(root_ca_pem), -1) {
		cert, err := ParseCertificatePEM([]byte(match[0]))
		if err != nil {
			fmt.Println(match[0])
			panic(err)
		}
		addTrustedCertCA(cert)
	}
}

func addTrustedCertCA(cert *x509.Certificate) {
	if !rootSum[sha256.Sum224(cert.Raw)] {
		RootCAPool.AddCert(cert)
		root_ca_certificates = append(root_ca_certificates, cert)
		rootSum[sha256.Sum224(cert.Raw)] = true
	}
}

// CompleteCertificateChain completes the certificate chain.
func CompleteCertificateChain(certs ...*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate provided")
	}

	chains := make([]*x509.Certificate, 0)

	var current *x509.Certificate
	for _, cert := range certs {
		if current == nil {
			current = cert
			chains = append(chains, cert)
			continue
		}
		if current.CheckSignatureFrom(cert) == nil {
			chains = append(chains, cert)
			current = cert
		} else {
			break
		}
	}
	for {
		issuer, err := FetchIssuerCertificate(current)
		if err == ErrIssuingCertificateURLNotFound {
			break
		}
		if err != nil {
			return chains, err
		}
		chains = append(chains, issuer)
		current = issuer
	}
	for {
		if IsRootCA(current) {
			break
		}
		for _, root := range root_ca_certificates {
			if current.CheckSignatureFrom(root) == nil {
				chains = append(chains, root)
				current = root
			}
		}
	}
	if IsTrusted(chains...) {
		return chains, nil
	}
	return chains, errors.New("certificate signed by unknown authority")
}

func IsTrusted(certs ...*x509.Certificate) bool {
	if len(certs) == 0 {
		return false
	}
	var trusted bool
	var current *x509.Certificate
	for _, c := range certs {
		if current == nil {
			current = c
			continue
		}
		if current.CheckSignatureFrom(c) != nil {
			return false
		}
		for _, root := range root_ca_certificates {
			if c.CheckSignatureFrom(root) == nil {
				trusted = true
			}
		}
		current = c
	}
	return trusted
}
