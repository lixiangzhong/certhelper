package certhelper

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"fmt"
	"regexp"
)

//https://curl.se/ca/cacert.pem

//go:embed cacert.pem
var root_ca_pem []byte

var RootCAPool = x509.NewCertPool()

type sum224 [sha256.Size224]byte

var rootSum = make(map[sum224]bool)

var pemCertRegexp = regexp.MustCompile(`-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END CERTIFICATE-----`)

var root_ca_certificates []*x509.Certificate

func init() {
	for _, match := range pemCertRegexp.FindAllStringSubmatch(string(root_ca_pem), -1) {
		cert, err := ParseCertificatePEM([]byte(match[0]))
		if err != nil {
			fmt.Println(match[0])
			panic(err)
		}
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
	for _, root := range root_ca_certificates {
		if current.CheckSignatureFrom(root) == nil {
			chains = append(chains, root)
			return chains, nil
		}
	}
	return chains, fmt.Errorf("root certificate not found")
}
