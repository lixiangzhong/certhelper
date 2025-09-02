package certhelper

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/lixiangzhong/certhelper/pkcs7"
)

var (
	httpclient = new(http.Client)
)

var ParseCertificatesPKCS7 = pkcs7.ExtractCertificates

func ParseCertificatePKCS7(data []byte) (*x509.Certificate, error) {
	certs, err := pkcs7.ExtractCertificates(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificatesPEM(pemBytes)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func ParseCertificatesPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(bytes.TrimSpace(pemBytes))
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("unexpected block type: " + block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		pemBytes = rest
	}
	return certs, nil
}

var ParseCertificatesDER = x509.ParseCertificates
var ParseCertificateDER = x509.ParseCertificate

var ErrIssuingCertificateURLNotFound = errors.New("issuingCertificateURL not found")

// FetchIssuerCertificate fetches the issuer certificate of the given certificate.
func FetchIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	for _, url := range cert.IssuingCertificateURL {
		return fetchIssuerCertificate(url)
	}
	return nil, ErrIssuingCertificateURLNotFound
}

var issuerCache = map[string]*x509.Certificate{}
var issuerCacheLocker = new(sync.Mutex)

func fetchIssuerCertificate(url string) (*x509.Certificate, error) {
	issuerCacheLocker.Lock()
	defer issuerCacheLocker.Unlock()
	if issuer, ok := issuerCache[url]; ok {
		if time.Now().Before(issuer.NotAfter) {
			return issuer, nil
		}
		delete(issuerCache, url)
	}
	resp, err := httpclient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var issuers []*x509.Certificate

	issuer, err := ParseCertificatesPKCS7(b)
	if err == nil {
		issuers = append(issuers, issuer...)
	}
	issuer, err = ParseCertificatesDER(b)
	if err == nil {
		issuers = append(issuers, issuer...)
	}
	issuer, err = ParseCertificatesPEM(b)
	if err == nil {
		issuers = append(issuers, issuer...)
	}
	sort.Slice(issuers, func(i, j int) bool {
		return issuers[i].NotAfter.After(issuers[j].NotAfter)
	})
	issuerCache[url] = issuers[0]
	return issuers[0], nil
}

func EncodeCertificatePEM(cert ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range cert {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return buf.Bytes()
}

var crlCache = map[string]*x509.RevocationList{}
var crlCacheLocker = new(sync.Mutex)

func fetchCRL(url string) (*x509.RevocationList, error) {
	crlCacheLocker.Lock()
	defer crlCacheLocker.Unlock()
	if crl, ok := crlCache[url]; ok {
		if time.Now().Before(crl.NextUpdate) {
			return crl, nil
		}
		delete(crlCache, url)
	}
	resp, err := httpclient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	crl, err := x509.ParseRevocationList(b)
	if err != nil {
		return nil, err
	}
	crlCache[url] = crl
	return crl, nil
}

var (
	KeyUsageNames = map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "Digital Signature",
		x509.KeyUsageContentCommitment: "Content Commitment",
		x509.KeyUsageKeyEncipherment:   "Key Encipherment",
		x509.KeyUsageDataEncipherment:  "Data Encipherment",
		x509.KeyUsageKeyAgreement:      "Key Agreement",
		x509.KeyUsageCertSign:          "Certificate Sign",
		x509.KeyUsageCRLSign:           "CRL Sign",
		x509.KeyUsageEncipherOnly:      "Encipher Only",
		x509.KeyUsageDecipherOnly:      "Decipher Only",
	}
)

func KeyUsageName(ku x509.KeyUsage) []string {
	names := make([]string, 0)
	for i := 0; i < 9; i++ {
		keyUsage := x509.KeyUsage(1 << i)
		if ku&keyUsage != 0 {
			if name, ok := KeyUsageNames[1<<i]; ok {
				names = append(names, name)
			}
		}
	}
	return names
}
