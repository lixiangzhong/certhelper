package certhelper

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

// IsSelfSignedCertificate checks if the certificate is self-signed.
func IsSelfSignedCertificate(cert *x509.Certificate) bool {
	return cert.Subject.CommonName == cert.Issuer.CommonName
}

// IsRootCA checks if the certificate is a root CA.
func IsRootCA(cert *x509.Certificate) bool {
	return rootSum[sum224(sha256.Sum224(cert.Raw))]
}

// IsIntermediateCA checks if the certificate is an intermediate CA.
func IsIntermediateCA(cert *x509.Certificate) bool {
	return cert.IsCA && !IsRootCA(cert)
}

// IsEv checks if the certificate is an EV certificate.
func IsEv(cert *x509.Certificate) bool {
	return len(cert.Subject.SerialNumber) > 0
}

// IsOv checks if the certificate is an OV certificate.
func IsOv(cert *x509.Certificate) bool {
	return len(cert.Subject.Organization) > 0
}

// IsDv checks if the certificate is a DV certificate.
func IsDv(cert *x509.Certificate) bool {
	return !IsEv(cert) && !IsOv(cert)
}

// IsRevoked checks if the certificate is revoked.
func IsRevoked(cert *x509.Certificate) (bool, error) {
	issuer, err := FetchIssuerCertificate(cert)
	if err != nil {
		return false, err
	}
	for _, v := range cert.CRLDistributionPoints {
		crl, err := fetchCRL(v)
		if err != nil {
			return false, err
		}
		err = crl.CheckSignatureFrom(issuer)
		if err != nil {
			return false, err
		}
		for _, r := range crl.RevokedCertificateEntries {
			if r.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true, nil
			}
		}
	}
	ocspResp, err := fetchOCSP(cert, issuer)
	if err != nil {
		return false, err
	}
	if ocspResp.Status == ocsp.Revoked {
		return true, nil
	}
	return false, nil
}

var ErrOCSPServerNotFound = errors.New("OCSP server not found")

func fetchOCSP(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	for _, v := range cert.OCSPServer {
		req, err := ocsp.CreateRequest(cert, issuer, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.Post(v, "application/ocsp-request", bytes.NewReader(req))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New("OCSP server response error")
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return ocsp.ParseResponseForCert(b, cert, issuer)
	}
	return nil, ErrOCSPServerNotFound
}
