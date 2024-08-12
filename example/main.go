package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lixiangzhong/certhelper"
)

func main() {
	certs, err := fetchCert("badssl.com:443")
	if err != nil {
		log.Fatal(err)
	}
	err = Verify("badssl.com", certs...)
	log.Println(err)
	// certs, err := loadCert("1.pem")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// Dump(certs...)

	// fullchain, err := certhelper.CompleteCertificateChain(certs...)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// b := certhelper.EncodeCertificatePEM(fullchain...)
	// log.Println(string(b))
	// Dump(fullchain...)
}

func fetchCert(servername string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", servername, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, err
}

func loadCert(filename string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return certhelper.ParseCertificatesPEM(b)
}

func Dump(certs ...*x509.Certificate) {
	for _, cert := range certs {
		fmt.Println("签发给:", cert.Subject.CommonName)
		if len(cert.DNSNames) > 0 {
			fmt.Println("域名:", cert.DNSNames)
		}
		fmt.Println("签发者:", cert.Issuer.CommonName)
		if certhelper.IsRootCA(cert) {
			fmt.Println("根证书")
			fmt.Println("品牌:", cert.Issuer.Organization)
		} else if certhelper.IsSelfSignedCertificate(cert) {
			fmt.Println("自签名证书")
		}
		if certhelper.IsIntermediateCA(cert) {
			fmt.Println("中间证书")
		}
		fmt.Println("有效期:", cert.NotBefore.Format(time.DateTime), cert.NotAfter.Format(time.DateTime))
		fmt.Println("-------------------------")
	}
}

func Verify(hostname string, certs ...*x509.Certificate) error {
	intermediatePool := x509.NewCertPool()

	var server *x509.Certificate
	for _, cert := range certs {
		if server == nil {
			if certhelper.IsSelfSignedCertificate(cert) && !certhelper.IsRootCA(cert) {
				return errors.New("self-signed certificate")
			}
			server = cert
			continue
		}
		if certhelper.IsIntermediateCA(cert) {
			intermediatePool.AddCert(cert)
		}
		if certhelper.IsRootCA(cert) {
			continue
		}
	}
	_, err := server.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediatePool,
		Roots:         certhelper.RootCAPool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}
	revoked, err := certhelper.IsRevoked(server)
	if err == nil && revoked {
		return errors.New("revoked certificate")
	}
	return nil
}
