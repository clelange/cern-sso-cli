// Package certs provides embedded CERN CA certificates.
// Certificates are downloaded at build time by scripts/download_certs.sh
// and embedded into the binary using go:embed.
package certs

import (
	"crypto/x509"
	_ "embed"
	"fmt"
)

// CERN CA certificate files (downloaded at build time)
//
//go:embed cern_root_ca2.pem
var cernRootCA2 []byte

//go:embed cern_grid_ca.pem
var cernGridCA []byte

//go:embed cern_ca.pem
var cernCA []byte

// GetCERNCertsBundle returns the concatenated CERN CA certificates as a PEM bundle.
func GetCERNCertsBundle() []byte {
	bundle := make([]byte, 0, len(cernRootCA2)+len(cernGridCA)+len(cernCA))
	bundle = append(bundle, cernRootCA2...)
	bundle = append(bundle, cernGridCA...)
	bundle = append(bundle, cernCA...)
	return bundle
}

// GetCERNCertPool returns a new certificate pool containing CERN CA certificates.
// This does NOT include system certificates - use AppendToCertPool to add to an existing pool.
func GetCERNCertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if err := appendCERNCerts(pool); err != nil {
		return nil, err
	}
	return pool, nil
}

// GetSystemWithCERNCertPool returns a certificate pool containing both
// the system's trusted certificates and CERN CA certificates.
func GetSystemWithCERNCertPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		// Fall back to empty pool if system certs can't be loaded
		pool = x509.NewCertPool()
	}
	if err := appendCERNCerts(pool); err != nil {
		return nil, err
	}
	return pool, nil
}

// appendCERNCerts adds all CERN CA certificates to the given pool.
func appendCERNCerts(pool *x509.CertPool) error {
	certs := []struct {
		name string
		data []byte
	}{
		{"CERN Root CA 2", cernRootCA2},
		{"CERN Grid CA", cernGridCA},
		{"CERN CA", cernCA},
	}

	for _, cert := range certs {
		if !pool.AppendCertsFromPEM(cert.data) {
			return fmt.Errorf("failed to parse %s certificate", cert.name)
		}
	}
	return nil
}
