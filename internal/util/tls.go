package util

import (
	"crypto/tls"
	"doh-autoproxy/internal/config"
	"fmt"
)

func LoadServerCertificate(certFile, keyFile string) ([]tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("无法加载证书和密钥 (%s, %s): %w", certFile, keyFile, err)
	}
	return []tls.Certificate{cert}, nil
}

func LoadServerCertificates(certConfigs []config.TLSCertConfig) ([]tls.Certificate, error) {
	var certs []tls.Certificate
	for _, c := range certConfigs {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("无法加载证书和密钥 (%s, %s): %w", c.CertFile, c.KeyFile, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
