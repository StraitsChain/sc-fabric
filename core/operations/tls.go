/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operations

import (
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"

	tls "github.com/tjfoc/gmsm/gmtls"
)

type TLS struct {
	Enabled            bool
	CertFile           string
	KeyFile            string
	ClientCertRequired bool
	ClientCACertFiles  []string
}

func (t TLS) Config() (*tls.Config, error) {
	var tlsConfig *tls.Config

	if t.Enabled {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		for _, caPath := range t.ClientCACertFiles {
			caPem, err := ioutil.ReadFile(caPath)
			if err != nil {
				return nil, err
			}
			caCertPool.AppendCertsFromPEM(caPem)
		}
		var gmSupport *tls.GMSupport
		if gm.IsPureGMTLSCertificate(&cert) {
			gmSupport = &tls.GMSupport{}
		}
		tlsConfig = &tls.Config{
			GMSupport:    gmSupport,
			Certificates: []tls.Certificate{cert},
			CipherSuites: comm.DefaultTLSCipherSuites,
			ClientCAs:    caCertPool,
		}
		if t.ClientCertRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsConfig, nil
}
