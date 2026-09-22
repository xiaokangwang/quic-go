package quic

import (
	"crypto/tls"
	"slices"
)

func setupTLSConfigForALPNMismatch(tlsConf *tls.Config) *tls.Config {
	// Initialize the session ticket keys before cloning, so connections continue
	// to share them. See https://github.com/golang/go/issues/60506.
	_, _ = tlsConf.DecryptTicket(nil, tls.ConnectionState{})

	conf := tlsConf.Clone()
	getConfigForClient := conf.GetConfigForClient
	conf.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		selected := tlsConf
		if getConfigForClient != nil {
			c, err := getConfigForClient(info)
			if err != nil {
				return nil, err
			}
			if c != nil {
				selected = c
			}
		}
		if len(info.SupportedProtos) == 0 {
			return selected, nil
		}
		for _, proto := range selected.NextProtos {
			if slices.Contains(info.SupportedProtos, proto) {
				return selected, nil
			}
		}
		// Only change this connection's configuration. The selected configuration
		// may be shared with other connections or returned by an application callback.
		selected = selected.Clone()
		selected.NextProtos = []string{info.SupportedProtos[0]}
		return selected, nil
	}
	return conf
}
