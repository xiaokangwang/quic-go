package self_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func TestAllowALPNMismatch(t *testing.T) {
	for _, tc := range []struct {
		name              string
		clientProtos      []string
		serverProtos      []string
		allow             bool
		clientAllow       bool
		tlsCallback       bool
		nilTLSCallback    bool
		rejectTLSCallback bool
		quicCallback      bool
		want              string
		wantError         string
	}{
		{name: "disabled", clientProtos: []string{"client"}, serverProtos: []string{"server"}, wantError: "no application protocol"},
		{name: "enabled only on client", clientProtos: []string{"client"}, serverProtos: []string{"server"}, clientAllow: true, wantError: "no application protocol"},
		{name: "fallback to first offer", clientProtos: []string{"client", "other"}, serverProtos: []string{"server"}, allow: true, want: "client"},
		{name: "preserve server preference", clientProtos: []string{"first", "second"}, serverProtos: []string{"second", "first"}, allow: true, want: "second"},
		{name: "no server protocols", clientProtos: []string{"client"}, allow: true, want: "client"},
		{name: "no client protocols", serverProtos: []string{"server"}, allow: true, wantError: "no application protocol"},
		{name: "TLS callback mismatch", clientProtos: []string{"client"}, serverProtos: []string{"server"}, allow: true, tlsCallback: true, want: "client"},
		{name: "TLS callback preference", clientProtos: []string{"first", "second"}, serverProtos: []string{"second", "first"}, allow: true, tlsCallback: true, want: "second"},
		{name: "nil TLS callback config", clientProtos: []string{"client"}, serverProtos: []string{"server"}, allow: true, nilTLSCallback: true, want: "client"},
		{name: "TLS callback rejection", clientProtos: []string{"client"}, serverProtos: []string{"server"}, allow: true, rejectTLSCallback: true, wantError: "internal error"},
		{name: "QUIC callback enables fallback", clientProtos: []string{"client"}, serverProtos: []string{"server"}, quicCallback: true, want: "client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientPacketConn, serverPacketConn, close := newSimnetLink(t, 10*time.Millisecond)
				defer close(t)

				serverTLS := getTLSConfig()
				serverTLS.NextProtos = slices.Clone(tc.serverProtos)
				var callbackTLS *tls.Config
				var tlsCallbackCalled bool
				if tc.tlsCallback || tc.nilTLSCallback || tc.rejectTLSCallback {
					callbackTLS = serverTLS.Clone()
					if tc.tlsCallback {
						// The callback's configuration must take precedence over the
						// listener's protocols, even when those match the client's.
						serverTLS.NextProtos = tc.clientProtos
					}
					serverTLS.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
						tlsCallbackCalled = true
						require.Equal(t, tc.clientProtos, info.SupportedProtos)
						if tc.rejectTLSCallback {
							return nil, errors.New("reject client")
						}
						if tc.nilTLSCallback {
							return nil, nil
						}
						return callbackTLS, nil
					}
				}
				originalProtos := slices.Clone(serverTLS.NextProtos)
				serverConf := &quic.Config{AllowALPNMismatch: tc.allow}
				if tc.quicCallback {
					serverConf.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
						return getQuicConfig(&quic.Config{AllowALPNMismatch: true}), nil
					}
				}
				ln, err := quic.Listen(serverPacketConn, serverTLS, getQuicConfig(serverConf))
				require.NoError(t, err)
				defer ln.Close()
				clientTLS := getTLSClientConfig()
				clientTLS.NextProtos = tc.clientProtos
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				conn, err := quic.Dial(ctx, clientPacketConn, ln.Addr(), clientTLS, getQuicConfig(&quic.Config{AllowALPNMismatch: tc.clientAllow}))
				require.Equal(t, tc.tlsCallback || tc.nilTLSCallback || tc.rejectTLSCallback, tlsCallbackCalled)
				require.Equal(t, originalProtos, serverTLS.NextProtos)
				if callbackTLS != nil {
					require.Equal(t, tc.serverProtos, callbackTLS.NextProtos)
				}
				if tc.wantError != "" {
					var transportErr *quic.TransportError
					require.ErrorAs(t, err, &transportErr)
					require.True(t, transportErr.ErrorCode.IsCryptoError())
					require.ErrorContains(t, err, tc.wantError)
					return
				}
				require.NoError(t, err)
				defer conn.CloseWithError(0, "")
				serverConn, err := ln.Accept(ctx)
				require.NoError(t, err)
				defer serverConn.CloseWithError(0, "")
				require.Equal(t, tc.want, conn.ConnectionState().TLS.NegotiatedProtocol)
				require.Equal(t, tc.want, serverConn.ConnectionState().TLS.NegotiatedProtocol)

				stream, err := conn.OpenUniStream()
				require.NoError(t, err)
				_, err = stream.Write([]byte("hello"))
				require.NoError(t, err)
				require.NoError(t, stream.Close())
				received, err := serverConn.AcceptUniStream(ctx)
				require.NoError(t, err)
				data, err := io.ReadAll(received)
				require.NoError(t, err)
				require.Equal(t, "hello", string(data))
			})
		})
	}
}

func TestAllowALPNMismatch0RTT(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientPacketConn, serverPacketConn, close := newSimnetLink(t, 10*time.Millisecond)
		defer close(t)
		serverTLS := getTLSConfig()
		serverTLS.NextProtos = []string{"server-only"}
		tr := &quic.Transport{Conn: serverPacketConn}
		defer tr.Close()
		ln, err := tr.ListenEarly(serverTLS, getQuicConfig(&quic.Config{
			AllowALPNMismatch: true,
			Allow0RTT:         true,
		}))
		require.NoError(t, err)
		defer ln.Close()

		clientTLS := dialAndReceiveTicket(t, ln, clientPacketConn, nil)
		transfer0RTTData(t, ln, clientPacketConn, clientTLS, getQuicConfig(nil), []byte("resumed with client ALPN"))
		require.Equal(t, []string{"server-only"}, serverTLS.NextProtos)
	})
}
