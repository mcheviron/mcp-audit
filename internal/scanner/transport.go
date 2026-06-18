package scanner

import (
	"context"
	"fmt"
	"maps"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

func newTransport(srv config.ServerEntry, forceFlag string, auth AuthConfig, maxResp int64) (mcp.Transport, error) {
	kind := srv.Kind()
	if forceFlag != "" {
		switch forceFlag {
		case "stdio":
			kind = config.TransportStdio
		case "http":
			kind = config.TransportHTTP
		case "sse":
			kind = config.TransportSSE
		default:
			return nil, fmt.Errorf("unknown transport flag: %s", forceFlag)
		}
	}

	switch kind {
	case config.TransportStdio:
		if forceFlag == "" {
			return nil, fmt.Errorf(
				"stdio transport requires explicit --transport stdio flag to execute commands from config")
		}
		if srv.Command == "" {
			return nil, fmt.Errorf("no command for stdio transport")
		}
		tr := mcp.NewStdioTransport(srv.Command, srv.Args, mcp.DefaultTimeout)
		if err := applyAuth(tr, srv, auth); err != nil {
			return nil, err
		}
		return tr, nil
	case config.TransportHTTP:
		if srv.URL == "" {
			return nil, fmt.Errorf("no URL for HTTP transport")
		}
		if forceFlag != "" {
			tr := mcp.NewHTTPTransport(srv.URL, mcp.DefaultTimeout, maxResp)
			if err := applyAuth(tr, srv, auth); err != nil {
				return nil, err
			}
			return tr, nil
		}
		tr := mcp.NewAutoTransport(srv.URL, mcp.DefaultTimeout, maxResp)
		if err := applyAuth(tr, srv, auth); err != nil {
			return nil, err
		}
		return tr, nil
	case config.TransportSSE:
		if srv.URL == "" {
			return nil, fmt.Errorf("no URL for SSE transport")
		}
		tr := mcp.NewSSETransport(srv.URL, mcp.DefaultTimeout)
		if err := applyAuth(tr, srv, auth); err != nil {
			return nil, err
		}
		return tr, nil
	default:
		return nil, fmt.Errorf("unknown transport: %v", kind)
	}
}

func applyAuth(tr mcp.Transport, srv config.ServerEntry, global AuthConfig) error {
	token := srv.AuthToken
	if token == "" {
		token = global.Token
	}
	if token != "" {
		tr.SetAuthToken(token)
	}

	if len(global.Headers) > 0 || len(srv.AuthHeaders) > 0 {
		headers := make(map[string]string)
		maps.Copy(headers, global.Headers)
		maps.Copy(headers, srv.AuthHeaders)
		tr.SetAuthHeaders(headers)
	}

	certFile := srv.TLSCertFile
	if certFile == "" {
		certFile = global.Cert
	}
	keyFile := srv.TLSKeyFile
	if keyFile == "" {
		keyFile = global.Key
	}
	if certFile != "" && keyFile != "" {
		if err := tr.SetTLS(certFile, keyFile); err != nil {
			return fmt.Errorf("TLS setup failed: %w", err)
		}
	}
	return nil
}

func handshakeServer(
	ctx context.Context, srv config.ServerEntry, transportFlag string, auth AuthConfig, maxResp int64,
) (mcp.Client, mcp.Transport, error) {
	transport, err := newTransport(srv, transportFlag, auth, maxResp)
	if err != nil {
		return nil, nil, err
	}

	mcpClient := mcp.NewClient(transport)
	_, err = mcpClient.Initialize(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}

	return mcpClient, transport, nil
}

func noAuthConfigured(srv config.ServerEntry, global AuthConfig) bool {
	return srv.AuthToken == "" && len(srv.AuthHeaders) == 0 &&
		global.Token == "" && len(global.Headers) == 0 &&
		srv.TLSCertFile == "" && srv.TLSKeyFile == "" &&
		global.Cert == "" && global.Key == ""
}
