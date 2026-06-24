package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

func newClient(ctx context.Context, srv config.ServerEntry, forceFlag string, auth AuthConfig) (mcp.Client, error) {
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

	token, headers, certFile, keyFile := mergeAuth(srv, auth)

	switch kind {
	case config.TransportStdio:
		if forceFlag == "" {
			return nil, fmt.Errorf(
				"stdio transport requires explicit --transport stdio flag to execute commands from config")
		}
		if srv.Command == "" {
			return nil, fmt.Errorf("no command for stdio transport")
		}
		return mcp.NewStdioClient(ctx, srv.Command, srv.Args, mcp.DefaultTimeout), nil
	case config.TransportHTTP:
		if srv.URL == "" {
			return nil, fmt.Errorf("no URL for HTTP transport")
		}
		if forceFlag != "" {
			return mcp.NewHTTPClient(srv.URL, mcp.DefaultTimeout, token, headers, certFile, keyFile)
		}
		return mcp.NewAutoClient(srv.URL, mcp.DefaultTimeout, token, headers, certFile, keyFile)
	case config.TransportSSE:
		if srv.URL == "" {
			return nil, fmt.Errorf("no URL for SSE transport")
		}
		return mcp.NewSSEClient(srv.URL, mcp.DefaultTimeout, token, headers, certFile, keyFile)
	default:
		return nil, fmt.Errorf("unknown transport: %v", kind)
	}
}

func mergeAuth(srv config.ServerEntry, global AuthConfig) (string, map[string]string, string, string) {
	token := srv.AuthToken
	if token == "" {
		token = global.Token
	}
	headers := make(map[string]string)
	maps.Copy(headers, global.Headers)
	maps.Copy(headers, srv.AuthHeaders)
	cert := srv.TLSCertFile
	if cert == "" {
		cert = global.Cert
	}
	key := srv.TLSKeyFile
	if key == "" {
		key = global.Key
	}
	return token, headers, cert, key
}

func handshakeServer(
	ctx context.Context, srv config.ServerEntry, transportFlag string, auth AuthConfig,
) (mcp.Client, error) {
	client, err := newClient(ctx, srv, transportFlag, auth)
	if err != nil {
		return nil, err
	}

	_, err = client.Initialize(ctx)
	if err != nil {
		if cerr := client.Close(); cerr != nil {
			slog.Debug("close client after init failure", "err", cerr)
		}
		return nil, err
	}

	return client, nil
}

func noAuthConfigured(srv config.ServerEntry, global AuthConfig) bool {
	return srv.AuthToken == "" && len(srv.AuthHeaders) == 0 &&
		global.Token == "" && len(global.Headers) == 0 &&
		srv.TLSCertFile == "" && srv.TLSKeyFile == "" &&
		global.Cert == "" && global.Key == ""
}
