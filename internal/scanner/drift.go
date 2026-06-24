package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/mcp"
	"github.com/mcheviron/mcp-audit/internal/snapshot"
)

type driftConfig struct {
	snapshotDir       string
	noSnapshot        bool
	noTrustOnFirstUse bool
	trustConfig       *config.TrustConfig
}

func buildToolEntries(tools []mcp.Tool) []snapshot.ToolEntry {
	entries := make([]snapshot.ToolEntry, len(tools))
	for i, t := range tools {
		entries[i] = snapshot.ToolEntry{
			Name:            t.Name,
			DescriptionHash: snapshot.HashToolDescription(t.Description),
			SchemaHash:      snapshot.HashToolSchema(t.InputSchema),
			Properties:      snapshot.SchemaPropertyKeys(t.InputSchema),
		}
	}
	return entries
}

func driftSeverityToScanner(sev snapshot.Severity) Severity {
	return Severity(sev)
}

func performDriftCheck(
	srv config.ServerEntry,
	tools []mcp.Tool,
	driftCfg driftConfig,
	results *[]Result,
	mu *sync.Mutex,
) {
	srvKey := snapshot.MakeKey(srv.Name, srv.URL, srv.Command)

	oldSnap, err := snapshot.LoadSnapshot(driftCfg.snapshotDir, srvKey)
	if err != nil {
		mu.Lock()
		*results = append(*results, Result{
			Severity:   SevLow,
			Server:     srv.Name,
			Type:       "drift",
			Finding:    fmt.Sprintf("failed to load snapshot: %v — treating as first scan", err),
			ConfigPath: srv.ConfigPath,
		})
		mu.Unlock()
	}

	entries := buildToolEntries(tools)

	var pinned map[string]string
	if driftCfg.trustConfig != nil {
		pinned = driftCfg.trustConfig.PinnedForServer(srv.Name)
	}

	curSnap := &snapshot.Snapshot{
		Server:    srv.Name,
		Key:       srvKey,
		URL:       srv.URL,
		Command:   srv.Command,
		ScannedAt: time.Now(),
		Tools:     entries,
	}

	trustOnFirst := !driftCfg.noTrustOnFirstUse
	driftFindings := snapshot.CompareSnapshots(oldSnap, curSnap, pinned, trustOnFirst)
	var driftResults []Result
	for _, df := range driftFindings {
		sev := driftSeverityToScanner(df.Severity)
		driftResults = append(driftResults, Result{
			Severity:   sev,
			Server:     df.Server,
			Type:       "drift",
			Finding:    df.Finding,
			Detail:     df.Detail,
			ConfigPath: srv.ConfigPath,
		})
	}
	if len(driftResults) > 0 {
		mu.Lock()
		*results = append(*results, driftResults...)
		mu.Unlock()
	}

	if err := snapshot.SaveSnapshot(driftCfg.snapshotDir, srvKey,
		srv.Name, srv.URL, srv.Command, entries); err != nil {
		mu.Lock()
		*results = append(*results, Result{
			Severity:   SevLow,
			Server:     srv.Name,
			Type:       "drift",
			Finding:    fmt.Sprintf("failed to save snapshot: %v", err),
			ConfigPath: srv.ConfigPath,
		})
		mu.Unlock()
	}
}
