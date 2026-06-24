package report

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type evidenceEntry struct {
	ID       string `json:"id"`
	Data     string `json:"data"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

type evidenceBundle struct {
	FormatVersion string            `json:"format_version"`
	Tool          string            `json:"tool"`
	Version       string            `json:"version"`
	ScanTimestamp string            `json:"scan_timestamp"`
	Findings      []evidenceFinding `json:"findings"`
	Chains        []evidenceChain   `json:"chains,omitempty"`
	Entries       []evidenceEntry   `json:"entries"`
	ChainValid    bool              `json:"chain_valid"`
}

type evidenceFinding struct {
	Severity   string                  `json:"severity"`
	Server     string                  `json:"server"`
	Type       string                  `json:"type"`
	Finding    string                  `json:"finding"`
	Detail     string                  `json:"detail,omitempty"`
	Compliance []scanner.ComplianceTag `json:"compliance,omitempty"`
	Related    []scanner.FindingRef    `json:"related_findings,omitempty"`
}

type evidenceChain struct {
	Hops        []scanner.ChainHop `json:"hops"`
	MaxSeverity string             `json:"max_severity"`
	Truncated   bool               `json:"truncated"`
}

func computeHMAC(key []byte, id, data, prev string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	mac.Write([]byte(data))
	mac.Write([]byte(prev))
	return hex.EncodeToString(mac.Sum(nil))
}

func ExportEvidence(path, keyHex string, results []scanner.Result, chains []scanner.Chain) error {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid evidence key: must be hex-encoded: %w", err)
	}

	ef := make([]evidenceFinding, len(results))
	for i, r := range results {
		ef[i] = evidenceFinding{
			Severity:   r.Severity.String(),
			Server:     r.Server,
			Type:       r.Type,
			Finding:    r.Finding,
			Detail:     r.Detail,
			Compliance: r.Compliance,
			Related:    r.RelatedFindings,
		}
	}

	ec := make([]evidenceChain, len(chains))
	for i, c := range chains {
		ec[i] = evidenceChain{
			Hops:        c.Hops,
			MaxSeverity: c.MaxSeverity.String(),
			Truncated:   c.Truncated,
		}
	}

	entries := buildEvidenceEntries(results, key)

	valid := verifyHMACChain(entries, key)

	bundle := evidenceBundle{
		FormatVersion: "1.0",
		Tool:          "mcp-audit",
		Version:       "0.1.0",
		ScanTimestamp: time.Now().UTC().Format(time.RFC3339),
		Findings:      ef,
		Chains:        ec,
		Entries:       entries,
		ChainValid:    valid,
	}

	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("create evidence file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			_ = cerr
		}
	}()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

func verifyHMACChain(entries []evidenceEntry, key []byte) bool {
	prevHash := ""
	for _, e := range entries {
		expected := computeHMAC(key, e.ID, e.Data, prevHash)
		if !hmac.Equal([]byte(expected), []byte(e.Hash)) {
			return false
		}
		prevHash = e.Hash
	}
	return true
}

func buildEvidenceEntries(results []scanner.Result, key []byte) []evidenceEntry {
	var entries []evidenceEntry
	prevHash := ""
	for _, r := range results {
		id := scanner.MakeResultIDForExport(r)
		dataJSON, _ := json.Marshal(evidenceFinding{
			Severity:   r.Severity.String(),
			Server:     r.Server,
			Type:       r.Type,
			Finding:    r.Finding,
			Detail:     r.Detail,
			Compliance: r.Compliance,
			Related:    r.RelatedFindings,
		})
		h := computeHMAC(key, id, string(dataJSON), prevHash)
		entries = append(entries, evidenceEntry{
			ID:       id,
			Data:     string(dataJSON),
			PrevHash: prevHash,
			Hash:     h,
		})
		prevHash = h
	}
	return entries
}

func VerifyEvidenceBundle(path, keyHex string) (bool, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return false, fmt.Errorf("invalid evidence key: must be hex-encoded: %w", err)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return false, fmt.Errorf("read evidence file: %w", err)
	}
	var bundle evidenceBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return false, fmt.Errorf("parse evidence bundle: %w", err)
	}
	return verifyHMACChain(bundle.Entries, key), nil
}
