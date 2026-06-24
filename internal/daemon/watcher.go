package daemon

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hashicorp/go-set"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type Watcher struct {
	Interval      time.Duration
	OnFinding     string
	ProjectDir    string
	lastModTimes  map[string]time.Time
	lastFindings  []scanner.Result
	cachedPaths   []string
	debounceTimer *time.Timer
	debounceCh    chan struct{}
}

func NewWatcher(interval time.Duration, onFinding string) *Watcher {
	return &Watcher{
		Interval:     interval,
		OnFinding:    onFinding,
		lastModTimes: make(map[string]time.Time),
		debounceCh:   make(chan struct{}, 1),
	}
}

func (w *Watcher) Watch(ctx context.Context) error {
	slog.Info("daemon watching config files for changes",
		"interval", w.Interval)

	results := w.scan()
	w.recordFindings(results)

	configs := config.Discover(w.ProjectDir)
	w.cachedPaths = make([]string, len(configs))
	for i, cfg := range configs {
		w.cachedPaths[i] = cfg.Path
		if info, err := os.Stat(cfg.Path); err == nil {
			w.lastModTimes[filepath.Dir(cfg.Path)] = info.ModTime()
		}
	}

	intervalTicker := time.NewTicker(w.Interval)
	defer intervalTicker.Stop()

	pollTicker := time.NewTicker(1 * time.Second)
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("watcher shutting down")
			return nil
		case <-intervalTicker.C:
			slog.Debug("periodic re-scan triggered")
			w.runScan()
		case <-w.debounceCh:
			slog.Debug("debounced re-scan triggered by fs change")
			w.runScan()
		case <-pollTicker.C:
			w.pollChanges()
		}
	}
}

func (w *Watcher) runScan() {
	results := w.scan()
	newFindings := w.diffFindings(results)
	if len(newFindings) > 0 {
		slog.Warn("new findings detected", "count", len(newFindings))
		for _, f := range newFindings {
			slog.Warn("new finding", "severity", f.Severity, "server", f.Server, "finding", f.Finding)
		}
		if w.OnFinding != "" {
			w.executeNotification(newFindings)
		}
	}
	w.recordFindings(results)
}

func (w *Watcher) pollChanges() {
	for _, path := range w.cachedPaths {
		dir := filepath.Dir(path)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		modTime := info.ModTime()
		prev, ok := w.lastModTimes[dir]
		w.lastModTimes[dir] = modTime
		if ok && modTime.After(prev) {
			w.debounce()
		}
	}
}

func (w *Watcher) debounce() {
	if w.debounceTimer != nil {
		w.debounceTimer.Stop()
	}
	w.debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
		select {
		case w.debounceCh <- struct{}{}:
		default:
		}
	})
}

func (w *Watcher) scan() []scanner.Result {
	s := scanner.New()
	s.ProjectDir = w.ProjectDir
	results, err := s.Static()
	if err != nil {
		slog.Error("scan failed", "error", err)
		return nil
	}

	for i := range results.Results {
		scanner.PopulateRemediation(&results.Results[i])
	}

	return results.Results
}

func (w *Watcher) recordFindings(results []scanner.Result) {
	w.lastFindings = results
}

func findingKey(r scanner.Result) string {
	return r.Server + "|" + r.Finding
}

func (w *Watcher) diffFindings(current []scanner.Result) []scanner.Result {
	prevMap := set.New[string](0)
	for _, r := range w.lastFindings {
		prevMap.Insert(findingKey(r))
	}

	var newFindings []scanner.Result
	for _, r := range current {
		if !prevMap.Contains(findingKey(r)) {
			newFindings = append(newFindings, r)
		}
	}
	return newFindings
}

func (w *Watcher) executeNotification(findings []scanner.Result) {
	counts := make(map[scanner.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	summary := "New mcp-audit findings: "
	for _, sev := range []scanner.Severity{
		scanner.SevCritical, scanner.SevHigh, scanner.SevMedium, scanner.SevLow, scanner.SevInfo,
	} {
		if c, ok := counts[sev]; ok && c > 0 {
			summary += sev.String() + "=" + strconv.Itoa(c) + " "
		}
	}

	cmd := exec.CommandContext(context.Background(), "sh", "-c", w.OnFinding) //nolint:gosec
	cmd.Env = append(os.Environ(),
		"MCP_AUDIT_FINDINGS="+summary,
		"MCP_AUDIT_FINDING_COUNT="+strconv.Itoa(len(findings)),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	slog.Info("executing notification command", "command", w.OnFinding, "env", summary)
	if err := cmd.Run(); err != nil {
		slog.Error("notification command failed", "error", err)
	}
}
