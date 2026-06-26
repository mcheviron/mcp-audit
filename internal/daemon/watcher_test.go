package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

func TestWatcherDebounce(t *testing.T) {
	w := NewWatcher(context.Background(), 5*time.Minute, "")

	count := 0
	done := make(chan struct{})

	go func() {
		for range w.debounceCh {
			count++
			if count >= 1 {
				close(done)
				return
			}
		}
	}()

	w.debounce()
	w.debounce()
	w.debounce()
	w.debounce()

	select {
	case <-done:
		if count != 1 {
			t.Errorf("expected 1 debounced event, got %d", count)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("debounce did not fire within 2 seconds")
	}
}

func TestDiffFindings(t *testing.T) {
	w := NewWatcher(context.Background(), 5*time.Minute, "")

	w.recordFindings([]scanner.Result{
		{Server: "a", Finding: "f1"},
		{Server: "b", Finding: "f2"},
	})

	current := []scanner.Result{
		{Server: "a", Finding: "f1"},
		{Server: "b", Finding: "f2"},
		{Server: "c", Finding: "f3"},
	}

	newFound := w.diffFindings(current)
	if len(newFound) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(newFound))
	}
	if newFound[0].Server != "c" || newFound[0].Finding != "f3" {
		t.Errorf("unexpected finding: %+v", newFound[0])
	}
}

func TestDiffFindingsNone(t *testing.T) {
	w := NewWatcher(context.Background(), 5*time.Minute, "")

	current := []scanner.Result{
		{Server: "a", Finding: "f1"},
		{Server: "b", Finding: "f2"},
	}

	w.recordFindings(current)
	newFound := w.diffFindings(current)
	if len(newFound) != 0 {
		t.Fatalf("expected 0 new findings, got %d", len(newFound))
	}
}

func TestPollChangesNoConfig(t *testing.T) {
	w := NewWatcher(context.Background(), 5*time.Minute, "")

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "not-a-config.json")
	if err := os.WriteFile(tmpFile, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	w.lastModTimes[tmpDir] = time.Now()
	w.pollChanges()
}
