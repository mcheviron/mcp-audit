package main

import (
	"fmt"
	"os"
	"time"
)

type spinner struct {
	stop   chan struct{}
	frames []string
}

func startSpinner(msg string) *spinner {
	s := &spinner{
		stop:   make(chan struct{}),
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%s %s", s.frames[i%len(s.frames)], msg)
				i++
			}
		}
	}()
	return s
}

func (s *spinner) clear() {
	close(s.stop)
}
