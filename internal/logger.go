package internal

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	gvisorlog "github.com/sagernet/gvisor/pkg/log"
)

// tzStampWriter wraps an io.Writer and prepends each record with a
// timestamp that includes the local timezone abbreviation, e.g.
//
//	2026/04/14 09:15:09 MSK Connecting to endpoint ...
//
// It is intended to be installed as the output of a stdlib *log.Logger
// whose date/time flags have been cleared (see InstallDefaultLogTZStamp
// and NewTZStampLogger), so the prefix is produced here instead of by
// the log package. Safe for concurrent use.
type tzStampWriter struct {
	mu sync.Mutex
	w  io.Writer
}

const tzStampLayout = "2006/01/02 15:04:05 MST "

func (t *tzStampWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	stamp := time.Now().Format(tzStampLayout)
	var buf bytes.Buffer
	buf.Grow(len(stamp) + len(p))
	buf.WriteString(stamp)
	buf.Write(p)
	if _, err := t.w.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

// NewTZStampWriter wraps w so every record written to it is prefixed
// with a local timestamp plus timezone abbreviation.
//
// The caller is responsible for ensuring the attached logger does not
// also emit its own date/time prefix (i.e. use flags = 0).
func NewTZStampWriter(w io.Writer) io.Writer {
	return &tzStampWriter{w: w}
}

var (
	logWriter io.Writer = os.Stderr
	logMu     sync.Mutex
)

// GetLogWriter returns the currently configured log writer (e.g., stderr or a multi-writer with a file).
func GetLogWriter() io.Writer {
	logMu.Lock()
	defer logMu.Unlock()
	return logWriter
}

// SetupLogging configures both standard logging and gVisor logging to write only to the given file (and not to the terminal/stderr), falling back to stderr if no file is configured.
func SetupLogging(filePath string) error {
	logMu.Lock()
	defer logMu.Unlock()

	var w io.Writer = os.Stderr
	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file %q: %v", filePath, err)
		}
		w = f
	}
	logWriter = w

	log.SetFlags(0)
	log.SetPrefix("")
	tzWriter := NewTZStampWriter(w)
	log.SetOutput(tzWriter)
	gvisorlog.SetTarget(&gvisorlog.Writer{Next: tzWriter})
	return nil
}

// InstallDefaultLogTZStamp rewires the stdlib default logger so every
// record is prefixed with "YYYY/MM/DD HH:MM:SS <TZ> ", regardless of
// whether the host has zoneinfo available. This addresses log lines
// being indistinguishable between local time and UTC on systems where
// time.Local silently falls back to UTC (e.g. OpenWrt/busybox).
//
// It also redirects gVisor's global logger (used by the netstack) away
// from the default Google/glog-style emitter so tunnel-related lines
// match the same prefix and stderr stream.
func InstallDefaultLogTZStamp() {
	log.SetFlags(0)
	log.SetPrefix("")
	w := NewTZStampWriter(GetLogWriter())
	log.SetOutput(w)
	gvisorlog.SetTarget(&gvisorlog.Writer{Next: w})
}
