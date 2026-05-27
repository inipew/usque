package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	gvisorlog "github.com/sagernet/gvisor/pkg/log"
	"github.com/sagernet/sing/common/logger"
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

// Level represents the log severity level
type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
	LevelPanic
)

// ParseLevel converts a string into a Level representation
func ParseLevel(level string) Level {
	switch strings.ToLower(level) {
	case "trace":
		return LevelTrace
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	case "panic":
		return LevelPanic
	default:
		return LevelInfo
	}
}

// FormatLevel converts a Level into its string representation
func FormatLevel(level Level) string {
	switch level {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	case LevelPanic:
		return "PANIC"
	default:
		return "INFO"
	}
}

var (
	currentLogLevel Level = LevelInfo
)

// SetLogLevel updates the active global log filtering level
func SetLogLevel(level Level) {
	currentLogLevel = level
}

type appLogger struct {
	tag string
}

// NewLogger creates a new logger.ContextLogger with the given tag
func NewLogger(tag string) logger.ContextLogger {
	return &appLogger{tag: tag}
}

func (l *appLogger) log(level Level, ctx context.Context, args ...any) {
	if level < currentLogLevel {
		return
	}

	w := GetLogWriter()
	stamp := time.Now().Format("2006/01/02 15:04:05 MST ")

	var msg string
	if len(args) == 1 {
		msg = fmt.Sprint(args[0])
	} else {
		msg = fmt.Sprint(args...)
	}

	levelStr := FormatLevel(level)
	var output string
	if l.tag != "" {
		output = fmt.Sprintf("%s[%s] %s: %s\n", stamp, levelStr, l.tag, msg)
	} else {
		output = fmt.Sprintf("%s[%s] %s\n", stamp, levelStr, msg)
	}

	_, _ = w.Write([]byte(output))

	if level == LevelPanic {
		panic(msg)
	} else if level == LevelFatal {
		os.Exit(1)
	}
}

// Drop-in compatibility with standard *log.Logger
func (l *appLogger) Printf(format string, v ...any) {
	l.log(LevelInfo, nil, fmt.Sprintf(format, v...))
}

func (l *appLogger) Println(v ...any) {
	l.log(LevelInfo, nil, v...)
}

func (l *appLogger) Print(v ...any) {
	l.log(LevelInfo, nil, v...)
}

// Trace logs trace args
func (l *appLogger) Trace(args ...any) { l.log(LevelTrace, nil, args...) }
func (l *appLogger) Debug(args ...any) { l.log(LevelDebug, nil, args...) }
func (l *appLogger) Info(args ...any)  { l.log(LevelInfo, nil, args...) }
func (l *appLogger) Warn(args ...any)  { l.log(LevelWarn, nil, args...) }
func (l *appLogger) Error(args ...any) { l.log(LevelError, nil, args...) }
func (l *appLogger) Fatal(args ...any) { l.log(LevelFatal, nil, args...) }
func (l *appLogger) Panic(args ...any) { l.log(LevelPanic, nil, args...) }

// TraceContext logs trace args with context
func (l *appLogger) TraceContext(ctx context.Context, args ...any) { l.log(LevelTrace, ctx, args...) }
func (l *appLogger) DebugContext(ctx context.Context, args ...any) { l.log(LevelDebug, ctx, args...) }
func (l *appLogger) InfoContext(ctx context.Context, args ...any)  { l.log(LevelInfo, ctx, args...) }
func (l *appLogger) WarnContext(ctx context.Context, args ...any)  { l.log(LevelWarn, ctx, args...) }
func (l *appLogger) ErrorContext(ctx context.Context, args ...any) { l.log(LevelError, ctx, args...) }
func (l *appLogger) FatalContext(ctx context.Context, args ...any) { l.log(LevelFatal, ctx, args...) }
func (l *appLogger) PanicContext(ctx context.Context, args ...any) { l.log(LevelPanic, ctx, args...) }
