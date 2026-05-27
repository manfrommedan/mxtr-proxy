// Package main — logger.go
//
// A tiny level-aware logger built on top of `log/slog`. The server can run
// from totally silent ("-log-level off") through "-log-level debug".
//
// We expose package-level helpers (logErrorf, logInfof, logWarnf) so the rest
// of the code reads like log.Printf would, while routing through slog and
// honouring the global level.

package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// LogLevel is the configured threshold; below it everything is dropped.
type LogLevel int

const (
	LogOff LogLevel = iota
	LogError
	LogWarn
	LogInfo
	LogDebug
)

// Stored as atomic so it can be tweaked at runtime if we ever expose a control
// channel. Default is Info to match historical log.Printf behaviour.
var currentLogLevel atomic.Int32

func init() {
	currentLogLevel.Store(int32(LogInfo))
}

func parseLogLevel(s string) (LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none", "silent":
		return LogOff, nil
	case "error", "err":
		return LogError, nil
	case "warn", "warning":
		return LogWarn, nil
	case "info":
		return LogInfo, nil
	case "debug", "trace":
		return LogDebug, nil
	default:
		return LogOff, fmt.Errorf("unknown log level %q (off/error/warn/info/debug)", s)
	}
}

// configureLogger applies the chosen level and silences the default log
// package writer when level == off (so accidental log.Printf calls in libs
// also stay quiet).
func configureLogger(level LogLevel) {
	currentLogLevel.Store(int32(level))
	switch level {
	case LogOff:
		slog.SetDefault(slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 100})))
	case LogError:
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	case LogWarn:
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	case LogInfo:
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	case LogDebug:
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func logEnabled(level LogLevel) bool {
	return LogLevel(currentLogLevel.Load()) >= level
}

func logErrorf(format string, args ...any) {
	if logEnabled(LogError) {
		slog.Error(fmt.Sprintf(format, args...))
	}
}

func logWarnf(format string, args ...any) {
	if logEnabled(LogWarn) {
		slog.Warn(fmt.Sprintf(format, args...))
	}
}

func logInfof(format string, args ...any) {
	if logEnabled(LogInfo) {
		slog.Info(fmt.Sprintf(format, args...))
	}
}

