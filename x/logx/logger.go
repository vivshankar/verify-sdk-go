package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"time"
)

type Logger struct {
	*slog.Logger

	AddNewline bool
}

func (l *Logger) Errorf(str string, args ...any) {
	if l.AddNewline {
		str = str + "\n"
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])

	r := slog.NewRecord(time.Now(), slog.LevelError, fmt.Sprintf(str, args...), pcs[0])
	_ = l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Infof(str string, args ...any) {
	if l.AddNewline {
		str = str + "\n"
	}
	l.Info(fmt.Sprintf(str, args...))
}

func (l *Logger) Warnf(str string, args ...any) {
	if l.AddNewline {
		str = str + "\n"
	}
	l.Warn(fmt.Sprintf(str, args...))
}

func (l *Logger) Debugf(str string, args ...any) {
	if l.AddNewline {
		str = str + "\n"
	}
	l.Debug(fmt.Sprintf(str, args...))
}

// NewLoggerWithWriter returns a new logger instance with the
// specified context ID and prints out to the
// specified writer
func NewLoggerWithWriter(contextID string, level slog.Leveler, w io.Writer) *Logger {

	log := slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}).WithAttrs([]slog.Attr{
		{
			Key:   "contextID",
			Value: slog.StringValue(contextID),
		},
	}))

	wrapLog := &Logger{
		Logger: log,
	}

	return wrapLog
}
