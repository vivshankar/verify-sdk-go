package logx

import (
	"fmt"
	"io"
	"log/slog"
)

type Logger struct {
	*slog.Logger

	AddNewline bool
}

func (l *Logger) Errorf(str string, args ...any) {
	if l.AddNewline {
		str = str + "\n"
	}
	l.Error(fmt.Sprintf(str, args...))
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
