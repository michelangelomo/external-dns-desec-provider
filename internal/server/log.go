// Source: https://github.com/pytimer/mux-logrus/blob/master/middleware.go
// Package muxlogrus is a logrus middleware for gorilla/mux.
// Every request information will be record and output.
package server

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type timer interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

// realClock save request times
type realClock struct{}

func (rc *realClock) Now() time.Time {
	return time.Now()
}

func (rc *realClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// LogOptions logging middleware options
type LogOptions struct {
	Formatter      logrus.Formatter
	EnableStarting bool
}

// LoggingMiddleware is a middleware handler that logs the request as it goes in and the response as it goes out.
type LoggingMiddleware struct {
	logger         *logrus.Logger
	clock          timer
	enableStarting bool
}

// NewLogger returns a new *LoggingMiddleware, yay!
func NewLogger(opts ...LogOptions) *LoggingMiddleware {
	var opt LogOptions
	if len(opts) == 0 {
		opt = LogOptions{}
	} else {
		opt = opts[0]
	}

	if opt.Formatter == nil {
		opt.Formatter = &logrus.TextFormatter{
			DisableColors:   true,
			TimestampFormat: time.RFC3339,
		}
	}

	log := logrus.New()
	log.Formatter = opt.Formatter

	return &LoggingMiddleware{
		logger:         log,
		clock:          &realClock{},
		enableStarting: opt.EnableStarting,
	}
}

// realIP get the real IP from http request
func realIP(req *http.Request) string {
	ra := req.RemoteAddr
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		ra = strings.Split(ip, ", ")[0]
	} else if ip := req.Header.Get("X-Real-IP"); ip != "" {
		ra = ip
	} else {
		ra, _, _ = net.SplitHostPort(ra)
	}
	return ra
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *loggingResponseWriter) Write(b []byte) (int, error) {
	return lw.ResponseWriter.Write(b)
}

// Middleware implement mux middleware interface
func (m *LoggingMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		entry := logrus.NewEntry(m.logger)
		start := m.clock.Now()

		if reqID := r.Header.Get("X-Request-Id"); reqID != "" {
			entry = entry.WithField("requestId", reqID)
		}

		if remoteAddr := realIP(r); remoteAddr != "" {
			entry = entry.WithField("remoteAddr", remoteAddr)
		}

		if m.enableStarting {
			entry.WithFields(logrus.Fields{
				"request": r.RequestURI,
				"method":  r.Method,
			}).Info("started handling request")
		}

		lw := newLoggingResponseWriter(w)
		next.ServeHTTP(lw, r)

		latency := m.clock.Since(start)

		entry.WithFields(logrus.Fields{
			"status": lw.statusCode,
			"took":   latency,
		}).Info("completed handling request")
	})
}
