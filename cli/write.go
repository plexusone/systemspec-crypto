package cli

import (
	"fmt"
	"io"
)

// errWriter wraps an io.Writer and records the first write error, letting a
// sequence of formatted writes be issued without checking each one. Callers
// check Err once after the sequence.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

func (ew *errWriter) println(a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w, a...)
}

func (ew *errWriter) Err() error { return ew.err }
