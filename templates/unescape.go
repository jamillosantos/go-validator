package templates

import (
	"io"

	"github.com/valyala/quicktemplate"
)

func writeunesc(iow io.Writer, s string) {
	qw := quicktemplate.AcquireWriter(iow)
	streamunesc(qw, s)
	quicktemplate.ReleaseWriter(qw)
}

func unesc(s string) string {
	qb := quicktemplate.AcquireByteBuffer()
	writeunesc(qb, s)
	qs := string(qb.B)
	quicktemplate.ReleaseByteBuffer(qb)
	return qs
}

func streamunesc(qw *quicktemplate.Writer, s string) {
	qw.N().S(s)
}
