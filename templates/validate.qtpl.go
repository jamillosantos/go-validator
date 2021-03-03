// Code generated by qtc from "validate.qtpl". DO NOT EDIT.
// See https://github.com/valyala/quicktemplate for details.

//line validate.qtpl:1
package templates

//line validate.qtpl:1
import "github.com/jamillosantos/go-validator"

//line validate.qtpl:3
import (
	qtio422016 "io"

	qt422016 "github.com/valyala/quicktemplate"
)

//line validate.qtpl:3
var (
	_ = qtio422016.Copy
	_ = qt422016.AcquireByteBuffer
)

//line validate.qtpl:3
func StreamValidate(qw422016 *qt422016.Writer, s *validator.StructData) {
//line validate.qtpl:3
	qw422016.N().S(`
func (v *`)
//line validate.qtpl:5
	qw422016.E().S(s.Struct.Name())
//line validate.qtpl:5
	qw422016.N().S(`) Validate() error {
	verr := make(validator.ValidationErrors, 0)

`)
//line validate.qtpl:8
	for _, field := range s.Fields {
//line validate.qtpl:9
		for _, validation := range field.Validations {
//line validate.qtpl:10
			streamvalidation := validation.Validation.Func

//line validate.qtpl:10
			qw422016.N().S(`
`)
//line validate.qtpl:11
			streamvalidation(qw422016, s, field, validation.Data)
//line validate.qtpl:11
			qw422016.N().S(`
`)
//line validate.qtpl:12
		}
//line validate.qtpl:13
	}
//line validate.qtpl:13
	qw422016.N().S(`
	if len(verr) > 0 {
		return verr
	}
	return nil
}

`)
//line validate.qtpl:21
}

//line validate.qtpl:21
func WriteValidate(qq422016 qtio422016.Writer, s *validator.StructData) {
//line validate.qtpl:21
	qw422016 := qt422016.AcquireWriter(qq422016)
//line validate.qtpl:21
	StreamValidate(qw422016, s)
//line validate.qtpl:21
	qt422016.ReleaseWriter(qw422016)
//line validate.qtpl:21
}

//line validate.qtpl:21
func Validate(s *validator.StructData) string {
//line validate.qtpl:21
	qb422016 := qt422016.AcquireByteBuffer()
//line validate.qtpl:21
	WriteValidate(qb422016, s)
//line validate.qtpl:21
	qs422016 := string(qb422016.B)
//line validate.qtpl:21
	qt422016.ReleaseByteBuffer(qb422016)
//line validate.qtpl:21
	return qs422016
//line validate.qtpl:21
}