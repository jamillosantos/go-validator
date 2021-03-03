package validator

import "github.com/pkg/errors"

type FieldError struct {
	Field string
	Rule  string
	Value interface{}
	err   error
}

func NewFieldError(err error, rule, field string, value interface{}) *FieldError {
	return &FieldError{
		Field: field,
		Rule:  rule,
		Value: value,
		err:   err,
	}
}

type ValidationErrors []*FieldError

func (err ValidationErrors) Error() string {
	return "validator error"
}

func (err *FieldError) Unwrap() error {
	return err.err
}

func (err *FieldError) Error() string {
	return err.Error()
}

var (
	ErrRequired  = errors.New("field required")
	ErrIsDefault = errors.New("field must have default value")
)
