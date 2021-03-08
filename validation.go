package validator

// Validable abstracts the behavior of a struct that can be validated.
type Validable interface {
	// Validate validates the struct
	Validate() error
}

// CustomValidation is used to implement custom validations that are not
// directly supported by the library.
//
// The generate `Validate` method will call the `CustomValidation`
// automatically, if the model implements it.
type CustomValidation interface {
	CustomValidate() error
}

// FieldContext is the information that is passed to the validation function `Func`.
type FieldContext struct {
	Tag    string
	Params []string
	Value  interface{}
	Source interface{}
}
