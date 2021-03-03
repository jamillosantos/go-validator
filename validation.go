package validator

// Validable abstracts the behavior of a struct that can be validated.
type Validable interface {
	// Validate validates the struct
	Validate() error
}

// FieldLevel is the information that is passed to the validation function `Func`.
type FieldContext struct {
	Tag    string
	Params []string
	Value  interface{}
	Source interface{}
}
