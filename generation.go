package validator

import (
	"fmt"

	myasthurts "github.com/jamillosantos/go-my-ast-hurts"
	"github.com/jamillosantos/go-validator/tagparser"
	"github.com/pkg/errors"
	"github.com/valyala/quicktemplate"
)

type ValidationData struct {
	Params []string
}

type ValidationPair struct {
	Validation *ValidationRegistration
	Data       *ValidationData
}

type StructData struct {
	Struct *myasthurts.Struct
	Fields []*FieldData
}

type FieldData struct {
	// Field       *myasthurts.Field
	Name        string
	Identifier  string
	IsPointer   bool
	IsArray     bool
	IsNumeric   bool
	IsBoolean   bool
	IsString    bool
	Validations []*ValidationPair
}

func NewFieldData(field *myasthurts.Field) *FieldData {
	_, isPointer := field.RefType.(*myasthurts.StarRefType)
	_, isArray := field.RefType.(*myasthurts.ArrayRefType)
	isNumeric := false
	isBoolean := false
	isString := false
	switch field.RefType.Name() {
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64",
		"complex64", "complex128":
		isNumeric = true
	case "bool":
		isBoolean = true
	case "string":
		isString = true
	}

	v := make([]*ValidationPair, 0)

	validationsFromTag := tagparser.Parse(field.Tag.Raw)
	for _, validation := range validationsFromTag {
		registeredValidation, ok := validations[validation.Name]
		if !ok {
			fmt.Println(field.Tag.Raw)
			panic(errors.Errorf("validation %s not found: %s:%d", validation.Name, field.Position.FileName, field.Position.Line))
		}
		v = append(v, &ValidationPair{
			Validation: registeredValidation,
			Data: &ValidationData{
				Params: validation.Params,
			},
		})
	}

	identifier := field.Name

	jsonName := field.Tag.TagParamByName("json")
	if jsonName != nil {
		identifier = jsonName.Value
	}

	return &FieldData{
		Name:        field.Name,
		Identifier:  identifier,
		IsPointer:   isPointer,
		IsArray:     isArray,
		IsNumeric:   isNumeric,
		IsBoolean:   isBoolean,
		IsString:    isString,
		Validations: v,
	}
}

type ValidationGenerationFunc = func(w *quicktemplate.Writer, s *StructData, field *FieldData, validation *ValidationData)

type ValidateValidationField = func(s *StructData, field *FieldData, validation *ValidationData) error

type ImportData struct {
	Name string
	Path string
}

type ValidationRegistration struct {
	Func          ValidationGenerationFunc
	Imports       []*ImportData
	ValidateField ValidateValidationField
}

var (
	validations                  = map[string]*ValidationRegistration{}
	ErrFunctionAlreadyRegistered = errors.New("function already registered")
)

func RegisterValidation(name string, r *ValidationRegistration) error {
	if _, ok := validations[name]; ok {
		return errors.Wrap(ErrFunctionAlreadyRegistered, name)
	}
	validations[name] = r
	return nil
}

func MustRegisterValidation(name string, r *ValidationRegistration) {
	err := RegisterValidation(name, r)
	if err != nil {
		panic(err)
	}
}
