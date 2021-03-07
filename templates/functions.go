package templates

import "github.com/jamillosantos/go-validator"

func init() {
	validator.MustRegisterValidation("required", &validator.ValidationRegistration{
		Func: StreamHasValue,
	})
	validator.MustRegisterValidation("isdefault", &validator.ValidationRegistration{
		Func: StreamIsDefault,
	})
	validator.MustRegisterValidation("gte", &validator.ValidationRegistration{
		Func: StreamGte,
	})
	validator.MustRegisterValidation("lte", &validator.ValidationRegistration{
		Func: StreamLte,
	})
	validator.MustRegisterValidation("min", &validator.ValidationRegistration{
		Func: StreamMin,
	})
	validator.MustRegisterValidation("max", &validator.ValidationRegistration{
		Func: StreamMax,
	})
	validator.MustRegisterValidation("email", &validator.ValidationRegistration{
		Func:    StreamEmail,
		Imports: []*validator.ImportData{},
	})
	validator.MustRegisterValidation("hexcolor", &validator.ValidationRegistration{
		Func:    StreamHexcolor,
		Imports: []*validator.ImportData{},
	})
	validator.MustRegisterValidation("rgba", &validator.ValidationRegistration{
		Func:    StreamRGBa,
		Imports: []*validator.ImportData{},
	})
	validator.MustRegisterValidation("rgb", &validator.ValidationRegistration{
		Func:    StreamRGB,
		Imports: []*validator.ImportData{},
	})
}
