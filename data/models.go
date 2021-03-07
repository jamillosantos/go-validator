package data

type RequiredValidation struct {
	Name        string  `json:"name"     validate:"required"`
	NamePointer *string `json:"name_ptr" validate:"required"`
}

type EmailValidation struct {
	Email        string  `json:"email" validate:"email"`
	EmailPointer *string `validate:"email"`
}

type MinValidation struct {
	Name       string   `json:"name"      validate:"min=3"`
	NamePtr    *string  `json:"name_ptr"  validate:"min=3"`
	Names      []string `json:"names"     validate:"min=3"`
	Age        int      `json:"age"       validate:"min=35"`
	AgePointer *int     `json:"age_ptr"   validate:"min=35"`
}

type MaxValidation struct {
	Name       string   `json:"name"      validate:"max=3"`
	NamePtr    *string  `json:"name_ptr"  validate:"max=3"`
	Names      []string `json:"names"     validate:"max=3"`
	Age        int      `json:"age"       validate:"max=35"`
	AgePointer *int     `json:"age_ptr"   validate:"max=35"`
}

// User contains user information
type User struct {
	FirstName      string `json:"fname"`
	LastName       string `json:"lname"`
	Age            uint8  `json:"age" validate:"gte=0,lte=130"`
	Email          string `json:"email" validate:"required,email"`
	FavouriteColor string `json:"favourite_color" validate:"hexcolor|rgb|rgba"`
	// Addresses      []*Address `json:"addresses" validate:"required,dive,required"` // a person can have a home and cottage...
}

// Address houses a users address information
type Address struct {
	Street string `json:"street" validate:"required"`
	City   string `json:"city" validate:"required"`
	Planet string `json:"planet" validate:"required"`
	Phone  string `json:"phone" validate:"required"`
}
