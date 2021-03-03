package data

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
