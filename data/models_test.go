package data

import (
	"errors"

	"github.com/jamillosantos/go-validator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Validations", func() {
	Describe("Required", func() {
		nameValue := "S. Eyes"
		namePtrValue := "S. Eyes Ptr"
		emptyNamePtrValue := ""

		It("should validate", func() {
			data := RequiredValidation{
				Name:        "Name 1",
				NamePointer: &namePtrValue,
			}

			Expect(data.Validate()).To(Succeed())
		})

		It("should fail validating an empty name", func() {
			data := RequiredValidation{
				NamePointer: &namePtrValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr := err.(validator.ValidationErrors)
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name"))
			Expect(validationErr[0].Rule).To(Equal("required"))
			Expect(validationErr[0].Value).To(Equal(""))
			Expect(errors.Is(validationErr[0], validator.ErrRequired)).To(BeTrue())
		})

		It("should fail validating an empty pointer name", func() {
			data := RequiredValidation{
				Name:        nameValue,
				NamePointer: &emptyNamePtrValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr := err.(validator.ValidationErrors)
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name_ptr"))
			Expect(validationErr[0].Rule).To(Equal("required"))
			Expect(validationErr[0].Value).To(Equal(&emptyNamePtrValue))
			Expect(errors.Is(validationErr[0], validator.ErrRequired)).To(BeTrue())
		})

		It("should fail validating a nil pointer name", func() {
			data := RequiredValidation{
				Name:        nameValue,
				NamePointer: nil,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr := err.(validator.ValidationErrors)
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name_ptr"))
			Expect(validationErr[0].Rule).To(Equal("required"))
			Expect(validationErr[0].Value).To(BeNil())
			Expect(errors.Is(validationErr[0], validator.ErrRequired)).To(BeTrue())
		})
	})

	Describe("Email", func() {
		emailValue := "s.eyes@gijoe.com"
		invalidEmailValue := "this is not a valid email"
		emptyEmailPtrValue := ""

		It("should validate", func() {
			data := EmailValidation{
				Email:        emailValue,
				EmailPointer: &emailValue,
			}

			Expect(data.Validate()).To(Succeed())
		})

		It("should validate with empty data", func() {
			data := EmailValidation{}
			Expect(data.Validate()).To(Succeed())
		})

		It("should validate with empty data and non nil email pointer", func() {
			data := EmailValidation{
				EmailPointer: &emptyEmailPtrValue,
			}
			Expect(data.Validate()).To(Succeed())
		})

		It("should fail validating an invalid email", func() {
			data := EmailValidation{
				Email: invalidEmailValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr := err.(validator.ValidationErrors)
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("email"))
			Expect(validationErr[0].Rule).To(Equal("email"))
			Expect(validationErr[0].Value).To(Equal(invalidEmailValue))
			Expect(errors.Is(validationErr[0], validator.ErrEmail)).To(BeTrue())
			Expect(errors.Is(validationErr[0], validator.ErrInvalidFormat)).To(BeTrue())
		})

		It("should fail validating an invalid email pointer", func() {
			data := EmailValidation{
				EmailPointer: &invalidEmailValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr := err.(validator.ValidationErrors)
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("EmailPointer"))
			Expect(validationErr[0].Rule).To(Equal("email"))
			Expect(validationErr[0].Value).To(Equal(&invalidEmailValue))
			Expect(errors.Is(validationErr[0], validator.ErrEmail)).To(BeTrue())
		})

	})

	Describe("Min", func() {
		nameValue := "S.E"
		invalidNameValue := "se"
		namesValue := []string{"Snake Eyes", "Scarlet", "Duke"}
		invalidNamesValue := []string{"Snake Eyes", "Scarlet"}
		ageValue := 35
		invalidAgeValue := 34

		It("should validate", func() {
			data := MinValidation{
				Name:  nameValue,
				Names: namesValue,
				Age:   ageValue,
			}

			Expect(data.Validate()).To(Succeed())
		})

		It("should validate with empty data", func() {
			data := MinValidation{}

			Expect(data.Validate()).To(Succeed())
		})

		It("should fail validating a name too small", func() {
			data := MinValidation{
				Name: invalidNameValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name"))
			Expect(validationErr[0].Rule).To(Equal("min"))
			Expect(validationErr[0].Value).To(Equal(invalidNameValue))
			Expect(errors.Is(validationErr[0], validator.ErrMin)).To(BeTrue())
		})

		It("should fail validating a name pointer too small", func() {
			data := MinValidation{
				NamePtr: &invalidNameValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name_ptr"))
			Expect(validationErr[0].Rule).To(Equal("min"))
			Expect(validationErr[0].Value).To(Equal(&invalidNameValue))
			Expect(errors.Is(validationErr[0], validator.ErrMin)).To(BeTrue())
		})

		It("should fail validating a names too small", func() {
			data := MinValidation{
				Names: invalidNamesValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("names"))
			Expect(validationErr[0].Rule).To(Equal("min"))
			Expect(validationErr[0].Value).To(Equal(invalidNamesValue))
			Expect(errors.Is(validationErr[0], validator.ErrMin)).To(BeTrue())

		})

		It("should fail validating a numeric field", func() {
			data := MinValidation{
				Age: invalidAgeValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("age"))
			Expect(validationErr[0].Rule).To(Equal("min"))
			Expect(validationErr[0].Value).To(Equal(invalidAgeValue))
			Expect(errors.Is(validationErr[0], validator.ErrMin)).To(BeTrue())
		})

		It("should fail validating a numeric pointer field", func() {
			data := MinValidation{
				AgePointer: &invalidAgeValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("age_ptr"))
			Expect(validationErr[0].Rule).To(Equal("min"))
			Expect(validationErr[0].Value).To(Equal(&invalidAgeValue))
			Expect(errors.Is(validationErr[0], validator.ErrMin)).To(BeTrue())
		})
	})

	Describe("Max", func() {
		nameValue := "S.E"
		invalidNameValue := "S.E."
		namesValue := []string{"Snake Eyes", "Scarlet", "Duke"}
		invalidNamesValue := []string{"Snake Eyes", "Scarlet", "Duke", "Tank"}
		ageValue := 35
		invalidAgeValue := 36

		It("should validate", func() {
			data := MaxValidation{
				Name:       nameValue,
				Names:      namesValue,
				Age:        ageValue,
				NamePtr:    &nameValue,
				AgePointer: &ageValue,
			}

			Expect(data.Validate()).To(Succeed())
		})

		It("should validate with empty data", func() {
			data := MaxValidation{}

			Expect(data.Validate()).To(Succeed())
		})

		It("should fail validating a name too big", func() {
			data := MaxValidation{
				Name: invalidNameValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name"))
			Expect(validationErr[0].Rule).To(Equal("max"))
			Expect(validationErr[0].Value).To(Equal(invalidNameValue))
			Expect(errors.Is(validationErr[0], validator.ErrMax)).To(BeTrue())
		})

		It("should fail validating a name pointer too big", func() {
			data := MaxValidation{
				NamePtr: &invalidNameValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("name_ptr"))
			Expect(validationErr[0].Rule).To(Equal("max"))
			Expect(validationErr[0].Value).To(Equal(&invalidNameValue))
			Expect(errors.Is(validationErr[0], validator.ErrMax)).To(BeTrue())
		})

		It("should fail validating a names too big", func() {
			data := MaxValidation{
				Names: invalidNamesValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("names"))
			Expect(validationErr[0].Rule).To(Equal("max"))
			Expect(validationErr[0].Value).To(Equal(invalidNamesValue))
			Expect(errors.Is(validationErr[0], validator.ErrMax)).To(BeTrue())

		})

		It("should fail validating a numeric field", func() {
			data := MaxValidation{
				Age: invalidAgeValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("age"))
			Expect(validationErr[0].Rule).To(Equal("max"))
			Expect(validationErr[0].Value).To(Equal(invalidAgeValue))
			Expect(errors.Is(validationErr[0], validator.ErrMax)).To(BeTrue())
		})

		It("should fail validating a numeric pointer field", func() {
			data := MaxValidation{
				AgePointer: &invalidAgeValue,
			}

			err := data.Validate()
			Expect(err).To(HaveOccurred())
			validationErr, ok := err.(validator.ValidationErrors)
			Expect(ok).To(BeTrue())
			Expect(validationErr).To(HaveLen(1))
			Expect(validationErr[0].Field).To(Equal("age_ptr"))
			Expect(validationErr[0].Rule).To(Equal("max"))
			Expect(validationErr[0].Value).To(Equal(&invalidAgeValue))
			Expect(errors.Is(validationErr[0], validator.ErrMax)).To(BeTrue())
		})
	})
})
