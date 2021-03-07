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
})
