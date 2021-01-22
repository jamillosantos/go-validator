package tagparser_test

import (
	"testing"

	"github.com/jamillosantos/go-validator/tagparser"
	"github.com/novln/macchiato"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestParser(t *testing.T) {
	RegisterFailHandler(Fail)
	macchiato.RunSpecs(t, "Parser Test Suite")
}

var _ = Describe("Parser", func() {
	It("should return nil for an invalid tag", func() {
		Expect(tagparser.Parse(`json:"fie`)).To(BeNil())
	})

	It("should return nil for an empty tag", func() {
		Expect(tagparser.Parse(`validate:""`)).To(BeNil())
	})

	It("should return nil when no validate is found", func() {
		Expect(tagparser.Parse(`json:"field1"`)).To(BeNil())
	})

	It("should parse one tag", func() {
		v := tagparser.Parse(`validate:"required"`)
		Expect(v).To(HaveLen(1))
		Expect(v[0].Name).To(Equal("required"))
		Expect(v[0].Params).To(BeEmpty())
	})

	It("should parse among two tag", func() {
		v := tagparser.Parse(`json:"field1" validate:"required"`)
		Expect(v).To(HaveLen(1))
		Expect(v[0].Name).To(Equal("required"))
		Expect(v[0].Params).To(BeEmpty())
	})

	It("should parse one tag with one param", func() {
		v := tagparser.Parse(`validate:"min=10"`)
		Expect(v).To(HaveLen(1))
		Expect(v[0].Name).To(Equal("min"))
		Expect(v[0].Params).To(Equal([]string{"10"}))
	})

	It("should parse one tag with multiple params", func() {
		v := tagparser.Parse(`validate:"between=10 20"`)
		Expect(v).To(HaveLen(1))
		Expect(v[0].Name).To(Equal("between"))
		Expect(v[0].Params).To(Equal([]string{"10", "20"}))
	})

	It("should parse one tag with multiple params with space", func() {
		v := tagparser.Parse(`validate:"between=10 'this is a test' 20"`)
		Expect(v).To(HaveLen(1))
		Expect(v[0].Name).To(Equal("between"))
		Expect(v[0].Params).To(Equal([]string{"10", "this is a test", "20"}))
	})
})
