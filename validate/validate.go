package validate

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

func New() *validator.Validate {
	return validator.New()
}

func Validate(v *validator.Validate, generic interface{}) []string {
	err := v.Struct(generic)
	if err != nil {
		// this check is only needed when your code could produce
		// an invalid value for validation such as interface with nil
		// value most including myself do not usually have code like this.
		if _, ok := err.(*validator.InvalidValidationError); ok {
			fmt.Println(err)
			return nil
		}

		var errMessages []string
		for _, err := range err.(validator.ValidationErrors) {
			// errMessages = append(errMessages, fmt.Sprintf("%s is %s", err.StructNamespace(), err.Tag()))
			errMessages = append(errMessages, fmt.Sprintf("%s%s", err.Field(), getVldErrorMsg(err.ActualTag())))
		}

		return errMessages
	}
	return nil
}

var validationErrors = map[string]string{
	"required": " is required, but was not received",
	"min":      "'s value or length is less than allowed",
	"max":      "'s value or length is bigger than allowed",
}

func getVldErrorMsg(s string) string {
	if v, ok := validationErrors[s]; ok {
		return v
	}
	return " failed on " + s + " validation"
}
