package validate

import (
	"fmt"

	"github.com/go-playground/validator/v10"

	"github.com/0xTatsu/mvtn-api/res"
)

func New() *validator.Validate {
	return validator.New()
}

func Validate(v *validator.Validate, generic interface{}) []*res.ErrorItem {
	err := v.Struct(generic)
	if err != nil {
		// this check is only needed when your code could produce
		// an invalid value for validation such as interface with nil
		// value most including myself do not usually have code like this.
		if _, ok := err.(*validator.InvalidValidationError); ok {
			fmt.Println(err)
			return nil
		}

		errItems := make([]*res.ErrorItem, 0)
		for _, err := range err.(validator.ValidationErrors) {
			errItems = append(errItems, &res.ErrorItem{
				Field:   err.Field(),
				Message: getVldErrorMsg(err),
			})
		}

		return errItems
	}
	return nil
}

var validationErrors = map[string]string{
	"required": "this field is required",
	// "min":      "'s value or length is less than allowed",
	"max":   "'s value or length is bigger than allowed",
	"email": "invalid email",
}

func getVldErrorMsg(err validator.FieldError) string {
	tag := err.ActualTag()
	if msg, exist := validationErrors[tag]; exist {
		return msg
	}

	if tag == "eqfield" {
		return err.Field() + " doesn't match " + err.Param()
	}

	if tag == "min" {
		// string: number of characters
		// slices, arrays, maps: number of items
		// duration: greater than or equal to the duration given
		switch err.Type().String() {
		case "string":
			return "minimum " + err.Param() + " characters"
		default:
			return "minimum " + err.Param()
		}
	}

	fmt.Println(err.Namespace())
	fmt.Println(err.Field())
	fmt.Println(err.StructNamespace())
	fmt.Println(err.StructField())
	fmt.Println(err.Tag())
	fmt.Println(err.ActualTag())
	fmt.Println(err.Kind())
	fmt.Println(err.Type())
	fmt.Println(err.Value())
	fmt.Println(err.Param())
	fmt.Println()

	return " failed on " + tag + " validation"
}
