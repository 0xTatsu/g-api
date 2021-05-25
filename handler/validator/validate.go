package validator

import (
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/0xTatsu/g-api/handler/res"
)

type Validator struct {
	validator *validator.Validate
}

func New(validator *validator.Validate) *Validator {
	return &Validator{
		validator: validator,
	}
}

func (v Validator) Validate(input interface{}) []res.ErrorItem {
	err := v.validator.Struct(input)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			zap.L().Error(err.Error())

			return nil
		}

		errItems := make([]res.ErrorItem, 0)
		for _, err := range err.(validator.ValidationErrors) {
			errItems = append(errItems, res.ErrorItem{
				Field:   err.Field(),
				Message: errMsgByTag(err),
			})
		}

		return errItems
	}
	return nil
}

func errMsgByTag(err validator.FieldError) string {
	errMsgMap := map[string]string{
		"email":    "Invalid email",
		"required": err.Field() + " is required",
		"min":      "Minimum " + err.Param(),
		"max":      "Maximum " + err.Param(),
		"eqfield":  err.Field() + " doesn't match " + err.Param(),
	}

	msg, exist := errMsgMap[err.ActualTag()]
	if !exist {
		return "failed on " + err.ActualTag() + " validation"
	}

	return msg
}
