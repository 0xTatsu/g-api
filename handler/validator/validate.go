package validator

import (
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/0xTatsu/g-api/res"
)

type Validator struct {
	validator *validator.Validate
}

func New(validator *validator.Validate) *Validator {
	return &Validator{
		validator: validator,
	}
}

func (v Validator) Validate(input interface{}) res.Error {
	err := v.validator.Struct(input)
	if err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			zap.L().Error(err.Error())

			return res.Error{}
		}

		e := res.Errors{}
		for _, err := range err.(validator.ValidationErrors) {
			e = append(e, res.ErrorItem{
				Field: err.Field(),
				Msg:   errMsgByTag(err),
			})
		}

		return res.Error{
			Code:   res.CodeValidationFailed,
			Msg:    "Validation failed",
			Errors: &e,
		}
	}

	return res.Error{}
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
