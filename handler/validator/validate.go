package validator

import (
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/0xTatsu/g-api/res"
)

type Validator struct {
	validator *validator.Validate
}

func New() *Validator {
	return &Validator{
		validator: validator.New(),
	}
}

func (v Validator) Validate(input interface{}) res.Error {
	err := v.validator.Struct(input)
	if err != nil {
		var validatorErr *validator.InvalidValidationError
		if errors.As(err, &validatorErr) {
			zap.L().Error("failed to parse validation errors", zap.Error(err))

			return res.Error{
				HTTPCode: http.StatusInternalServerError,
				Msg:      http.StatusText(http.StatusInternalServerError),
			}
		}

		e := res.Errors{}
		var appErrors validator.ValidationErrors
		if errors.As(err, &appErrors) {
			for _, err := range appErrors {
				e = append(e, res.ErrorItem{
					Field: err.Field(),
					Msg:   errMsgByTag(err),
				})
			}
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
		"email":    "invalid email",
		"required": err.Field() + " is required",
		"number":   err.Field() + " is not a number",
		"datetime": err.Field() + " is not a datetime",
		// "excluded_without": err.Param() + " is required with " + err.Field(),
	}

	msg, exist := errMsgMap[err.ActualTag()]
	if !exist {
		return err.Field() + " failed on " + err.ActualTag() + " validation"
	}

	return msg
}
