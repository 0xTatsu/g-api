package validator_test

import (
	"net/http"
	"testing"

	appValidator "github.com/0xTatsu/g-api/handler/validator"
	"github.com/0xTatsu/g-api/res"
	"github.com/stretchr/testify/assert"
)

func Test_Validate(t *testing.T) {
	t.Parallel()
	validation := appValidator.New()
	t.Run("throw error if invalidValidationError", func(t *testing.T) {
		err := validation.Validate("test")
		assert.Equal(t, err.HTTPCode, http.StatusInternalServerError)
	})

	testcases := []struct {
		name        string
		input       interface{}
		expectedMsg string
	}{
		{
			name: "email",
			input: struct {
				Invalid string `validate:"email"`
				Valid   string `validate:"email"`
			}{
				Invalid: "abc",
				Valid:   "abc@gmail.com",
			},
			expectedMsg: "invalid email",
		},
		{
			name: "required",
			input: struct {
				Invalid string `validate:"required"`
				Valid   string `validate:"required"`
			}{
				Invalid: "",
				Valid:   "abc",
			},
			expectedMsg: "Invalid is required",
		},
		{
			name: "number",
			input: struct {
				Invalid string `validate:"number"`
				Valid   int    `validate:"number"`
			}{
				Invalid: "abc",
				Valid:   123,
			},
			expectedMsg: "Invalid is not a number",
		},
		{
			name: "datetime",
			input: struct {
				Invalid string `validate:"datetime=2006-01-02"`
				Valid   string `validate:"datetime=2006-01-02"`
			}{
				Invalid: "1991-09-011",
				Valid:   "1991-09-01",
			},
			expectedMsg: "Invalid is not a datetime",
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name+" validation", func(t *testing.T) {
			t.Parallel()
			err := validation.Validate(tc.input)
			assert.Equal(t, err.Code, res.CodeValidationFailed)
			assert.Len(t, *err.Errors, 1)
			assert.Equal(t, (*err.Errors)[0].Field, "Invalid")
			assert.Equal(t, (*err.Errors)[0].Msg, tc.expectedMsg)
		})
	}
}
