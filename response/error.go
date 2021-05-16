package response

import (
	"net/http"

	"github.com/go-chi/render"
)

// ErrResponse renderer type for handling all sorts of errors.
type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging

	Errors []*FieldError `json:"errors,omitempty"`
}

type FieldError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Render sets the application-specific error code in AppCode.
func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

func Error(httpStatusCode int, err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: httpStatusCode,
		StatusText:     http.StatusText(httpStatusCode),
		ErrorText:      err.Error(),
	}
}

func Errors(httpStatusCode int, errors []*FieldError) render.Renderer {
	return &ErrResponse{
		HTTPStatusCode: httpStatusCode,
		StatusText:     http.StatusText(httpStatusCode),
		Errors:         errors,
	}
}
