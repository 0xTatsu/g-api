package res

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
)

type Response struct {
	HTTPStatus int          `json:"-"` // http response status code
	Ok         bool         `json:"ok"`
	Data       *Data        `json:"data,omitempty"` // application-level error message, for debugging
	Error      *ErrorItem   `json:"error,omitempty"`
	Errors     []*ErrorItem `json:"errors,omitempty"`
}

type Data struct {
	ItemsPerPage int `json:"itemsPerPage,omitempty"`
	TotalItems   int `json:"totalItems,omitempty"`
	PageIndex    int `json:"pageIndex,omitempty"`

	Items []json.RawMessage `json:"items,omitempty"`
	Item  *json.RawMessage  `json:"Item,omitempty"`
}

type ErrorItem struct {
	Code    int    `json:"code,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
}

func Error(w http.ResponseWriter, r *http.Request, httpStatus int, err string) {
	render.Status(r, httpStatus)
	render.JSON(w, r, &Response{
		Ok:    false,
		Error: &ErrorItem{Message: err},
	})
}

func Errors(w http.ResponseWriter, r *http.Request, httpStatus int, errItems []*ErrorItem) {
	render.Status(r, httpStatus)
	render.JSON(w, r, &Response{
		Ok:     false,
		Errors: errItems,
	})
}
