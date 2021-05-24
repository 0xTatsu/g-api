package res

import (
	"net/http"

	"github.com/go-chi/render"
)

type Response struct {
	Message string `json:"message,omitempty"`
	Data    *Data  `json:"data,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Data struct {
	Items Items `json:"items,omitempty"`

	// paging
	TotalItems   int `json:"totalItems,omitempty"`
	ItemsPerPage int `json:"itemsPerPage,omitempty"`
	TotalPages   int `json:"totalPages,omitempty"`
	PageIndex    int `json:"pageIndex,omitempty"`
	StartIndex   int `json:"startIndex,omitempty"`
}

type Item interface{}
type Items []Item

type Error struct {
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Errors  []ErrorItem `json:"errors,omitempty"`
}

type ErrorItem struct {
	Code    int    `json:"code,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message,omitempty"`
}

func WithItems(w http.ResponseWriter, r *http.Request, items Items) {
	render.Status(r, http.StatusOK)
	render.JSON(w, r, &Response{
		Data: &Data{
			Items: items,
		},
	})
}

func WithItem(w http.ResponseWriter, r *http.Request, item Item) {
	render.Status(r, http.StatusOK)
	render.JSON(w, r, &Response{
		Data: &Data{
			Items: []Item{item},
		},
	})
}

func WithErrors(w http.ResponseWriter, r *http.Request, errors []ErrorItem) {
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, &Response{
		Error: &Error{
			Errors: errors,
		},
	})
}

func WithErrorMsg(w http.ResponseWriter, r *http.Request, errorMsg string) {
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, &Response{
		Error: &Error{
			Message: errorMsg,
		},
	})
}

func NoData(w http.ResponseWriter, r *http.Request, httpStatus int) {
	render.Status(r, httpStatus)
	render.JSON(w, r, &Response{
		Message: http.StatusText(httpStatus),
	})
}

func Created(w http.ResponseWriter, r *http.Request) {
	NoData(w, r, http.StatusCreated)
}

func NoContent(w http.ResponseWriter, r *http.Request) {
	NoData(w, r, http.StatusNoContent)
}

func Unauthorized(w http.ResponseWriter, r *http.Request) {
	NoData(w, r, http.StatusUnauthorized)
}

func InternalServerError(w http.ResponseWriter, r *http.Request) {
	NoData(w, r, http.StatusInternalServerError)
}
