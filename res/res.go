package res

import (
	"net/http"
	"reflect"

	"github.com/go-chi/render"
)

type Response struct {
	Code   string  `json:"code,omitempty"`
	Msg    string  `json:"message,omitempty"`
	Data   *Data   `json:"data,omitempty"`
	Errors *Errors `json:"errors,omitempty"`
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

type Items []Item
type Item interface{}

type Error struct {
	HttpCode int    `json:"-"`
	Code     string `json:"code,omitempty"`
	Field    string `json:"field,omitempty"`
	Msg      string `json:"message,omitempty"`
}
type Errors []Error

func WithErrMsg(w http.ResponseWriter, r *http.Request, code int, errMsg string) {
	render.Status(r, code)
	render.JSON(w, r, &Response{
		Msg: errMsg,
	})
}

func WithError(w http.ResponseWriter, r *http.Request, code int, err Error) {
	render.Status(r, code)
	render.JSON(w, r, &Response{
		Code: err.Code,
		Msg:  err.Msg,
	})
}

func WithErrors(w http.ResponseWriter, r *http.Request, code int, errors Errors) {
	render.Status(r, code)
	render.JSON(w, r, &Response{
		Errors: &errors,
	})
}

func WithData(w http.ResponseWriter, r *http.Request, data interface{}) {
	if reflect.TypeOf(data).Kind() == reflect.Slice {
		WithItems(w, r, data.(Items))
	} else {
		WithItem(w, r, data)
	}
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

func WithNoContent(w http.ResponseWriter, r *http.Request, code int) {
	render.Status(r, code)
	render.JSON(w, r, http.NoBody)
}
