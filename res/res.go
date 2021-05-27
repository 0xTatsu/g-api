package res

import (
	"net/http"
	"reflect"

	"github.com/go-chi/render"
)

type Response struct {
	Msg   string `json:"message,omitempty"`
	Data  *Data  `json:"data,omitempty"`
	Error *Error `json:"error,omitempty"`
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

type (
	Items []Item
	Item  interface{}
)

type Error struct {
	HttpCode int     `json:"-"`
	Code     string  `json:"code,omitempty"`
	Msg      string  `json:"message,omitempty"`
	Errors   *Errors `json:"errors,omitempty"`
}

func (e Error) Error() string {
	return ""
}

type ErrorItem struct {
	Code  string `json:"code,omitempty"`
	Field string `json:"field,omitempty"`
	Msg   string `json:"message,omitempty"`
}
type Errors []ErrorItem

func WithErrMsg(w http.ResponseWriter, r *http.Request, code int, errMsg string) {
	render.Status(r, code)
	render.JSON(w, r, &Response{
		Msg: errMsg,
	})
}

func WithError(w http.ResponseWriter, r *http.Request, code int, err Error) {
	render.Status(r, code)
	render.JSON(w, r, &Response{
		Error: &err,
	})
}

func WithData(w http.ResponseWriter, r *http.Request, data interface{}) {
	vData := reflect.ValueOf(data)
	if vData.Kind() != reflect.Slice {
		WithItem(w, r, data)
		return
	}

	// interfaces to []struct
	items := make(Items, vData.Len())
	for i := 0; i < vData.Len(); i++ {
		temp := vData.Index(i).Interface()
		items[i] = temp.(Item)
	}

	WithItems(w, r, items)
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
	w.WriteHeader(code)
}
