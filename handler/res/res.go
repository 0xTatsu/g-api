package res

//
// import (
// 	"net/http"
//
// 	"github.com/go-chi/render"
// )
//
// type Response struct {
// 	Msg    string  `json:"message,omitempty"`
// 	Data   *Data   `json:"data,omitempty"`
// 	Errors *Errors `json:"errors,omitempty"`
// }
//
// type Data struct {
// 	Items Items `json:"items,omitempty"`
//
// 	// paging
// 	TotalItems   int `json:"totalItems,omitempty"`
// 	ItemsPerPage int `json:"itemsPerPage,omitempty"`
// 	TotalPages   int `json:"totalPages,omitempty"`
// 	PageIndex    int `json:"pageIndex,omitempty"`
// 	StartIndex   int `json:"startIndex,omitempty"`
// }
//
// type Item interface{}
// type Items []Item
//
// type Error struct {
// 	Code  string `json:"code,omitempty"`
// 	Field string `json:"field,omitempty"`
// 	Msg   string `json:"message,omitempty"`
// }
// type Errors []Error
//
// func WithItems(w http.ResponseWriter, r *http.Request, items Items) {
// 	render.Status(r, http.StatusOK)
// 	render.JSON(w, r, &Response{
// 		Data: &Data{
// 			Items: items,
// 		},
// 	})
// }
//
// func WithItem(w http.ResponseWriter, r *http.Request, item Item) {
// 	render.Status(r, http.StatusOK)
// 	render.JSON(w, r, &Response{
// 		Data: &Data{
// 			Items: []Item{item},
// 		},
// 	})
// }
//
// func NoData(w http.ResponseWriter, r *http.Request, httpStatus int) {
// 	render.Status(r, httpStatus)
// 	render.JSON(w, r, http.NoBody)
// }
//
// func Created(w http.ResponseWriter, r *http.Request) {
// 	NoData(w, r, http.StatusCreated)
// }
//
// func Updated(w http.ResponseWriter, r *http.Request) {
// 	NoData(w, r, http.StatusNoContent)
// }
//
// func Unauthorized(w http.ResponseWriter, r *http.Request) {
// 	NoData(w, r, http.StatusUnauthorized)
// }
//
// func InternalServerError(w http.ResponseWriter, r *http.Request) {
// 	NoData(w, r, http.StatusInternalServerError)
// }
//
// func WithError(w http.ResponseWriter, r *http.Request, err Error) {
// 	render.Status(r, http.StatusBadRequest)
// 	render.JSON(w, r, &Response{
// 		Errors: &Errors{err},
// 	})
// }
//
// func WithErrors(w http.ResponseWriter, r *http.Request, errors Errors) {
// 	render.Status(r, http.StatusBadRequest)
// 	render.JSON(w, r, &Response{
// 		Errors: &errors,
// 	})
// }
//
// func DecodeError(w http.ResponseWriter, r *http.Request, err error) {
// 	render.Status(r, http.StatusBadRequest)
// 	render.JSON(w, r, &Response{
// 		Errors: &Errors{{Msg: err.Error()}},
// 	})
// }
//
// func ValidateErrors(w http.ResponseWriter, r *http.Request, errors Errors) {
// 	render.Status(r, http.StatusBadRequest)
// 	render.JSON(w, r, &Response{
// 		Errors: &errors,
// 	})
// }
