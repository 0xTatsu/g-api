package handler

import (
	"net/http"

	"github.com/0xTatsu/g-api/config"
	"github.com/0xTatsu/g-api/res"
)

// Env An application-wide configuration.
type Env struct {
	Cfg       *config.Configuration
	Validator Validator
}

type Handler struct {
	H func(w http.ResponseWriter, r *http.Request) (interface{}, interface{})
}

// ServeHTTP allows our Handler type to satisfy http.Handler.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, err := h.H(w, r)
	if err != nil {
		switch err.(type) {
		case error:
			res.WithErrMsg(w, r, http.StatusBadRequest, err.(error).Error())
			return

		case res.Error:
			val := err.(res.Error)
			httpStatusCode := http.StatusBadRequest
			if val.HttpCode != 0 {
				httpStatusCode = val.HttpCode
			}

			if val.Code == "" && val.Msg == "" {
				res.WithNoContent(w, r, httpStatusCode)
				return
			}

			res.WithError(w, r, httpStatusCode, val)
			return

		case res.Errors:
			res.WithErrors(w, r, http.StatusBadRequest, err.(res.Errors))
			return

		// case Error:
		// 	// We can retrieve the status here and write out a specific
		// 	// HTTP status code.
		// 	log.Printf("HTTP %d - %s", e.Status(), e)
		// 	http.Error(w, e.Error(), e.Status())
		default:
			// Any error types we don't specifically look out for default
			// to serving a HTTP 500
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	if data != nil {
		switch data.(type) {
		case int:
			res.WithNoContent(w, r, data.(int))
		default:
			res.WithData(w, r, data)
			return
		}
	}
}

type Validator interface {
	Validate(input interface{}) res.Errors
}
