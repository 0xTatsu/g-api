package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"github.com/0xTatsu/g-api/handler"
	"github.com/0xTatsu/g-api/res"
	"github.com/0xTatsu/g-api/test"
)

func Test_Handler(t *testing.T) {
	tc := []struct {
		name           string
		data           interface{}
		err            error
		expectHttpCode int
		expectBody     string
	}{
		{
			"Error: WithNoContent",
			nil,
			res.Error{HttpCode: http.StatusInternalServerError},
			http.StatusInternalServerError,
			``,
		},
		{
			"Error: WithError",
			nil,
			res.Error{Errors: &res.Errors{{Code: "1", Field: "2", Msg: "3"}}},
			http.StatusBadRequest,
			`{"error":{"errors":[{"code":"1","field":"2","message":"3"}]}}`,
		},
		{
			"Error: WithErrMsg",
			nil,
			test.ErrTest,
			http.StatusBadRequest,
			`{"message":"mock error"}`,
		},
		{
			"Data: WithNoContent ",
			http.StatusCreated,
			nil,
			http.StatusCreated,
			``,
		},
		{
			"Data: WithItem",
			struct{ ID int }{ID: 1},
			nil,
			http.StatusOK,
			`{"data":{"items":[{"ID":1}]}}`,
		},
		{
			"Data: WithItems",
			[]struct{ ID int }{{ID: 1}, {ID: 2}},
			nil,
			http.StatusOK,
			`{"data":{"items":[{"ID":1},{"ID":2}]}}`,
		},
	}

	for _, c := range tc {
		c := c
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			testHandler := func(w http.ResponseWriter, r *http.Request) (interface{}, error) {
				return c.data, c.err
			}
			route := chi.NewRouter()
			route.Method(http.MethodPost, "/", handler.Handler{H: testHandler})
			route.ServeHTTP(w, r)

			assert.Equal(t, w.Code, c.expectHttpCode)
			if w.Body.String() != "" {
				assert.JSONEq(t, c.expectBody, w.Body.String())
			} else {
				assert.Equal(t, c.expectBody, w.Body.String())
			}
		})
	}
}
