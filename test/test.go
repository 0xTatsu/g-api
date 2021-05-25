package test

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/0xTatsu/g-api/handler/res"
)

var ErrTest = errors.New("mock error")

func Body2Errors(t *testing.T, body io.Reader) res.Errors {
	t.Helper()
	response := res.Response{}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		t.Fatalf("cannot parse body (%v) to response struct: '%v'", body, err)
	}

	return *response.Errors
}

func Body2Items(t *testing.T, body io.Reader) []map[string]interface{} {
	t.Helper()
	response := res.Response{}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		t.Fatalf("cannot parse body (%v) to response struct: '%v'", body, err)
	}

	items := reflect.ValueOf(response.Data.Items)
	if items.Kind() != reflect.Slice {
		t.Fatalf("items type is not slice: '%v'", items.Kind())
	}

	data := make([]map[string]interface{}, items.Len())
	for i := 0; i < items.Len(); i++ {
		temp := items.Index(i).Interface()
		data[i] = temp.(map[string]interface{})
	}

	return data
}
