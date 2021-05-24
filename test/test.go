package test

import (
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/0xTatsu/mvtn-api/handler/res"
)

var ErrTest = errors.New("mock error")

func Body2Response(t *testing.T, body io.Reader) res.Response {
	t.Helper()
	response := res.Response{}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		t.Fatalf("cannot parse body (%v) to response struct: '%v'", body, err)
	}

	return response
}
