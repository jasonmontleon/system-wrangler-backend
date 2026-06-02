// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInstantBySystemParsesVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"status":"success",
			"data":{"resultType":"vector","result":[
				{"metric":{"system_id":"a"},"value":[1700000000,"91.5"]},
				{"metric":{"system_id":"b"},"value":[1700000000,"42"]},
				{"metric":{"__name__":"x"},"value":[1700000000,"7"]},
				{"metric":{"system_id":"c"},"value":[1700000000,"NaN"]}
			]}
		}`))
	}))
	defer srv.Close()

	q := &PrometheusQuerier{BaseURL: srv.URL}
	got, err := q.InstantBySystem(context.Background(), "up")
	if err != nil {
		t.Fatalf("InstantBySystem: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 systems (no-system-id and NaN dropped), got %d: %v", len(got), got)
	}
	if got["a"] != 91.5 || got["b"] != 42 {
		t.Errorf("values wrong: %v", got)
	}
	if _, ok := got["c"]; ok {
		t.Error("NaN sample should be dropped")
	}
}

func TestInstantBySystemUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`))
	}))
	defer srv.Close()

	q := &PrometheusQuerier{BaseURL: srv.URL}
	if _, err := q.InstantBySystem(context.Background(), "!!!"); err == nil {
		t.Error("expected error from upstream error status")
	}
}

func TestInstantBySystemNonVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"scalar","result":[1700000000,"1"]}}`))
	}))
	defer srv.Close()
	q := &PrometheusQuerier{BaseURL: srv.URL}
	if _, err := q.InstantBySystem(context.Background(), "1"); err == nil {
		t.Error("expected error for non-vector result")
	}
}

func TestInstantBySystemNoBaseURL(t *testing.T) {
	q := &PrometheusQuerier{}
	if _, err := q.InstantBySystem(context.Background(), "up"); err == nil {
		t.Error("expected error when BaseURL is empty")
	}
}

func TestInstantBySystemUnreachableUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // closed immediately → connection refused
	q := &PrometheusQuerier{BaseURL: srv.URL}
	if _, err := q.InstantBySystem(context.Background(), "up"); err == nil {
		t.Error("expected transport error")
	}
}
