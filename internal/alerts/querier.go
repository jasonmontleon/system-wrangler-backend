// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PromQuerier runs an instant PromQL query and returns the result keyed
// by the system_id label. Samples without a system_id label, or whose
// value is NaN/non-finite, are dropped — an alert can only be about a
// known system with a real number. The interface lets the evaluator be
// tested with a fake instead of a live Prometheus.
type PromQuerier interface {
	InstantBySystem(ctx context.Context, expr string) (map[string]float64, error)
}

// PrometheusQuerier is the production PromQuerier: a thin client over
// the Prometheus HTTP API's instant-query endpoint. BaseURL is the same
// upstream the metrics proxy uses (SW_PROMETHEUS_URL); a trailing slash
// is tolerated.
type PrometheusQuerier struct {
	BaseURL string
	Client  *http.Client
}

func (q *PrometheusQuerier) client() *http.Client {
	if q.Client != nil {
		return q.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// promResponse mirrors the subset of the Prometheus instant-query JSON
// the evaluator needs: a vector result, each entry a metric label set
// plus a [timestamp, "value"] pair.
type promResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string  `json:"metric"`
			Value  [2]json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
}

// InstantBySystem issues GET /api/v1/query and folds the vector result
// into system_id -> value. When several samples share a system_id (e.g.
// a PromQL expr that didn't aggregate cleanly), the last one wins; the
// curated catalog expressions are one-per-system by construction.
func (q *PrometheusQuerier) InstantBySystem(ctx context.Context, expr string) (map[string]float64, error) {
	if q.BaseURL == "" {
		return nil, fmt.Errorf("alerts: querier has no BaseURL")
	}
	base := strings.TrimRight(q.BaseURL, "/")
	u, err := url.Parse(base + "/api/v1/query")
	if err != nil {
		return nil, fmt.Errorf("alerts: parse upstream: %w", err)
	}
	form := url.Values{"query": {expr}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("alerts: build query: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := q.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("alerts: query upstream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var pr promResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("alerts: decode query response: %w", err)
	}
	if pr.Status != "success" {
		return nil, fmt.Errorf("alerts: upstream %s: %s", pr.ErrorType, pr.Error)
	}
	if pr.Data.ResultType != "vector" {
		return nil, fmt.Errorf("alerts: expected vector result, got %q", pr.Data.ResultType)
	}
	out := make(map[string]float64, len(pr.Data.Result))
	for _, r := range pr.Data.Result {
		sysID := r.Metric["system_id"]
		if sysID == "" {
			continue
		}
		// value is [unixTimestamp, "stringifiedFloat"].
		var raw string
		if err := json.Unmarshal(r.Value[1], &raw); err != nil {
			continue
		}
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			continue
		}
		out[sysID] = f
	}
	return out, nil
}
