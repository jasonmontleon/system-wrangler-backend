// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"errors"
	"strconv"
	"testing"
)

type fakeStore struct {
	values  map[string]string
	getErr  error
	setErr  error
	allErr  error
	lastKey string
	lastVal string
}

func newFakeStore() *fakeStore { return &fakeStore{values: map[string]string{}} }

func (f *fakeStore) Get(key string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.values[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *fakeStore) Set(key, value string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.lastKey = key
	f.lastVal = value
	f.values[key] = value
	return nil
}

func (f *fakeStore) All() (map[string]string, error) {
	if f.allErr != nil {
		return nil, f.allErr
	}
	out := make(map[string]string, len(f.values))
	for k, v := range f.values {
		out[k] = v
	}
	return out, nil
}

func TestProbeIntervalSeconds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store Store
		setup func(*fakeStore)
		want  int
	}{
		{name: "nil store falls back to default", store: nil, want: DefaultProbeIntervalSeconds},
		{name: "unset returns default", store: newFakeStore(), want: DefaultProbeIntervalSeconds},
		{
			name:  "below min returns default",
			store: newFakeStore(),
			setup: func(f *fakeStore) {
				f.values[KeyProbeIntervalSeconds] = strconv.Itoa(MinProbeIntervalSeconds - 1)
			},
			want: DefaultProbeIntervalSeconds,
		},
		{
			name:  "above max clamps to max",
			store: newFakeStore(),
			setup: func(f *fakeStore) {
				f.values[KeyProbeIntervalSeconds] = strconv.Itoa(MaxProbeIntervalSeconds + 100)
			},
			want: MaxProbeIntervalSeconds,
		},
		{
			name:  "valid pass-through",
			store: newFakeStore(),
			setup: func(f *fakeStore) {
				f.values[KeyProbeIntervalSeconds] = "60"
			},
			want: 60,
		},
		{
			name:  "unparseable returns default",
			store: newFakeStore(),
			setup: func(f *fakeStore) {
				f.values[KeyProbeIntervalSeconds] = "not-a-number"
			},
			want: DefaultProbeIntervalSeconds,
		},
		{
			name: "store error returns default",
			store: func() Store {
				f := newFakeStore()
				f.getErr = errors.New("backend down")
				return f
			}(),
			want: DefaultProbeIntervalSeconds,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup(tc.store.(*fakeStore))
			}
			if got := ProbeIntervalSeconds(tc.store); got != tc.want {
				t.Fatalf("ProbeIntervalSeconds = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSetProbeIntervalSeconds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		store     Store
		value     int
		wantErr   error
		wantStore string
	}{
		{name: "nil store errors", store: nil, value: 30, wantErr: errors.New("settings: store is nil")},
		{name: "below min", store: newFakeStore(), value: MinProbeIntervalSeconds - 1, wantErr: ErrInvalid},
		{name: "above max", store: newFakeStore(), value: MaxProbeIntervalSeconds + 1, wantErr: ErrInvalid},
		{name: "valid stores stringified", store: newFakeStore(), value: 45, wantStore: "45"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := SetProbeIntervalSeconds(tc.store, tc.value)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("err = nil, want %v", tc.wantErr)
				}
				if errors.Is(tc.wantErr, ErrInvalid) && !errors.Is(err, ErrInvalid) {
					t.Fatalf("err = %v, want wrapping ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			f := tc.store.(*fakeStore)
			if f.lastKey != KeyProbeIntervalSeconds || f.lastVal != tc.wantStore {
				t.Fatalf("stored (%q, %q), want (%q, %q)", f.lastKey, f.lastVal, KeyProbeIntervalSeconds, tc.wantStore)
			}
		})
	}
}

func TestProbeFailureThresholdRoundTrip(t *testing.T) {
	f := newFakeStore()
	if err := SetProbeFailureThreshold(f, 3); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := ProbeFailureThreshold(f); got != 3 {
		t.Fatalf("Get = %d, want 3", got)
	}
	if err := SetProbeFailureThreshold(f, MinProbeFailureThreshold-1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("below-min err = %v, want ErrInvalid", err)
	}
	if err := SetProbeFailureThreshold(f, MaxProbeFailureThreshold+1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("above-max err = %v, want ErrInvalid", err)
	}
	if err := SetProbeFailureThreshold(nil, 1); err == nil {
		t.Errorf("nil store err = nil, want error")
	}
}

func TestProbeSuccessThresholdRoundTrip(t *testing.T) {
	f := newFakeStore()
	if err := SetProbeSuccessThreshold(f, 5); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := ProbeSuccessThreshold(f); got != 5 {
		t.Fatalf("Get = %d, want 5", got)
	}
	if err := SetProbeSuccessThreshold(f, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if err := SetProbeSuccessThreshold(nil, 1); err == nil {
		t.Errorf("nil store err = nil, want error")
	}
}

// TestProbeFailureThresholdNilStore covers the nil-store fast-path
// on the getter — symmetric to the test in TestProbeIntervalSeconds
// but for the failure/success accessors so the clampedSetting
// branch coverage doesn't depend on the interval test running.
func TestProbeFailureThresholdNilStore(t *testing.T) {
	if got := ProbeFailureThreshold(nil); got != DefaultProbeFailureThreshold {
		t.Fatalf("got %d, want %d", got, DefaultProbeFailureThreshold)
	}
	if got := ProbeSuccessThreshold(nil); got != DefaultProbeSuccessThreshold {
		t.Fatalf("got %d, want %d", got, DefaultProbeSuccessThreshold)
	}
}
