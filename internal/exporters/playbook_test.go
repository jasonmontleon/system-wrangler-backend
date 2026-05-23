// SPDX-License-Identifier: Apache-2.0

package exporters

import "testing"

func TestParseMarkersFullSet(t *testing.T) {
	stdout := []byte(
		"TASK [Surface exporter port] *********\n" +
			"ok: [x] => { \"msg\": \"SW_EXPORTER_PORT: 9100\" }\n" +
			"TASK [Surface exporter service name] *****\n" +
			"ok: [x] => { \"msg\": \"SW_EXPORTER_SERVICE: node_exporter.service\" }\n" +
			"TASK [Surface exporter state] *****\n" +
			"ok: [x] => { \"msg\": \"SW_EXPORTER_STATE: running\" }\n",
	)
	m := ParseMarkers(stdout)
	if m.Port != 9100 {
		t.Errorf("port = %d, want 9100", m.Port)
	}
	if m.ServiceName != "node_exporter.service" {
		t.Errorf("service = %q", m.ServiceName)
	}
	if m.State() != StateRunning {
		t.Errorf("state = %q, want running", m.State())
	}
}

func TestParseMarkersDefaults(t *testing.T) {
	m := ParseMarkers([]byte("nothing useful here\n"))
	if m.Port != 0 || m.ServiceName != "" || m.StateRaw != "" {
		t.Errorf("unexpected non-empty markers: %+v", m)
	}
	if m.State() != StateFailed {
		t.Errorf("empty raw state must resolve to failed, got %q", m.State())
	}
}

func TestStateMapping(t *testing.T) {
	cases := map[string]State{
		"running":   StateRunning,
		"RUNNING":   StateRunning,
		"installed": StateInstalled,
		"removed":   StateRemoved,
		"":          StateFailed,
		"weird":     StateFailed,
	}
	for in, want := range cases {
		got := MarkerResult{StateRaw: in}.State()
		if got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestParseMarkersLastWins(t *testing.T) {
	stdout := []byte(
		"\"msg\": \"SW_EXPORTER_STATE: failed\"\n" +
			"\"msg\": \"SW_EXPORTER_STATE: running\"\n",
	)
	m := ParseMarkers(stdout)
	if m.State() != StateRunning {
		t.Errorf("state = %q, want running (last-wins)", m.State())
	}
}

func TestScanInlineCredentialsCatchesPassword(t *testing.T) {
	body := []byte("- hosts: all\n  vars:\n    password: secret\n")
	err := scanInlineCredentials(body)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestScanInlineCredentialsPassesClean(t *testing.T) {
	body := []byte("- hosts: all\n  tasks: []\n")
	if err := scanInlineCredentials(body); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
