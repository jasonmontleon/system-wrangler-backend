// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

func TestLabelFromUserAgent(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"empty", "", "Unknown browser"},
		{"whitespace", "   ", "Unknown browser"},
		{
			name: "firefox on linux",
			ua:   "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			want: "Firefox on Linux",
		},
		{
			name: "chrome on macos",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
			want: "Chrome on macOS",
		},
		{
			name: "edge on windows beats chrome token",
			ua:   "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0",
			want: "Edge on Windows",
		},
		{
			name: "opera on linux beats chrome token",
			ua:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 OPR/108.0",
			want: "Opera on Linux",
		},
		{
			name: "safari on ios",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			want: "Safari on iOS",
		},
		{
			name: "chrome on android",
			ua:   "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
			want: "Chrome on Android",
		},
		{
			name: "browser without recognisable os",
			ua:   "Firefox/128.0",
			want: "Firefox",
		},
		{
			name: "garbage falls back to unknown",
			ua:   "curl/8.5.0",
			want: "Unknown browser",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LabelFromUserAgent(tt.ua); got != tt.want {
				t.Errorf("LabelFromUserAgent(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}
