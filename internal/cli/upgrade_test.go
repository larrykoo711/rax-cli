package cli

import (
	"path/filepath"
	"testing"
	"time"
)

func TestIsNewerSemver(t *testing.T) {
	cases := []struct {
		cand string
		cur  string
		want bool
	}{
		{"0.4.0", "0.3.0", true},
		{"v0.10.0", "0.4.0", true},
		{"1.0.0", "0.9.9", true},
		{"0.4.0", "0.4.0", false},
		{"0.3.0", "0.4.0", false},
		{"0.4.0", "dev", false},
		{"", "0.4.0", false},
	}
	for _, tc := range cases {
		if got := isNewerSemver(tc.cand, tc.cur); got != tc.want {
			t.Errorf("isNewerSemver(%q, %q) = %v, want %v", tc.cand, tc.cur, got, tc.want)
		}
	}
}

func TestUpdateCacheRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rax", "update-check.json")
	now := time.Date(2026, 11, 26, 6, 30, 0, 0, time.UTC)
	writeUpdateCache(p, "0.4.0", now)
	c := readUpdateCache(p)
	if c == nil || c.LatestVersion != "0.4.0" || !c.CheckedAt.Equal(now) {
		t.Fatalf("unexpected cache content: %+v", c)
	}
}
