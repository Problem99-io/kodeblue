package openai

import (
	"net/http"
	"testing"
	"time"
)

func TestResponseHeaderTimeoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", 120 * time.Second}, {"invalid", 120 * time.Second}, {"0", 120 * time.Second},
		{"-1s", 120 * time.Second}, {"500ms", 120 * time.Second}, {"121m", 120 * time.Second},
		{"10m", 10 * time.Minute}, {"2h", 2 * time.Hour},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("KODEBLUE_PROVIDER_RESPONSE_HEADER_TIMEOUT", tc.value)
			c := NewClient("test", "test")
			if got := c.httpClient.Transport.(*http.Transport).ResponseHeaderTimeout; got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
