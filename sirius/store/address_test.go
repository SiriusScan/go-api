package store

import "testing"

func TestValkeyAddress(t *testing.T) {
	for _, tc := range []struct{ name, address, host, port, want string }{
		{"default", "", "", "", SIRIUS_VALKEY},
		{"native", "", "127.0.0.1", "16379", "127.0.0.1:16379"},
		{"IPv6", "", "::1", "16379", "[::1]:16379"},
		{"explicit", " localhost:16380 ", "other", "1", "localhost:16380"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VALKEY_ADDR", tc.address)
			t.Setenv("VALKEY_HOST", tc.host)
			t.Setenv("VALKEY_PORT", tc.port)
			if got := valkeyAddress(); got != tc.want {
				t.Fatalf("address = %q; want %q", got, tc.want)
			}
		})
	}
}
