package host

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestGenerateHostID(t *testing.T) {
	t.Parallel()
	got, err := generateHostID(bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 255}))
	if err != nil || got != "scan-00010203040506ff" {
		t.Fatalf("generateHostID = %q, %v", got, err)
	}
}

func TestGenerateHostIDRejectsIncompleteRandomness(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 7} {
		got, err := generateHostID(bytes.NewReader(make([]byte, size)))
		expected := io.ErrUnexpectedEOF
		if size == 0 {
			expected = io.EOF
		}
		if got != "" || !errors.Is(err, expected) {
			t.Errorf("%d random bytes: got %q, %v; want empty identity and %v", size, got, err, expected)
		}
	}
}
