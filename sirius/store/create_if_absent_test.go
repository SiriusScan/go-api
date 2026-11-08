package store

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

// This fixture uses net.Pipe, not a listener or a live Valkey. It verifies the
// concrete adapter's wire command and error classification with fake values.
func TestValkeyAtomicCreateAndMissingKeyClassification(t *testing.T) {
	var mu sync.Mutex
	data := map[string]string{}
	var setCommands [][]string
	dial := func(string, *net.Dialer, *tls.Config) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			for {
				command, err := readEnrollmentRESPCommand(reader)
				if err != nil {
					return
				}
				response := "+OK\r\n"
				mu.Lock()
				switch command[0] {
				case "HELLO":
					response = "*0\r\n"
				case "PING":
					response = "+PONG\r\n"
				case "QUIT":
				case "GET":
					if command[1] == "fixture:failure" {
						response = "-ERR synthetic read failure\r\n"
					} else if value, ok := data[command[1]]; ok {
						response = fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)
					} else {
						response = "$-1\r\n"
					}
				case "SET":
					setCommands = append(setCommands, append([]string(nil), command...))
					if command[1] == "fixture:failure" {
						response = "-ERR synthetic write failure\r\n"
					} else if len(command) != 4 || command[3] != "NX" {
						response = "-ERR expected SET NX\r\n"
					} else if _, ok := data[command[1]]; ok {
						response = "$-1\r\n"
					} else {
						data[command[1]] = command[2]
					}
				default:
					response = "-ERR unexpected test command\r\n"
				}
				mu.Unlock()
				if _, err := io.WriteString(server, response); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{"fixture.invalid:6379"}, DialFn: dial,
		ForceSingleClient: true, AlwaysRESP2: true, DisableCache: true,
		ClientSetInfo: valkey.DisableClientSetInfo, DisableRetry: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	kv := &valkeyStore{client: client}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := kv.GetValue(ctx, "fixture:missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing reply lost sentinel: %v", err)
	}
	if _, err := kv.GetValue(ctx, "fixture:failure"); err == nil || errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("read error treated as absence: %v", err)
	}
	if ok, err := kv.SetValueIfAbsent(ctx, "fixture:key", "fake-first"); err != nil || !ok {
		t.Fatalf("create failed: %v", err)
	}
	if ok, err := kv.SetValueIfAbsent(ctx, "fixture:key", "fake-second"); err != nil || ok {
		t.Fatalf("duplicate not rejected: %v", err)
	}
	if resp, err := kv.GetValue(ctx, "fixture:key"); err != nil || resp.Message.Value != "fake-first" {
		t.Fatalf("original value overwritten: %v", err)
	}
	if ok, err := kv.SetValueIfAbsent(ctx, "fixture:failure", "fake-token"); err == nil || ok {
		t.Fatal("write error ignored")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(setCommands) != 3 {
		t.Fatalf("SET count=%d", len(setCommands))
	}
	for _, command := range setCommands {
		if len(command) != 4 || command[3] != "NX" {
			t.Fatalf("non-atomic command: %v", command)
		}
	}
}

func readEnrollmentRESPCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected RESP array")
	}
	count, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	if count < 1 || count > 32 {
		return nil, fmt.Errorf("unexpected command length")
	}
	result := make([]string, count)
	for i := range result {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(line, "$") {
			return nil, fmt.Errorf("expected RESP bulk string")
		}
		size, err := strconv.Atoi(strings.TrimSpace(line[1:]))
		if err != nil || size < 0 || size > 65536 {
			return nil, fmt.Errorf("invalid bulk size")
		}
		raw := make([]byte, size+2)
		if _, err = io.ReadFull(reader, raw); err != nil {
			return nil, err
		}
		result[i] = string(raw[:size])
	}
	return result, nil
}
