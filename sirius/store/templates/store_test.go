package templates

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

// fakeKV is an in-memory KV that implements just enough of the
// kvReader / kvWriter contracts for the helpers under test.
type fakeKV struct {
	mu       sync.Mutex
	data     map[string]string
	failSet  map[string]error // key -> error to return on SetValue
}

func newFakeKV() *fakeKV {
	return &fakeKV{
		data:    map[string]string{},
		failSet: map[string]error{},
	}
}

func (f *fakeKV) GetValue(_ context.Context, key string) (store.ValkeyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return store.ValkeyResponse{}, errors.New("not found")
	}
	return store.ValkeyResponse{Message: store.ValkeyValue{Value: v}}, nil
}

func (f *fakeKV) SetValue(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failSet[key]; ok {
		return err
	}
	f.data[key] = value
	return nil
}

func (f *fakeKV) DeleteValue(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}

func sampleRecord() *TemplateRecord {
	body := []byte("id: foo\ninfo:\n  name: foo\n")
	return &TemplateRecord{
		ID:            "foo",
		Version:       "1.0.0",
		Checksum:      SHA256Hex(body),
		Size:          int64(len(body)),
		Severity:      "high",
		Platforms:     []string{"linux"},
		DetectionType: "command",
		Author:        "test",
		Created:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Updated:       time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
		IsCustom:      true,
		Content:       body,
	}
}

func TestWriteRead_TemplateRoundTrip(t *testing.T) {
	kv := newFakeKV()
	rec := sampleRecord()

	if err := WriteTemplate(context.Background(), kv, rec); err != nil {
		t.Fatalf("WriteTemplate: %v", err)
	}

	got, err := ReadTemplate(context.Background(), kv, rec.ID)
	if err != nil {
		t.Fatalf("ReadTemplate: %v", err)
	}
	if got == nil {
		t.Fatal("ReadTemplate returned nil")
	}
	if got.ID != rec.ID || got.Checksum != rec.Checksum || string(got.Content) != string(rec.Content) {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	meta, err := ReadTemplateMeta(context.Background(), kv, rec.ID)
	if err != nil {
		t.Fatalf("ReadTemplateMeta: %v", err)
	}
	if meta == nil || len(meta.Content) != 0 {
		t.Errorf("meta should exist with empty content; got %+v", meta)
	}
}

func TestWriteTemplate_RollsBackOnMetaFailure(t *testing.T) {
	kv := newFakeKV()
	rec := sampleRecord()
	kv.failSet[AgentTemplateMetaKey(rec.ID)] = errors.New("boom")

	err := WriteTemplate(context.Background(), kv, rec)
	if err == nil {
		t.Fatal("expected error from meta failure")
	}
	if _, ok := kv.data[AgentTemplateKey(rec.ID, true)]; ok {
		t.Error("envelope should have been rolled back when meta write failed")
	}
}

func TestEncodeTemplate_WireShape(t *testing.T) {
	rec := sampleRecord()
	envBytes, err := EncodeTemplate(rec)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(envBytes, &raw); err != nil {
		t.Fatal(err)
	}
	contentStr, ok := raw["content"].(string)
	if !ok {
		t.Fatalf("content must serialize as base64 string; got %T", raw["content"])
	}
	decoded, err := base64.StdEncoding.DecodeString(contentStr)
	if err != nil {
		t.Fatalf("content not valid base64: %v", err)
	}
	if string(decoded) != string(rec.Content) {
		t.Error("base64 content does not round-trip to original bytes")
	}
}

func TestNseScript_RoundTrip(t *testing.T) {
	kv := newFakeKV()
	rec := &NseScriptRecord{
		Content:   "-- lua",
		Metadata:  NseScriptMeta{Author: "n", Tags: []string{"safe"}, Description: "d"},
		UpdatedAt: 42,
	}
	if err := WriteNseScript(context.Background(), kv, "scripts/foo/bar.nse", rec); err != nil {
		t.Fatal(err)
	}
	if _, ok := kv.data["nse:script:bar"]; !ok {
		t.Fatal("WriteNseScript did not canonicalize key")
	}
	got, err := ReadNseScript(context.Background(), kv, "bar.nse")
	if err != nil || got == nil {
		t.Fatalf("ReadNseScript: rec=%v err=%v", got, err)
	}
	if got.Content != rec.Content || got.UpdatedAt != rec.UpdatedAt {
		t.Errorf("nse round-trip mismatch: %+v", got)
	}
}

func TestNseManifest_CanonicalizesKeys(t *testing.T) {
	kv := newFakeKV()
	m := &NseManifest{
		Name:    "x",
		Version: "1",
		Scripts: map[string]NseManifestEntry{
			"scripts/foo/bar.nse": {Name: "bar", Path: "scripts/foo/bar.nse", Protocol: "tcp"},
			"baz":                 {Name: "baz", Path: "baz.nse", Protocol: "udp"},
		},
	}
	if err := WriteNseManifest(context.Background(), kv, m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadNseManifest(context.Background(), kv)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if _, ok := got.Scripts["bar"]; !ok {
		t.Errorf("expected canonical key 'bar' in manifest; got %v", got.Scripts)
	}
	if _, ok := got.Scripts["scripts/foo/bar.nse"]; ok {
		t.Error("manifest still contains non-canonical key")
	}
	// Path must be preserved verbatim.
	if got.Scripts["bar"].Path != "scripts/foo/bar.nse" {
		t.Errorf("Path lost: %q", got.Scripts["bar"].Path)
	}
}
