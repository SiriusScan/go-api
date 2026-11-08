package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// FindingJSON retains the full JSON evidence without passing numbers through
// float64. It is deliberately separate from the existing host JSONB map type.
type FindingJSON json.RawMessage

func (f FindingJSON) Value() (driver.Value, error) {
	if len(f) == 0 {
		return nil, nil
	}
	if !json.Valid(f) {
		return nil, fmt.Errorf("invalid finding JSON")
	}
	return string(f), nil
}

func (f *FindingJSON) Scan(value interface{}) error {
	switch v := value.(type) {
	case nil:
		*f = nil
	case []byte:
		*f = append((*f)[:0], v...)
	case string:
		*f = append((*f)[:0], v...)
	default:
		return fmt.Errorf("cannot scan %T into FindingJSON", value)
	}
	return nil
}

func (f FindingJSON) MarshalJSON() ([]byte, error) {
	if len(f) == 0 {
		return []byte("null"), nil
	}
	return json.RawMessage(f).MarshalJSON()
}

func (f *FindingJSON) UnmarshalJSON(data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid finding JSON")
	}
	*f = append((*f)[:0], data...)
	return nil
}
