package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// DecodeToolArguments retains integer tokens as int64/uint64 instead of
// rounding them through float64. Fractional/exponent forms retain normal JSON
// floating-point behavior; identifiers should use integer tokens or strings.
func DecodeToolArguments(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected a single JSON argument object")
	}
	for key, value := range values {
		normalized, err := toolArgumentNumbers(value)
		if err != nil {
			return nil, err
		}
		values[key] = normalized
	}
	return values, nil
}

func toolArgumentNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n, nil
		}
		if n, err := strconv.ParseUint(v.String(), 10, 64); err == nil {
			return n, nil
		}
		if !strings.ContainsAny(v.String(), ".eE") {
			// Keep out-of-range integer tokens exact too. Typed integer schemas
			// will reject them; untyped forwarded arguments retain the token.
			return v, nil
		}
		return v.Float64()
	case map[string]any:
		for key, item := range v {
			n, err := toolArgumentNumbers(item)
			if err != nil {
				return nil, err
			}
			v[key] = n
		}
	case []any:
		for i, item := range v {
			n, err := toolArgumentNumbers(item)
			if err != nil {
				return nil, err
			}
			v[i] = n
		}
	}
	return value, nil
}
