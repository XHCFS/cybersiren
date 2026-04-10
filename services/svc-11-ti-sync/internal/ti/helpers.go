package ti

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func ParseJSONBool(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return false
	}

	var boolean bool
	if err := json.Unmarshal(raw, &boolean); err == nil {
		return boolean
	}

	var num json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&num); err == nil {
		return num.String() == "1"
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "1", "true", "yes", "y":
			return true
		}
	}

	return false
}

func RawJSONToString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}

	var num json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&num); err == nil {
		return num.String()
	}

	return strings.Trim(strings.TrimSpace(string(raw)), "\"")
}

func ParseJSONInt(raw json.RawMessage) int {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0
	}

	var num int
	if err := json.Unmarshal(raw, &num); err == nil {
		return num
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, parseErr := strconv.Atoi(strings.TrimSpace(text))
		if parseErr == nil {
			return parsed
		}
	}

	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		parsed, parseErr := strconv.Atoi(number.String())
		if parseErr == nil {
			return parsed
		}
	}

	return 0
}

func ParseJSONTags(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}

	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		cleaned := make([]string, 0, len(list))
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item != "" {
				cleaned = append(cleaned, item)
			}
		}
		return cleaned
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return SplitCommaTags(text)
	}

	return nil
}

func SplitCommaTags(raw string) []string {
	parts := strings.Split(raw, ",")
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			tags = append(tags, trimmed)
		}
	}
	return tags
}

func StripCSVComments(payload []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	var builder strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		builder.WriteString(scanner.Text())
		builder.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return builder.String(), nil
}

func CSVHeaderIndex(header []string, names ...string) (map[string]int, error) {
	index := make(map[string]int, len(header))
	for i, column := range header {
		index[strings.ToLower(strings.TrimSpace(column))] = i
	}

	for _, name := range names {
		if _, ok := index[name]; !ok {
			return nil, fmt.Errorf("missing required CSV column %q", name)
		}
	}

	return index, nil
}

func CSVColumnValue(row []string, columns map[string]int, name string) string {
	idx, ok := columns[name]
	if !ok || idx < 0 || idx >= len(row) {
		return ""
	}
	return row[idx]
}

func ClampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

// IsValidSHA256 reports whether s is a valid lowercase hex-encoded SHA-256 hash.
func IsValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
