package kibana

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

func marshalLiveCanonicalJSON(value any) ([]byte, error) {
	if !validCanonicalUTF8(reflect.ValueOf(value)) {
		return nil, errors.New("canonical live projection is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if decoder.Decode(&generic) != nil {
		return nil, errors.New("canonical live projection is invalid")
	}
	return appendLiveCanonical(nil, generic)
}
func validCanonicalUTF8(value reflect.Value) bool {
	if !value.IsValid() {
		return true
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return true
		}
		return validCanonicalUTF8(value.Elem())
	case reflect.String:
		return utf8.ValidString(value.String())
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if value.Type().Field(index).PkgPath == "" && !validCanonicalUTF8(value.Field(index)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if !validCanonicalUTF8(value.Index(index)) {
				return false
			}
		}
	}
	return true
}
func appendLiveCanonical(destination []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return append(destination, "null"...), nil
	case bool:
		if typed {
			return append(destination, "true"...), nil
		}
		return append(destination, "false"...), nil
	case string:
		return appendLiveCanonicalString(destination, typed), nil
	case json.Number:
		number, err := strconv.ParseInt(string(typed), 10, 64)
		if err != nil || strconv.FormatInt(number, 10) != string(typed) {
			return nil, errors.New("canonical live number is invalid")
		}
		return strconv.AppendInt(destination, number, 10), nil
	case []any:
		destination = append(destination, '[')
		for index, item := range typed {
			if index > 0 {
				destination = append(destination, ',')
			}
			var err error
			destination, err = appendLiveCanonical(destination, item)
			if err != nil {
				return nil, err
			}
		}
		return append(destination, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return lessLiveUTF16(keys[i], keys[j]) })
		destination = append(destination, '{')
		for index, key := range keys {
			if index > 0 {
				destination = append(destination, ',')
			}
			destination = appendLiveCanonicalString(destination, key)
			destination = append(destination, ':')
			var err error
			destination, err = appendLiveCanonical(destination, typed[key])
			if err != nil {
				return nil, err
			}
		}
		return append(destination, '}'), nil
	default:
		return nil, errors.New("canonical live projection type is invalid")
	}
}
func appendLiveCanonicalString(destination []byte, value string) []byte {
	destination = append(destination, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			destination = append(destination, '\\', byte(character))
		case '\b':
			destination = append(destination, `\b`...)
		case '\t':
			destination = append(destination, `\t`...)
		case '\n':
			destination = append(destination, `\n`...)
		case '\f':
			destination = append(destination, `\f`...)
		case '\r':
			destination = append(destination, `\r`...)
		default:
			if character < 0x20 {
				const hex = "0123456789abcdef"
				destination = append(destination, '\\', 'u', '0', '0', hex[character>>4], hex[character&15])
			} else {
				destination = utf8.AppendRune(destination, character)
			}
		}
	}
	return append(destination, '"')
}
func lessLiveUTF16(left, right string) bool {
	leftUnits, rightUnits := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}
