package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

// marshalCanonicalJSON implements the RFC 8785 rules needed by the v1 desired
// projections. V1 projections intentionally contain only objects, arrays,
// strings, booleans, and null; numbers are rejected so adding one requires an
// explicit canonical-format review and digest-version change.
func marshalCanonicalJSON(value any) ([]byte, error) {
	if err := validateCanonicalUTF8(reflect.ValueOf(value)); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(encoded))
	result, err = appendCanonicalJSON(result, generic)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func validateCanonicalUTF8(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		return validateCanonicalUTF8(value.Elem())
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return errors.New("canonical JSON string is not valid UTF-8")
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if value.Type().Field(index).PkgPath == "" {
				if err := validateCanonicalUTF8(value.Field(index)); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if err := validateCanonicalUTF8(iterator.Key()); err != nil {
				return err
			}
			if err := validateCanonicalUTF8(iterator.Value()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalUTF8(value.Index(index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendCanonicalJSON(destination []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return append(destination, "null"...), nil
	case bool:
		if typed {
			return append(destination, "true"...), nil
		}
		return append(destination, "false"...), nil
	case string:
		return appendCanonicalString(destination, typed)
	case []any:
		destination = append(destination, '[')
		for index, item := range typed {
			if index != 0 {
				destination = append(destination, ',')
			}
			var err error
			destination, err = appendCanonicalJSON(destination, item)
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
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		destination = append(destination, '{')
		for index, key := range keys {
			if index != 0 {
				destination = append(destination, ',')
			}
			var err error
			destination, err = appendCanonicalString(destination, key)
			if err != nil {
				return nil, err
			}
			destination = append(destination, ':')
			destination, err = appendCanonicalJSON(destination, typed[key])
			if err != nil {
				return nil, err
			}
		}
		return append(destination, '}'), nil
	case json.Number:
		return nil, errors.New("canonical desired v1 does not support numeric values")
	default:
		return nil, fmt.Errorf("canonical desired v1 contains unsupported JSON type %T", value)
	}
}

func appendCanonicalString(destination []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, errors.New("canonical JSON string is not valid UTF-8")
	}
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
				const hexadecimal = "0123456789abcdef"
				destination = append(destination, '\\', 'u', '0', '0', hexadecimal[character>>4], hexadecimal[character&0x0f])
			} else {
				destination = utf8.AppendRune(destination, character)
			}
		}
	}
	return append(destination, '"'), nil
}

func lessUTF16(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
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
