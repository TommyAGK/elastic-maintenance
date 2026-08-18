package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

func DecodeStrictJSON(body io.Reader, destination any) error {
	contents, err := io.ReadAll(body)
	if err != nil {
		return errors.New("read JSON body")
	}
	if len(bytes.TrimSpace(contents)) == 0 {
		return errors.New("JSON body is required")
	}
	if bytes.Contains(contents, []byte(`\u`)) {
		return errors.New("escaped JSON field aliases are not allowed")
	}
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return err
	}
	var generic any
	if err := json.Unmarshal(contents, &generic); err != nil {
		return errors.New("JSON body is invalid")
	}
	object, ok := generic.(map[string]any)
	if !ok || object == nil {
		return errors.New("JSON body must be an object")
	}
	allowed := jsonFieldNames(reflect.TypeOf(destination))
	for key, value := range object {
		if !allowed[key] {
			return errors.New("JSON object contains an unknown field")
		}
		if containsJSONNull(value) {
			return errors.New("JSON null values are not allowed")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("JSON body is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JSON body must contain one value")
	}
	return nil
}

func containsJSONNull(value any) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if containsJSONNull(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if containsJSONNull(item) {
				return true
			}
		}
	}
	return false
}

func jsonFieldNames(value reflect.Type) map[string]bool {
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	result := make(map[string]bool)
	if value.Kind() != reflect.Struct {
		return result
	}
	for index := 0; index < value.NumField(); index++ {
		name := strings.Split(value.Field(index).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			result[name] = true
		}
	}
	return result
}

func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	var parseValue func() error
	parseValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("JSON body is invalid")
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return errors.New("JSON body is invalid")
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON body is invalid")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("JSON object contains duplicate fields")
				}
				seen[key] = struct{}{}
				if err := parseValue(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("JSON body is invalid")
			}
		case '[':
			for decoder.More() {
				if err := parseValue(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("JSON body is invalid")
			}
		default:
			return errors.New("JSON body is invalid")
		}
		return nil
	}
	if err := parseValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON body must contain one value")
	}
	return nil
}
