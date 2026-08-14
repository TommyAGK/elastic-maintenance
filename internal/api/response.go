package api

import (
	"encoding/json"
	"net/http"
)

type ErrorEnvelope struct {
	Error APIError `json:"error"`
}

type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

func WriteJSON(w http.ResponseWriter, request *http.Request, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if request != nil && request.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

func WriteError(w http.ResponseWriter, request *http.Request, status int, code, message, requestID string) {
	WriteJSON(w, request, status, ErrorEnvelope{Error: APIError{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}})
}
