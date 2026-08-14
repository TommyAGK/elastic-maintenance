package api

import (
	"encoding/json"
	"net/http"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
)

const Version = "elastic-maintainer/v1alpha1"

type ErrorEnvelope struct {
	APIVersion string   `json:"apiVersion"`
	Error      APIError `json:"error"`
}

type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

type SessionResponse struct {
	APIVersion    string     `json:"apiVersion"`
	Authenticated bool       `json:"authenticated"`
	Actor         auth.Actor `json:"actor"`
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
	WriteJSON(w, request, status, ErrorEnvelope{APIVersion: Version, Error: APIError{
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}})
}
