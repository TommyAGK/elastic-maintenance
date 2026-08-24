package api

import "time"

const CSRFTokenHeader = "X-CSRF-Token"

type CredentialPutRequest struct {
	APIKey           string `json:"apiKey"`
	CACertificatePEM string `json:"caCertificatePem,omitempty"`
}
type ConfirmedMutationRequest struct {
	Confirm bool `json:"confirm"`
}
type CredentialStatus struct {
	Configured            bool       `json:"configured"`
	SecretResourceVersion string     `json:"secretResourceVersion,omitempty"`
	RotatedAt             *time.Time `json:"rotatedAt,omitempty"`
	RotatedBy             string     `json:"rotatedBy,omitempty"`
	CertificateSHA256     string     `json:"certificateSHA256,omitempty"`
	CertificateNotAfter   *time.Time `json:"certificateNotAfter,omitempty"`
}
type CredentialStatusResponse struct {
	APIVersion       string           `json:"apiVersion"`
	TargetID         string           `json:"targetId"`
	CredentialStatus CredentialStatus `json:"credentialStatus"`
}
