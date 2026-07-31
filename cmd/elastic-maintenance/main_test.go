package main

import "testing"

func TestValidateFlags(t *testing.T) {
	if err := validateFlags("review", "http://kibana", "key", "config/desired-state.json", "default"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateFlags("bad", "http://kibana", "key", "config/desired-state.json", "default"); err == nil {
		t.Fatal("expected invalid mode error")
	}
}
