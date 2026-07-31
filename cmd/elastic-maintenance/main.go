package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"elastic-maintenance/internal/config"
	"elastic-maintenance/internal/kibana"
	"elastic-maintenance/internal/reconcile"
)

func main() {
	var (
		configPath = flag.String("config", "config/desired-state.json", "Path to desired-state JSON")
		mode       = flag.String("mode", "review", "review or apply")
		kibanaURL  = flag.String("kibana-url", getenv("KIBANA_URL", ""), "Kibana base URL")
		apiKey     = flag.String("api-key", getenv("KIBANA_API_KEY", ""), "Kibana API key")
		namespace  = flag.String("namespace", "default", "Default Fleet namespace")
	)
	flag.Parse()

	if err := validateFlags(*mode, *kibanaURL, *apiKey, *configPath, *namespace); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(64)
	}

	desired, err := config.Load(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}

	_ = namespace
	client := kibana.NewClient(*kibanaURL, *apiKey)
	report, err := reconcile.Run(client, desired, reconcile.Mode(*mode))
	if err != nil {
		fatalf("reconcile: %v", err)
	}

	fmt.Fprintln(os.Stdout, report.String())
	if strings.EqualFold(*mode, string(reconcile.ModeReview)) && report.ChangesPlanned > 0 {
		os.Exit(2)
	}
}

func validateFlags(mode, kibanaURL, apiKey, configPath, namespace string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != string(reconcile.ModeReview) && mode != string(reconcile.ModeApply) {
		return errors.New("invalid --mode: must be review or apply")
	}
	if strings.TrimSpace(kibanaURL) == "" {
		return errors.New("--kibana-url or KIBANA_URL is required")
	}
	if strings.TrimSpace(apiKey) == "" {
		return errors.New("--api-key or KIBANA_API_KEY is required")
	}
	if strings.TrimSpace(configPath) == "" {
		return errors.New("--config is required")
	}
	if strings.TrimSpace(namespace) == "" {
		return errors.New("--namespace is required")
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
