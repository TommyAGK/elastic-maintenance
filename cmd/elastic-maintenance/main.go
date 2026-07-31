package main

import (
	"flag"
	"fmt"
	"os"

	"elastic-maintenance/internal/config"
	"elastic-maintenance/internal/kibana"
	"elastic-maintenance/internal/reconcile"
)

func main() {
	var (
		configPath = flag.String("config", "config/desired-state.json", "Path to desired-state JSON")
		mode       = flag.String("mode", "review", "review or apply")
		kibanaURL   = flag.String("kibana-url", "", "Kibana base URL")
		apiKey     = flag.String("api-key", "", "Kibana API key")
	)
	flag.Parse()

	if *kibanaURL == "" {
		fatalf("--kibana-url is required")
	}
	if *apiKey == "" {
		fatalf("--api-key is required")
	}

	desired, err := config.Load(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}

	client := kibana.NewClient(*kibanaURL, *apiKey)
	report, err := reconcile.Run(client, desired, reconcile.Mode(*mode))
	if err != nil {
		fatalf("reconcile: %v", err)
	}

	fmt.Fprintln(os.Stdout, report.String())
	if report.ChangesApplied > 0 {
		os.Exit(2)
	}
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

