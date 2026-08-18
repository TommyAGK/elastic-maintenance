package validation

import (
	"context"
	"errors"
	"sort"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

type InputSnapshot struct {
	Config       *config.ServerConfig
	ResourceSets []source.ResourceSet
}

type InputReader interface {
	Read(context.Context) (InputSnapshot, error)
}

type MountedInputReader struct {
	ConfigPath string
	Overrides  config.StartupOptions
	Limits     source.Limits
}

func (reader MountedInputReader) Read(ctx context.Context) (InputSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return InputSnapshot{}, err
	}
	cfg, err := config.LoadServerConfig(reader.ConfigPath)
	if err != nil {
		return InputSnapshot{}, errors.New("load mounted server configuration")
	}
	cfg.ApplyStartupOverrides(reader.Overrides)
	if err := cfg.ValidateStartup(); err != nil {
		return InputSnapshot{}, errors.New("validate mounted server configuration")
	}
	limits := reader.Limits
	if limits == (source.Limits{}) {
		limits = source.DefaultLimits()
	}
	discoverer, err := source.NewDiscoverer(cfg.MountRoots, limits)
	if err != nil {
		return InputSnapshot{}, errors.New("initialize mounted source discovery")
	}
	ids := make([]string, 0, len(cfg.ResourceSets))
	for id := range cfg.ResourceSets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := InputSnapshot{Config: cfg, ResourceSets: make([]source.ResourceSet, 0, len(ids))}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return InputSnapshot{}, err
		}
		setConfig := cfg.ResourceSets[id]
		set, err := discoverer.DiscoverContext(ctx, id, setConfig.Path, setConfig.RevisionFile)
		if err != nil {
			return InputSnapshot{}, err
		}
		result.ResourceSets = append(result.ResourceSets, *set)
	}
	return result, nil
}
