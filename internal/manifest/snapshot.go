package manifest

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

const SourceSnapshotAPIVersion = "elastic-maintainer/source-snapshot/v1"

type RevisionProvenance struct {
	RelativePath string `json:"relativePath"`
	Value        string `json:"value"`
}

type ResourceSnapshot struct {
	Resource      ResourceIdentity `json:"resource"`
	Source        source.Location  `json:"source"`
	DesiredDigest DesiredDigest    `json:"desiredDigest"`
}

type ResourceSetSnapshot struct {
	ID            string                 `json:"id"`
	Revision      *RevisionProvenance    `json:"revision,omitempty"`
	DesiredDigest DesiredDigest          `json:"desiredDigest"`
	Files         []source.RawFileDigest `json:"files"`
	Resources     []ResourceSnapshot     `json:"resources"`
}

type TargetSnapshot struct {
	Identity      InventoryTargetIdentity `json:"identity"`
	Labels        []Label                 `json:"labels"`
	ResourceSetID string                  `json:"resourceSetID"`
	Revision      string                  `json:"revision,omitempty"`
	DesiredDigest DesiredDigest           `json:"desiredDigest"`
	Resources     []ResourceSnapshot      `json:"resources"`
}

type SourceSnapshot struct {
	APIVersion    string                `json:"apiVersion"`
	DigestDomain  string                `json:"digestDomain"`
	DigestVersion string                `json:"digestVersion"`
	ResourceSets  []ResourceSetSnapshot `json:"resourceSets"`
	Targets       []TargetSnapshot      `json:"targets"`
}

// BuildSourceSnapshot validates, decodes, assigns, and hashes discovered
// mounted resources. The returned snapshot contains metadata and digests only;
// it never retains source bodies or credential Secret references.
func BuildSourceSnapshot(cfg *config.ServerConfig, discovered []source.ResourceSet) (*SourceSnapshot, error) {
	if cfg == nil {
		return nil, errors.New("build source snapshot: server config is nil")
	}
	if len(discovered) > maxInventoryResourceSets {
		return nil, errors.New("build source snapshot: too many resource sets")
	}
	discoveredByID := make(map[string]source.ResourceSet, len(discovered))
	for _, set := range discovered {
		if set.ID == "" {
			return nil, errors.New("build source snapshot: discovered resource set id is empty")
		}
		if _, duplicate := discoveredByID[set.ID]; duplicate {
			return nil, errors.New("build source snapshot: duplicate discovered resource set")
		}
		if _, configured := cfg.ResourceSets[set.ID]; !configured {
			return nil, errors.New("build source snapshot: discovered resource set is not configured")
		}
		if set.Revision != "" {
			if len(set.Revision) > source.DefaultMaxRevisionBytes || source.ValidateRevisionMetadata(set.Revision) != nil {
				return nil, errors.New("build source snapshot: revision metadata is invalid")
			}
		}
		revisionFile := cfg.ResourceSets[set.ID].RevisionFile
		if revisionFile != "" && !safeSnapshotPath(revisionFile) {
			return nil, errors.New("build source snapshot: revision provenance path is invalid")
		}
		if (revisionFile == "") != (set.Revision == "") {
			return nil, errors.New("build source snapshot: revision provenance is inconsistent")
		}
		if len(set.Files) > source.DefaultMaxFiles {
			return nil, errors.New("build source snapshot: resource set contains too many files")
		}
		seenFiles := make(map[string]struct{}, len(set.Files))
		var totalBytes int64
		for _, file := range set.Files {
			if file.Location.ResourceSetID != set.ID || !safeSnapshotPath(file.Location.RelativePath) {
				return nil, errors.New("build source snapshot: source file provenance is invalid")
			}
			if file.Location.RelativePath == revisionFile {
				return nil, errors.New("build source snapshot: revision file must not also be a resource file")
			}
			if _, duplicate := seenFiles[file.Location.RelativePath]; duplicate {
				return nil, errors.New("build source snapshot: duplicate source file")
			}
			fileBytes := int64(len(file.Contents))
			if fileBytes > source.DefaultMaxFileBytes {
				return nil, errors.New("build source snapshot: source file is too large")
			}
			if fileBytes > source.DefaultMaxTotalBytes-totalBytes {
				return nil, errors.New("build source snapshot: resource set source bytes exceed the limit")
			}
			totalBytes += fileBytes
			seenFiles[file.Location.RelativePath] = struct{}{}
		}
		discoveredByID[set.ID] = set
	}
	for setID := range cfg.ResourceSets {
		if _, exists := discoveredByID[setID]; !exists {
			return nil, errors.New("build source snapshot: configured resource set was not discovered")
		}
	}

	setIDs := sortedResourceSetConfigIDs(cfg.ResourceSets)
	decoded := make([]*ResourceSet, 0, len(setIDs))
	for _, setID := range setIDs {
		set := discoveredByID[setID]
		resources, err := DecodeResourceSet(set)
		if err != nil {
			return nil, err
		}
		filePaths := make(map[string]struct{}, len(set.Files))
		for _, file := range set.Files {
			filePaths[file.Location.RelativePath] = struct{}{}
		}
		for _, resource := range resources.Resources {
			if resource.Source.ResourceSetID != setID {
				return nil, errors.New("build source snapshot: decoded resource provenance is invalid")
			}
			if _, exists := filePaths[resource.Source.RelativePath]; !exists {
				return nil, errors.New("build source snapshot: decoded resource source file is missing")
			}
		}
		decoded = append(decoded, resources)
	}
	inventory, err := BuildInventory(cfg, decoded)
	if err != nil {
		return nil, err
	}
	if _, err := ResolveTargetDAGs(decoded, inventory); err != nil {
		return nil, err
	}

	decodedByID := make(map[string]*ResourceSet, len(decoded))
	for _, set := range decoded {
		decodedByID[set.ID] = set
	}
	result := &SourceSnapshot{
		APIVersion: SourceSnapshotAPIVersion, DigestDomain: DesiredDigestDomain, DigestVersion: DesiredDigestVersion,
		ResourceSets: make([]ResourceSetSnapshot, 0, len(decoded)), Targets: make([]TargetSnapshot, 0, len(inventory.Targets)),
	}
	for _, setID := range setIDs {
		set := decodedByID[setID]
		canonical, err := canonicalizeResourceSet(set)
		if err != nil {
			return nil, err
		}
		setDigest, err := desiredDigest("resource-set", canonical)
		if err != nil {
			return nil, err
		}
		snapshot := ResourceSetSnapshot{
			ID: setID, DesiredDigest: setDigest, Files: discoveredByID[setID].RawFileDigests(),
			Resources: make([]ResourceSnapshot, 0, len(set.Resources)),
		}
		revisionFile := cfg.ResourceSets[setID].RevisionFile
		if set.Revision != "" {
			snapshot.Revision = &RevisionProvenance{RelativePath: revisionFile, Value: set.Revision}
		}
		resources := append([]Resource(nil), set.Resources...)
		sort.SliceStable(resources, func(i, j int) bool {
			return lessIdentity(resourceIdentity(resources[i]), resourceIdentity(resources[j]))
		})
		for _, resource := range resources {
			canonicalResource, err := canonicalizeResource(resource)
			if err != nil {
				return nil, err
			}
			digest, err := desiredDigest("resource", canonicalResource)
			if err != nil {
				return nil, err
			}
			snapshot.Resources = append(snapshot.Resources, ResourceSnapshot{Resource: resourceIdentity(resource), Source: resource.Source, DesiredDigest: digest})
		}
		result.ResourceSets = append(result.ResourceSets, snapshot)
	}
	for _, target := range inventory.Targets {
		set := decodedByID[target.ResourceSetID]
		canonical, err := canonicalizeTarget(cfg, target, set)
		if err != nil {
			return nil, err
		}
		digest, err := desiredDigest("target", canonical)
		if err != nil {
			return nil, err
		}
		resourcesByKey := make(map[string]ResourceSnapshot, len(set.Resources))
		setSnapshot := result.ResourceSets[sort.Search(len(result.ResourceSets), func(index int) bool { return result.ResourceSets[index].ID >= target.ResourceSetID })]
		for _, resource := range setSnapshot.Resources {
			resourcesByKey[identityKey(resource.Resource)] = resource
		}
		targetResources := make([]ResourceSnapshot, 0, len(target.Resources))
		for _, identity := range target.Resources {
			targetResources = append(targetResources, resourcesByKey[identityKey(identity)])
		}
		sort.SliceStable(targetResources, func(i, j int) bool { return lessIdentity(targetResources[i].Resource, targetResources[j].Resource) })
		result.Targets = append(result.Targets, TargetSnapshot{
			Identity: target.Identity, Labels: append([]Label{}, target.Labels...), ResourceSetID: target.ResourceSetID,
			Revision: target.Revision, DesiredDigest: digest, Resources: targetResources,
		})
	}
	return result, nil
}

func safeSnapshotPath(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != ".." && !strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func (digest DesiredDigest) String() string {
	return fmt.Sprintf("%s:%s", digest.Algorithm, digest.Value)
}
