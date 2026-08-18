package manifest

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/TommyAGK/elastic-maintenance/internal/source"
	"gopkg.in/yaml.v3"
)

const (
	maxIDLength          = 128
	maxNameLength        = 256
	maxLabelCount        = 64
	maxCollectionEntries = 1024
	maxYAMLDepth         = 100
	maxYAMLNodes         = 100_000
	maxDocumentsPerFile  = 10_000
	maxDocumentsPerSet   = 100_000
	maxResourcesPerSet   = 10_000
	maxDiagnosticsPerSet = 10_000
)

var (
	idPattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$`)
	labelKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`)
	labelValuePattern = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
	semverPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	intervalPattern   = regexp.MustCompile(`^[1-9][0-9]{0,8}[smhd]$`)
	parserLinePattern = regexp.MustCompile(`^yaml: line ([0-9]+):`)
)

type decodeContext struct {
	resourceSetID string
	path          string
	document      int
}

type nodeObject struct {
	values map[string]*yaml.Node
	keys   map[string]*yaml.Node
}

func DecodeResourceSet(input source.ResourceSet) (*ResourceSet, error) {
	result := &ResourceSet{ID: input.ID, Revision: input.Revision, Resources: make([]Resource, 0)}
	var diagnostics []Diagnostic
	identities := make(map[string]source.Location)
	var prebuilt *source.Location
	totalDocuments := 0

	files := append([]source.File(nil), input.Files...)
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].Location.RelativePath < files[j].Location.RelativePath
	})
fileLoop:
	for _, file := range files {
		decoder := yaml.NewDecoder(bytes.NewReader(file.Contents))
		document := 0
		for {
			if len(diagnostics) >= maxDiagnosticsPerSet {
				break fileLoop
			}
			var node yaml.Node
			err := decoder.Decode(&node)
			if errors.Is(err, io.EOF) {
				if document == 0 {
					diagnostics = append(diagnostics, diagnostic(decodeContext{input.ID, file.Location.RelativePath, 1}, nil, "empty_document", "", "document must not be empty"))
				}
				break
			}
			document++
			totalDocuments++
			ctx := decodeContext{input.ID, file.Location.RelativePath, document}
			if totalDocuments > maxDocumentsPerSet {
				diagnostics = append(diagnostics, diagnostic(ctx, nil, "too_many_documents", "", "resource set contains too many YAML documents"))
				break fileLoop
			}
			if document > maxDocumentsPerFile {
				diagnostics = append(diagnostics, diagnostic(ctx, nil, "too_many_documents", "", "file contains too many YAML documents"))
				break
			}
			if err != nil {
				issue := diagnostic(ctx, nil, "invalid_yaml", "", "document is not valid YAML")
				issue.Location = parserErrorLocation(ctx, err)
				diagnostics = append(diagnostics, issue)
				break
			}
			if len(node.Content) != 1 || isEmptyNode(node.Content[0]) {
				diagnostics = append(diagnostics, diagnostic(ctx, firstContent(&node), "empty_document", "", "document must not be empty"))
				continue
			}
			root := node.Content[0]
			if issue := validateYAMLTree(ctx, root, ""); issue != nil {
				diagnostics = append(diagnostics, *issue)
				continue
			}
			resource, issue := decodeResource(ctx, root)
			if issue != nil {
				diagnostics = append(diagnostics, *issue)
				continue
			}
			identity := string(resource.Kind) + "/" + resource.Metadata.ID
			if prior, exists := identities[identity]; exists {
				issue := diagnostic(ctx, root, "duplicate_resource", "metadata.id", "resource identity must be unique within the resource set")
				issue.Related = &prior
				diagnostics = append(diagnostics, issue)
				continue
			}
			if resource.Kind == KindPrebuiltRules {
				if prebuilt != nil {
					issue := diagnostic(ctx, root, "multiple_prebuilt_rules", "kind", "only one PrebuiltRules resource is allowed in a resource set")
					issue.Related = prebuilt
					diagnostics = append(diagnostics, issue)
					continue
				}
				location := resource.Source
				prebuilt = &location
			}
			if len(result.Resources) >= maxResourcesPerSet {
				diagnostics = append(diagnostics, diagnostic(ctx, root, "too_many_resources", "", "resource set contains too many resources"))
				break fileLoop
			}
			identities[identity] = resource.Source
			result.Resources = append(result.Resources, resource)
		}
	}
	if len(diagnostics) != 0 {
		sortDiagnostics(diagnostics)
		return nil, &DiagnosticsError{Diagnostics: diagnostics}
	}
	return result, nil
}

func decodeResource(ctx decodeContext, root *yaml.Node) (Resource, *Diagnostic) {
	envelope, issue := decodeObject(ctx, root, "", []string{"apiVersion", "kind", "metadata", "spec"}, []string{"apiVersion", "kind", "metadata", "spec"})
	if issue != nil {
		return Resource{}, issue
	}
	apiVersion, issue := requiredString(ctx, envelope, "apiVersion", "apiVersion")
	if issue != nil {
		return Resource{}, issue
	}
	if apiVersion != APIVersion {
		return Resource{}, diagnosticPtr(ctx, envelope.values["apiVersion"], "unsupported_api_version", "apiVersion", "apiVersion is not supported")
	}
	kindText, issue := requiredString(ctx, envelope, "kind", "kind")
	if issue != nil {
		return Resource{}, issue
	}
	kind := Kind(kindText)
	if !supportedKind(kind) {
		return Resource{}, diagnosticPtr(ctx, envelope.values["kind"], "unsupported_kind", "kind", "resource kind is not supported")
	}
	metadata, issue := decodeMetadata(ctx, envelope.values["metadata"])
	if issue != nil {
		return Resource{}, issue
	}
	spec, issue := decodeSpec(ctx, kind, envelope.values["spec"])
	if issue != nil {
		return Resource{}, issue
	}
	return Resource{APIVersion: apiVersion, Kind: kind, Metadata: metadata, Spec: spec, Source: location(ctx, root)}, nil
}

func decodeMetadata(ctx decodeContext, node *yaml.Node) (Metadata, *Diagnostic) {
	object, issue := decodeObject(ctx, node, "metadata", []string{"id", "name", "targetSelector", "dependsOn"}, []string{"id", "name"})
	if issue != nil {
		return Metadata{}, issue
	}
	id, issue := requiredString(ctx, object, "id", "metadata.id")
	if issue != nil {
		return Metadata{}, issue
	}
	if len(id) > maxIDLength || !idPattern.MatchString(id) {
		return Metadata{}, diagnosticPtr(ctx, object.values["id"], "invalid_id", "metadata.id", "id must be a bounded lowercase identifier")
	}
	name, issue := requiredString(ctx, object, "name", "metadata.name")
	if issue != nil {
		return Metadata{}, issue
	}
	if !boundedPrintable(name, maxNameLength) {
		return Metadata{}, diagnosticPtr(ctx, object.values["name"], "invalid_name", "metadata.name", "name must be bounded printable text")
	}
	metadata := Metadata{ID: id, Name: name}
	if selectorNode := object.values["targetSelector"]; selectorNode != nil {
		selector, issue := decodeSelector(ctx, selectorNode)
		if issue != nil {
			return Metadata{}, issue
		}
		metadata.TargetSelector = selector
	}
	if dependsNode := object.values["dependsOn"]; dependsNode != nil {
		depends, issue := decodeReferences(ctx, dependsNode, "metadata.dependsOn", "")
		if issue != nil {
			return Metadata{}, issue
		}
		metadata.DependsOn = depends
	}
	return metadata, nil
}

func decodeSelector(ctx decodeContext, node *yaml.Node) (*TargetSelector, *Diagnostic) {
	object, issue := decodeObject(ctx, node, "metadata.targetSelector", []string{"matchLabels"}, []string{"matchLabels"})
	if issue != nil {
		return nil, issue
	}
	labelsNode := object.values["matchLabels"]
	if labelsNode.Kind != yaml.MappingNode {
		return nil, diagnosticPtr(ctx, labelsNode, "invalid_type", "metadata.targetSelector.matchLabels", "matchLabels must be an object")
	}
	if len(labelsNode.Content) == 0 || len(labelsNode.Content)/2 > maxLabelCount {
		return nil, diagnosticPtr(ctx, labelsNode, "invalid_labels", "metadata.targetSelector.matchLabels", "matchLabels must contain between 1 and 64 labels")
	}
	labels := make(map[string]string, len(labelsNode.Content)/2)
	for index := 0; index < len(labelsNode.Content); index += 2 {
		key, value := labelsNode.Content[index], labelsNode.Content[index+1]
		if !stringNode(key) || !labelKeyPattern.MatchString(key.Value) {
			return nil, diagnosticPtr(ctx, key, "invalid_label", "metadata.targetSelector.matchLabels", "label key is invalid")
		}
		if !stringNode(value) || !labelValuePattern.MatchString(value.Value) {
			return nil, diagnosticPtr(ctx, value, "invalid_label", "metadata.targetSelector.matchLabels", "label value must be bounded printable text")
		}
		labels[key.Value] = value.Value
	}
	return &TargetSelector{MatchLabels: labels}, nil
}

func decodeSpec(ctx decodeContext, kind Kind, node *yaml.Node) (any, *Diagnostic) {
	switch kind {
	case KindIntegrationPackage:
		object, issue := decodeObject(ctx, node, "spec", []string{"name", "version"}, []string{"name", "version"})
		if issue != nil {
			return nil, issue
		}
		name, issue := requiredString(ctx, object, "name", "spec.name")
		if issue != nil {
			return nil, issue
		}
		if !idPattern.MatchString(name) {
			return nil, diagnosticPtr(ctx, object.values["name"], "invalid_package_name", "spec.name", "package name must be a bounded lowercase identifier")
		}
		version, issue := requiredString(ctx, object, "version", "spec.version")
		if issue != nil {
			return nil, issue
		}
		if !exactSemver(version) {
			return nil, diagnosticPtr(ctx, object.values["version"], "invalid_version", "spec.version", "package version must be an exact semantic version")
		}
		return IntegrationPackageSpec{Name: name, Version: version}, nil
	case KindAgentPolicy:
		object, issue := decodeObject(ctx, node, "spec", []string{"namespace"}, nil)
		if issue != nil {
			return nil, issue
		}
		namespace := "default"
		if object.values["namespace"] != nil {
			namespace, issue = requiredString(ctx, object, "namespace", "spec.namespace")
			if issue != nil {
				return nil, issue
			}
		}
		if !idPattern.MatchString(namespace) {
			return nil, diagnosticPtr(ctx, object.values["namespace"], "invalid_namespace", "spec.namespace", "namespace must be a bounded lowercase identifier")
		}
		return AgentPolicySpec{Namespace: namespace}, nil
	case KindPackagePolicy:
		object, issue := decodeObject(ctx, node, "spec", []string{"namespace", "integrationRef", "agentPolicyRef"}, []string{"integrationRef", "agentPolicyRef"})
		if issue != nil {
			return nil, issue
		}
		namespace := "default"
		if object.values["namespace"] != nil {
			namespace, issue = requiredString(ctx, object, "namespace", "spec.namespace")
			if issue != nil {
				return nil, issue
			}
		}
		if !idPattern.MatchString(namespace) {
			return nil, diagnosticPtr(ctx, object.values["namespace"], "invalid_namespace", "spec.namespace", "namespace must be a bounded lowercase identifier")
		}
		integration, issue := decodeReference(ctx, object.values["integrationRef"], "spec.integrationRef", KindIntegrationPackage)
		if issue != nil {
			return nil, issue
		}
		agent, issue := decodeReference(ctx, object.values["agentPolicyRef"], "spec.agentPolicyRef", KindAgentPolicy)
		if issue != nil {
			return nil, issue
		}
		return PackagePolicySpec{Namespace: namespace, IntegrationRef: integration, AgentPolicyRef: agent}, nil
	case KindDetectionRule:
		fields := []string{"type", "enabled", "query", "severity", "interval", "language", "index"}
		object, issue := decodeObject(ctx, node, "spec", fields, fields)
		if issue != nil {
			return nil, issue
		}
		ruleType, issue := requiredString(ctx, object, "type", "spec.type")
		if issue != nil {
			return nil, issue
		}
		if ruleType != "query" {
			return nil, diagnosticPtr(ctx, object.values["type"], "unsupported_rule_type", "spec.type", "only query detection rules are supported")
		}
		enabled, issue := requiredBool(ctx, object, "enabled", "spec.enabled")
		if issue != nil {
			return nil, issue
		}
		query, issue := requiredString(ctx, object, "query", "spec.query")
		if issue != nil {
			return nil, issue
		}
		if !boundedPrintable(query, 64<<10) {
			return nil, diagnosticPtr(ctx, object.values["query"], "invalid_query", "spec.query", "query must be bounded printable text")
		}
		severity, issue := requiredString(ctx, object, "severity", "spec.severity")
		if issue != nil {
			return nil, issue
		}
		if severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
			return nil, diagnosticPtr(ctx, object.values["severity"], "invalid_severity", "spec.severity", "severity is not supported")
		}
		interval, issue := requiredString(ctx, object, "interval", "spec.interval")
		if issue != nil {
			return nil, issue
		}
		if !intervalPattern.MatchString(interval) {
			return nil, diagnosticPtr(ctx, object.values["interval"], "invalid_interval", "spec.interval", "interval must be a positive integer followed by s, m, h, or d")
		}
		language, issue := requiredString(ctx, object, "language", "spec.language")
		if issue != nil {
			return nil, issue
		}
		if language != "kuery" && language != "lucene" {
			return nil, diagnosticPtr(ctx, object.values["language"], "unsupported_language", "spec.language", "query language is not supported")
		}
		indexes, issue := requiredStringList(ctx, object, "index", "spec.index")
		if issue != nil {
			return nil, issue
		}
		return DetectionRuleSpec{Type: ruleType, Enabled: enabled, Query: query, Severity: severity, Interval: interval, Language: language, Index: indexes}, nil
	case KindPrebuiltRules:
		_, issue := decodeObject(ctx, node, "spec", nil, nil)
		if issue != nil {
			return nil, issue
		}
		return PrebuiltRulesSpec{}, nil
	default:
		panic("unsupported kind reached spec decoder")
	}
}

func decodeObject(ctx decodeContext, node *yaml.Node, field string, allowed, required []string) (nodeObject, *Diagnostic) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nodeObject{}, diagnosticPtr(ctx, node, "invalid_type", field, "field must be an object")
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	object := nodeObject{values: make(map[string]*yaml.Node), keys: make(map[string]*yaml.Node)}
	for index := 0; index < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		if !stringNode(key) {
			return nodeObject{}, diagnosticPtr(ctx, key, "invalid_field", field, "object keys must be strings")
		}
		if _, ok := allowedSet[key.Value]; !ok {
			code, message := "unknown_field", "object contains an unsupported field"
			if credentialField(key.Value) {
				code, message = "credential_field", "credential-bearing fields are not allowed in mounted resources"
			}
			return nodeObject{}, diagnosticPtr(ctx, key, code, field, message)
		}
		object.values[key.Value], object.keys[key.Value] = value, key
	}
	for _, name := range required {
		if object.values[name] == nil {
			return nodeObject{}, diagnosticPtr(ctx, node, "required_field", joinField(field, name), "required field is missing")
		}
	}
	return object, nil
}

func requiredString(ctx decodeContext, object nodeObject, key, field string) (string, *Diagnostic) {
	node := object.values[key]
	if !stringNode(node) || node.Value == "" {
		return "", diagnosticPtr(ctx, node, "invalid_type", field, "field must be a non-empty string")
	}
	return node.Value, nil
}

func requiredBool(ctx decodeContext, object nodeObject, key, field string) (bool, *Diagnostic) {
	node := object.values[key]
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!bool" || (node.Value != "true" && node.Value != "false") {
		return false, diagnosticPtr(ctx, node, "invalid_type", field, "field must be the canonical boolean true or false")
	}
	return node.Value == "true", nil
}

func requiredStringList(ctx decodeContext, object nodeObject, key, field string) ([]string, *Diagnostic) {
	node := object.values[key]
	if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) == 0 {
		return nil, diagnosticPtr(ctx, node, "invalid_type", field, "field must be a non-empty string array")
	}
	if len(node.Content) > maxCollectionEntries {
		return nil, diagnosticPtr(ctx, node, "too_many_values", field, "array contains too many entries")
	}
	values := make([]string, 0, len(node.Content))
	seen := make(map[string]struct{})
	for _, item := range node.Content {
		if !stringNode(item) || !boundedPrintable(item.Value, maxNameLength) {
			return nil, diagnosticPtr(ctx, item, "invalid_type", field, "array entries must be bounded non-empty strings")
		}
		if _, duplicate := seen[item.Value]; duplicate {
			return nil, diagnosticPtr(ctx, item, "duplicate_value", field, "array entries must be unique")
		}
		seen[item.Value] = struct{}{}
		values = append(values, item.Value)
	}
	return values, nil
}

func decodeReferences(ctx decodeContext, node *yaml.Node, field string, expected Kind) ([]Reference, *Diagnostic) {
	if node.Kind != yaml.SequenceNode {
		return nil, diagnosticPtr(ctx, node, "invalid_type", field, "field must be an array of references")
	}
	if len(node.Content) > maxCollectionEntries {
		return nil, diagnosticPtr(ctx, node, "too_many_references", field, "reference array contains too many entries")
	}
	result := make([]Reference, 0, len(node.Content))
	seen := make(map[string]struct{})
	for _, child := range node.Content {
		reference, issue := decodeReference(ctx, child, field, expected)
		if issue != nil {
			return nil, issue
		}
		key := string(reference.Kind) + "/" + reference.ID
		if _, duplicate := seen[key]; duplicate {
			return nil, diagnosticPtr(ctx, child, "duplicate_reference", field, "references must be unique")
		}
		seen[key] = struct{}{}
		result = append(result, reference)
	}
	return result, nil
}

func decodeReference(ctx decodeContext, node *yaml.Node, field string, expected Kind) (Reference, *Diagnostic) {
	if !stringNode(node) {
		return Reference{}, diagnosticPtr(ctx, node, "invalid_reference", field, "reference must use Kind/id format")
	}
	parts := strings.Split(node.Value, "/")
	if len(parts) != 2 || !supportedKind(Kind(parts[0])) || !idPattern.MatchString(parts[1]) {
		return Reference{}, diagnosticPtr(ctx, node, "invalid_reference", field, "reference must use supported Kind/id format")
	}
	reference := Reference{Kind: Kind(parts[0]), ID: parts[1]}
	if expected != "" && reference.Kind != expected {
		return Reference{}, diagnosticPtr(ctx, node, "invalid_reference_kind", field, "reference kind is not allowed for this field")
	}
	return reference, nil
}

func validateYAMLTree(ctx decodeContext, root *yaml.Node, field string) *Diagnostic {
	type pendingNode struct {
		node  *yaml.Node
		depth int
	}
	pending := []pendingNode{{node: root}}
	visited := 0
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		visited++
		if visited > maxYAMLNodes {
			return diagnosticPtr(ctx, current.node, "yaml_too_complex", field, "YAML document contains too many nodes")
		}
		if current.depth > maxYAMLDepth {
			return diagnosticPtr(ctx, current.node, "yaml_too_deep", field, "YAML document nesting is too deep")
		}
		node := current.node
		if node.Anchor != "" || node.Kind == yaml.AliasNode {
			return diagnosticPtr(ctx, node, "yaml_indirection", field, "YAML anchors and aliases are not allowed")
		}
		if !standardNodeTag(node) {
			return diagnosticPtr(ctx, node, "yaml_tag", field, "custom YAML tags are not allowed")
		}
		if node.Kind == yaml.MappingNode {
			if len(node.Content)%2 != 0 {
				return diagnosticPtr(ctx, node, "invalid_yaml", field, "YAML mapping is malformed")
			}
			seen := make(map[string]*yaml.Node, len(node.Content)/2)
			for index := 0; index < len(node.Content); index += 2 {
				key, value := node.Content[index], node.Content[index+1]
				if key.Value == "<<" {
					return diagnosticPtr(ctx, key, "yaml_indirection", field, "YAML merge keys are not allowed")
				}
				if prior := seen[key.Value]; prior != nil {
					issue := diagnostic(ctx, key, "duplicate_key", field, "object keys must be unique")
					related := location(ctx, prior)
					issue.Related = &related
					return &issue
				}
				seen[key.Value] = key
				pending = append(pending, pendingNode{node: value, depth: current.depth + 1}, pendingNode{node: key, depth: current.depth + 1})
			}
			continue
		}
		for _, child := range node.Content {
			pending = append(pending, pendingNode{node: child, depth: current.depth + 1})
		}
	}
	return nil
}

func standardNodeTag(node *yaml.Node) bool {
	switch node.Kind {
	case yaml.MappingNode:
		return node.Tag == "!!map"
	case yaml.SequenceNode:
		return node.Tag == "!!seq"
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null", "!!timestamp", "!!binary":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func supportedKind(kind Kind) bool {
	switch kind {
	case KindIntegrationPackage, KindAgentPolicy, KindPackagePolicy, KindDetectionRule, KindPrebuiltRules:
		return true
	default:
		return false
	}
}

func credentialField(name string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(name))
	switch normalized {
	case "apikey", "password", "secret", "clientsecret", "token", "authorization", "credential", "credentials", "privatekey", "certificate", "cacertificate", "cacertificatepem", "ca":
		return true
	default:
		return false
	}
}

func exactSemver(value string) bool {
	if !semverPattern.MatchString(value) {
		return false
	}
	prerelease := strings.SplitN(strings.SplitN(value, "+", 2)[0], "-", 2)
	if len(prerelease) == 1 {
		return true
	}
	for _, identifier := range strings.Split(prerelease[1], ".") {
		if len(identifier) > 1 && identifier[0] == '0' {
			numeric := true
			for _, character := range identifier {
				if character < '0' || character > '9' {
					numeric = false
					break
				}
			}
			if numeric {
				return false
			}
		}
	}
	return true
}

func boundedPrintable(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.Is(unicode.Categories["C"], character) {
			return false
		}
	}
	return true
}

func stringNode(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!str"
}
func isEmptyNode(node *yaml.Node) bool {
	return node == nil || (node.Kind == yaml.ScalarNode && node.Tag == "!!null")
}
func firstContent(node *yaml.Node) *yaml.Node {
	if node != nil && len(node.Content) > 0 {
		return node.Content[0]
	}
	return nil
}
func joinField(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}
func parserErrorLocation(ctx decodeContext, err error) source.Location {
	result := location(ctx, nil)
	match := parserLinePattern.FindStringSubmatch(err.Error())
	if len(match) != 2 {
		return result
	}
	line, conversionErr := strconv.Atoi(match[1])
	if conversionErr == nil && line > 0 {
		result.Line = line
		result.Column = 1
	}
	return result
}

func location(ctx decodeContext, node *yaml.Node) source.Location {
	result := source.Location{ResourceSetID: ctx.resourceSetID, RelativePath: ctx.path, Document: ctx.document}
	if node != nil {
		result.Line, result.Column = node.Line, node.Column
	}
	return result
}
func diagnostic(ctx decodeContext, node *yaml.Node, code, field, message string) Diagnostic {
	return Diagnostic{Code: code, Field: field, Message: message, Location: location(ctx, node)}
}
func diagnosticPtr(ctx decodeContext, node *yaml.Node, code, field, message string) *Diagnostic {
	issue := diagnostic(ctx, node, code, field, message)
	return &issue
}
