package manifest

// SelectorMatches reports whether labels satisfy every exact-match selector
// requirement. A nil selector applies to every target in the resource set.
func SelectorMatches(selector *TargetSelector, labels map[string]string) bool {
	if selector == nil {
		return true
	}
	for key, expected := range selector.MatchLabels {
		actual, exists := labels[key]
		if !exists || actual != expected {
			return false
		}
	}
	return true
}
