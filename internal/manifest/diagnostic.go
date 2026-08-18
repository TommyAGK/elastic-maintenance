package manifest

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

type Diagnostic struct {
	Code     string           `json:"code"`
	Field    string           `json:"field,omitempty"`
	Message  string           `json:"message"`
	Location source.Location  `json:"location"`
	Related  *source.Location `json:"related,omitempty"`
}

type DiagnosticsError struct {
	Diagnostics []Diagnostic
}

func (err *DiagnosticsError) Error() string {
	if len(err.Diagnostics) == 0 {
		return "manifest validation failed"
	}
	first := err.Diagnostics[0]
	where := fmt.Sprintf("resource set %q file %q document %d", first.Location.ResourceSetID, first.Location.RelativePath, first.Location.Document)
	if first.Location.Line > 0 {
		where += fmt.Sprintf(" line %d column %d", first.Location.Line, first.Location.Column)
	}
	return where + ": " + first.Code + ": " + first.Message
}

func sortDiagnostics(diagnostics []Diagnostic) {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		left, right := diagnostics[i], diagnostics[j]
		if left.Location.RelativePath != right.Location.RelativePath {
			return left.Location.RelativePath < right.Location.RelativePath
		}
		if left.Location.Document != right.Location.Document {
			return left.Location.Document < right.Location.Document
		}
		if left.Location.Line != right.Location.Line {
			return left.Location.Line < right.Location.Line
		}
		if left.Location.Column != right.Location.Column {
			return left.Location.Column < right.Location.Column
		}
		if left.Code != right.Code {
			return strings.Compare(left.Code, right.Code) < 0
		}
		if left.Field != right.Field {
			return strings.Compare(left.Field, right.Field) < 0
		}
		return strings.Compare(left.Message, right.Message) < 0
	})
}
