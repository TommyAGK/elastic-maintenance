package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
)

const (
	listPageSize = 100
	maxListItems = 100000
	maxListPages = 10000
)

type cursorPage[T any] struct {
	Items       *[]T     `json:"items"`
	SearchAfter []string `json:"searchAfter"`
	Total       *int     `json:"total"`
}
type numberedPage[T any] struct {
	Items   *[]T `json:"items"`
	Data    *[]T `json:"data"`
	Page    *int `json:"page"`
	PerPage *int `json:"perPage"`
	Total   *int `json:"total"`
}

func (c *Client) installedPackages(ctx context.Context) ([]InstalledPackage, error) {
	items := []InstalledPackage{}
	var cursor []string
	seen := map[string]bool{}
	expectedTotal := -1
	for pageNumber := 0; pageNumber < maxListPages; pageNumber++ {
		query := url.Values{"perPage": {strconv.Itoa(listPageSize)}}
		if len(cursor) != 0 {
			encoded, _ := json.Marshal(cursor)
			query.Set("searchAfter", string(encoded))
		}
		var page cursorPage[InstalledPackage]
		if err := c.getJSON(ctx, "/api/fleet/epm/packages/installed?"+query.Encode(), &page); err != nil {
			return nil, err
		}
		if page.Items == nil || page.Total == nil || *page.Total < 0 || *page.Total > maxListItems {
			return nil, paginationError()
		}
		if expectedTotal < 0 {
			expectedTotal = *page.Total
		} else if *page.Total != expectedTotal {
			return nil, paginationError()
		}
		pageItems := *page.Items
		if len(pageItems) > listPageSize || len(items)+len(pageItems) > expectedTotal {
			return nil, paginationError()
		}
		key := ""
		if len(page.SearchAfter) != 0 {
			encoded, _ := json.Marshal(page.SearchAfter)
			if len(encoded) > 4096 {
				return nil, paginationError()
			}
			key = string(encoded)
			if equalCursor(cursor, page.SearchAfter) || seen[key] {
				return nil, paginationError()
			}
		}
		items = append(items, pageItems...)
		if len(items) == expectedTotal {
			return items, nil
		}
		if key == "" {
			return nil, paginationError()
		}
		seen[key] = true
		cursor = append([]string{}, page.SearchAfter...)
	}
	return nil, paginationError()
}

func (c *Client) agentPolicies(ctx context.Context) ([]AgentPolicy, error) {
	return numberedItems[AgentPolicy](ctx, c, "/api/fleet/agent_policies", false)
}
func (c *Client) packagePolicies(ctx context.Context) ([]PackagePolicy, error) {
	return numberedItems[PackagePolicy](ctx, c, "/api/fleet/package_policies", false)
}
func (c *Client) rules(ctx context.Context) ([]Rule, error) {
	return numberedItems[Rule](ctx, c, "/api/detection_engine/rules/_find", true)
}

func numberedItems[T any](ctx context.Context, c *Client, path string, rules bool) ([]T, error) {
	items := []T{}
	expectedTotal := -1
	for requested := 1; requested <= maxListPages; requested++ {
		query := url.Values{"page": {strconv.Itoa(requested)}}
		if rules {
			query.Set("per_page", strconv.Itoa(listPageSize))
		} else {
			query.Set("perPage", strconv.Itoa(listPageSize))
		}
		var response numberedPage[T]
		if err := c.getJSON(ctx, path+"?"+query.Encode(), &response); err != nil {
			return nil, err
		}
		var pageItems []T
		if rules {
			if response.Data == nil {
				return nil, paginationError()
			}
			pageItems = *response.Data
		} else {
			if response.Items == nil {
				return nil, paginationError()
			}
			pageItems = *response.Items
		}
		if response.Page == nil || response.PerPage == nil || response.Total == nil || *response.Page != requested || *response.PerPage < 1 || *response.PerPage > listPageSize || *response.Total < 0 || *response.Total > maxListItems || len(pageItems) > *response.PerPage {
			return nil, paginationError()
		}
		if expectedTotal < 0 {
			expectedTotal = *response.Total
		} else if *response.Total != expectedTotal {
			return nil, paginationError()
		}
		if len(items)+len(pageItems) > expectedTotal {
			return nil, paginationError()
		}
		items = append(items, pageItems...)
		if len(items) == expectedTotal {
			return items, nil
		}
		if len(pageItems) == 0 {
			return nil, paginationError()
		}
	}
	return nil, paginationError()
}
func equalCursor(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func paginationError() error {
	return &ResponseError{StatusCode: 0, Message: "Kibana pagination response is invalid", kind: ErrorProtocol}
}
func isPaginationError(err error) bool {
	var remote *ResponseError
	return errors.As(err, &remote) && remote.Kind() == ErrorProtocol
}
