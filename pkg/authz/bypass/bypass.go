// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bypass

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type bypassMatchStrategy int

const (
	bypassMatchUnknown bypassMatchStrategy = 0
	bypassMatchExact   bypassMatchStrategy = 1
	bypassMatchPartial bypassMatchStrategy = 2
	bypassMatchPrefix  bypassMatchStrategy = 3
	bypassMatchSuffix  bypassMatchStrategy = 4
	bypassMatchRegex   bypassMatchStrategy = 5
)

// Config contains the entry for the authorization bypass.
type Config struct {
	MatchType string `json:"match_type,omitempty" xml:"match_type,omitempty" yaml:"match_type,omitempty"`
	URI       string `json:"uri,omitempty" xml:"uri,omitempty" yaml:"uri,omitempty"`
	match     bypassMatchStrategy
	regex     *regexp.Regexp
}

// Validate validates Config
func (b *Config) Validate() error {
	switch b.MatchType {
	case "exact":
		b.match = bypassMatchExact
	case "partial":
		b.match = bypassMatchPartial
	case "prefix":
		b.match = bypassMatchPrefix
	case "suffix":
		b.match = bypassMatchSuffix
	case "regex":
		b.match = bypassMatchRegex
	case "":
		return fmt.Errorf("undefined bypass match type")
	default:
		return fmt.Errorf("invalid %q bypass match type", b.MatchType)
	}
	b.URI = strings.TrimSpace(b.URI)
	if b.URI == "" {
		return fmt.Errorf("undefined bypass uri")
	}
	if b.regex == nil {
		r, err := regexp.Compile(b.URI)
		if err != nil {
			return err
		}
		b.regex = r
	}
	return nil
}

// Match matches HTTP URL to the bypass configuration.
// The request path is lower-cased before every string comparison so that all
// non-regex bypass rules are case-insensitive. This mirrors Caddy's intended
// MatchPath behaviour and prevents case-variation bypasses (CVE-2026-27587).
func Match(r *http.Request, cfgs []*Config) bool {
	// Normalise once; the regex branch uses the original to stay consistent
	// with the configured pattern (regex authors opt-in to (?i) themselves).
	reqPath := strings.ToLower(r.URL.Path)
	for _, cfg := range cfgs {
		switch cfg.match {
		case bypassMatchExact:
			if strings.ToLower(cfg.URI) == reqPath {
				return true
			}
		case bypassMatchPartial:
			if strings.Contains(reqPath, strings.ToLower(cfg.URI)) {
				return true
			}
		case bypassMatchPrefix:
			if strings.HasPrefix(reqPath, strings.ToLower(cfg.URI)) {
				return true
			}
		case bypassMatchSuffix:
			if strings.HasSuffix(reqPath, strings.ToLower(cfg.URI)) {
				return true
			}
		case bypassMatchRegex:
			if cfg.regex.MatchString(r.URL.Path) {
				return true
			}
		}
	}
	return false
}
