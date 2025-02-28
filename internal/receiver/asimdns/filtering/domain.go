//go:build windows
// +build windows

package filtering

import (
	"github.com/0xrawsec/golang-etw/etw"
	"go.uber.org/zap"
	"regexp"
	"strings"
)

// DomainFilter handles filtering based on domain patterns
type DomainFilter struct {
	logger        *zap.Logger
	domainRegexes []*regexp.Regexp
}

// NewDomainFilter creates a new DomainFilter
func NewDomainFilter(logger *zap.Logger, excludedDomains []string) *DomainFilter {
	filter := &DomainFilter{
		logger:        logger,
		domainRegexes: make([]*regexp.Regexp, 0, len(excludedDomains)),
	}
	
	// Compile the domain pattern regexes for efficient matching
	for _, pattern := range excludedDomains {
		// Convert glob pattern to regex
		regexPattern := strings.Replace(pattern, ".", "\\.", -1)
		regexPattern = strings.Replace(regexPattern, "*", ".*", -1)
		regexPattern = "^" + regexPattern + "$"
		
		regex, err := regexp.Compile(regexPattern)
		if err != nil {
			logger.Warn("Failed to compile domain pattern",
				zap.String("pattern", pattern),
				zap.Error(err))
			continue
		}
		
		filter.domainRegexes = append(filter.domainRegexes, regex)
		logger.Debug("Added domain pattern", 
			zap.String("pattern", pattern),
			zap.String("regex", regexPattern))
	}
	
	logger.Info("Domain filter initialized", 
		zap.Int("patternCount", len(filter.domainRegexes)))
	
	return filter
}

// ShouldFilter checks if a domain should be filtered
func (f *DomainFilter) ShouldFilter(event *etw.Event, getEventDataString func(*etw.Event, string) (string, bool)) bool {
	// If no domain regex patterns are configured, don't filter
	if len(f.domainRegexes) == 0 {
		return false
	}
	
	// Extract the query name from the event
	queryName, ok := getEventDataString(event, "QueryName")
	if !ok || queryName == "" {
		return false
	}
	
	// Check the domain against all regex patterns
	for _, regex := range f.domainRegexes {
		if regex.MatchString(queryName) {
			f.logger.Debug("Filtering domain based on pattern", 
				zap.String("domain", queryName),
				zap.String("pattern", regex.String()))
			return true
		}
	}
	
	return false
}
