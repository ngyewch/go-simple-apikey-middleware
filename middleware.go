package go_simple_apikey_middleware

import (
	"github.com/bmatcuk/doublestar/v4"
	slog "github.com/go-eden/slf4go"
	"net/http"
)

type Middleware struct {
	apiKeyDetailsService ApiKeyDetailsService
	pathConfig           PathConfig
}

type PathConfig struct {
	IncludedPatterns []string
}

var (
	logger slog.Logger
)

func init() {
	logger = slog.GetLogger()
}

func NewMiddleware(apiKeyDetailsService ApiKeyDetailsService, pathConfig PathConfig) *Middleware {
	return &Middleware{
		apiKeyDetailsService: apiKeyDetailsService,
		pathConfig:           pathConfig,
	}
}

func (middleware *Middleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !matchUri(r.URL.Path, middleware.pathConfig.IncludedPatterns) {
			// this is not a secured URI
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		apiKeyDetails, exists, err := middleware.apiKeyDetailsService.GetApiKeyDetails(apiKey)
		if err != nil {
			logger.Fatalf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if apiKeyDetails.ApiKeyDisabled {
			logger.Warnf("API key issued to '%s' disabled", apiKeyDetails.IssuedTo)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if apiKeyDetails.ApiKeyExpired {
			logger.Warnf("API key issued to '%s' expired", apiKeyDetails.IssuedTo)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if apiKeyDetails.ApiKeyLocked {
			logger.Warnf("API key issued to '%s' locked", apiKeyDetails.IssuedTo)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func matchUri(uri string, uriPatterns []string) bool {
	for _, uriPattern := range uriPatterns {
		match, _ := doublestar.Match(uriPattern, uri)
		if match {
			return true
		}
	}
	return false
}
