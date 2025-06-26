package go_simple_apikey_middleware

import (
	"github.com/bmatcuk/doublestar/v4"
	"log/slog"
	"net/http"
)

type Middleware struct {
	apiKeyDetailsService ApiKeyDetailsService
	pathConfig           PathConfig
}

type PathConfig struct {
	IncludedPatterns []string
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
			slog.Error("internal server error",
				slog.Any("err", err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if apiKeyDetails.ApiKeyDisabled {
			slog.Warn("API key disabled",
				slog.String("issuedTo", apiKeyDetails.IssuedTo),
			)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if apiKeyDetails.ApiKeyExpired {
			slog.Warn("API key expired",
				slog.String("issuedTo", apiKeyDetails.IssuedTo),
			)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if apiKeyDetails.ApiKeyLocked {
			slog.Warn("API key locked",
				slog.String("issuedTo", apiKeyDetails.IssuedTo),
			)
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
