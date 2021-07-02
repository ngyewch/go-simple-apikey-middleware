package go_simple_apikey_middleware

type ApiKeyDetailsService interface {
	GetApiKeyDetails(apiKey string) (*ApiKeyDetails, bool, error)
}

type ApiKeyDetails struct {
	ApiKey         string
	IssuedTo       string
	Authorities    []string
	ApiKeyDisabled bool
	ApiKeyExpired  bool
	ApiKeyLocked   bool
}
