package go_simple_apikey_middleware

type DefaultApiKeyDetailsService struct {
	apiKeyMap map[string]*ApiKeyDetails
}

func NewDefaultApiKeyDetailsService() *DefaultApiKeyDetailsService {
	return &DefaultApiKeyDetailsService{
		apiKeyMap: make(map[string]*ApiKeyDetails, 0),
	}
}

func (service *DefaultApiKeyDetailsService) AddApiKeyDetails(apiKeyDetails *ApiKeyDetails) {
	service.apiKeyMap[apiKeyDetails.ApiKey] = apiKeyDetails
}

func (service *DefaultApiKeyDetailsService) GetApiKeyDetails(apiKey string) (*ApiKeyDetails, bool, error) {
	apiKeyDetails, ok := service.apiKeyMap[apiKey]
	return apiKeyDetails, ok, nil
}
