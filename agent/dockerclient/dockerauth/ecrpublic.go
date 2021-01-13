package dockerauth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	apicontainer "github.com/aws/amazon-ecs-agent/agent/api/container"
	"github.com/aws/amazon-ecs-agent/agent/async"
	ecrpublicclient "github.com/aws/amazon-ecs-agent/agent/ecrpublic"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecrpublic"
	log "github.com/cihub/seelog"
	"github.com/docker/docker/api/types"
)

type ecrPublicAuthProvider struct {
	ecrPublicClient ecrpublicclient.ECRPublicClient
	tokenCache      async.Cache
}

// NewECRPublicAuthProvider returns a DockerAuthProvider that can handle retrieve
// credentials for pulling from Amazon EC2 Container Registry
func NewECRPublicAuthProvider(client ecrpublicclient.ECRPublicClient, cache async.Cache) DockerAuthProvider {
	return &ecrPublicAuthProvider{
		ecrPublicClient: client,
		tokenCache:      cache,
	}
}

// GetAuthconfig retrieves the correct auth configuration for the given repository
func (authProvider *ecrPublicAuthProvider) GetAuthconfig(image string, registryAuthData *apicontainer.RegistryAuthenticationData) (types.AuthConfig, error) {
	// Try to get the auth config from cache
	auth := authProvider.getPublicAuthConfigFromCache()
	if auth != nil {
		return *auth, nil
	}

	// Get the auth config from ECR
	return authProvider.getAuthConfigFromECRPublic()
}

// getAuthconfigFromCache retrieves the token from cache
func (authProvider *ecrPublicAuthProvider) getPublicAuthConfigFromCache() *types.AuthConfig {
	token, ok := authProvider.tokenCache.Get("ecrPublicKey")
	if !ok {
		return nil
	}

	cachedToken, ok := token.(*ecrpublic.AuthorizationData)
	if !ok {
		log.Warnf("Reading ECR credentials from cache failed")
		return nil
	}

	if isTokenExpired(cachedToken) {
		log.Errorf("ECR public authentication token has expired.")
		authProvider.tokenCache.Delete("ecrPublicKey")
		return nil
	}

	auth, err := extractECRPublicToken(cachedToken)
	if err != nil {
		log.Errorf("Extract docker auth from cache failed, err: %v", err)
	}
	return &auth
}

// getAuthConfigFromECR calls the ECR API to get docker auth config
func (authProvider *ecrPublicAuthProvider) getAuthConfigFromECRPublic() (types.AuthConfig, error) {
	log.Debugf("Calling ECR.GetAuthorizationToken for ecr-public%")
	cachedToken, err := ecrpublicclient.GetAuthorizationToken(authProvider.ecrPublicClient)
	if err != nil {
		return types.AuthConfig{}, err
	}
	if cachedToken == nil {
		return types.AuthConfig{}, fmt.Errorf("ecr auth: missing AuthorizationData in ECR public")
	}

	// Cache the new token
	authProvider.tokenCache.Set("ecrPublicKey", cachedToken)
	return extractECRPublicToken(cachedToken)
}

func extractECRPublicToken(authData *ecrpublic.AuthorizationData) (types.AuthConfig, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(aws.StringValue(authData.AuthorizationToken))
	if err != nil {
		return types.AuthConfig{}, err
	}
	parts := strings.SplitN(string(decodedToken), ":", 2)
	return types.AuthConfig{
		Username: parts[0],
		Password: parts[1],
	}, nil
}

func isTokenExpired(authData *ecrpublic.AuthorizationData) bool {
	return time.Now().After(*authData.ExpiresAt)
}
