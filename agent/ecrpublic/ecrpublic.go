package ecrpublic

import (
	"fmt"

	"github.com/aws/aws-sdk-go/service/ecrpublic"
)

// GetAuthorizationToken returns authorization token for ecr public repositories
func GetAuthorizationToken(client ECRPublicClient) (*ecrpublic.AuthorizationData, error) {
	output, err := client.GetAuthorizationToken(&ecrpublic.GetAuthorizationTokenInput{})

	if err != nil {
		return nil, err
	}

	if output.AuthorizationData == nil {
		return nil, fmt.Errorf("Authorization token for ecr public repository is nil")
	}
	return output.AuthorizationData, nil
}
