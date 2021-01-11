package ecrpublic

import "github.com/aws/aws-sdk-go/service/ecrpublic"

type ECRPublicClient interface {
	GetAuthorizationToken(*ecrpublic.GetAuthorizationTokenInput) (*ecrpublic.GetAuthorizationTokenOutput, error)
}
