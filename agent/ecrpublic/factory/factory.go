// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//    http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package factory

import (
	"time"

	ecrpublicclient "github.com/aws/amazon-ecs-agent/agent/ecrpublic"
	"github.com/aws/amazon-ecs-agent/agent/httpclient"
	"github.com/aws/aws-sdk-go/aws"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecrpublic"
	"github.com/cihub/seelog"
)

const (
	roundtripTimeout = 5 * time.Second
	ecrPublicRegion  = "us-east-1"
)

type ECRPublicClientCreator interface {
	NewECRPublicClient(creds *awscreds.Credentials) ecrpublicclient.ECRPublicClient
}

func NewECRPublicClientCreator() ECRPublicClientCreator {
	return &ecrPublicClientCreator{}
}

type ecrPublicClientCreator struct{}

func (*ecrPublicClientCreator) NewECRPublicClient(awscred *awscreds.Credentials) ecrpublicclient.ECRPublicClient {

	creds, err := awscred.Get()
	if err != nil {
		seelog.Errorf("Error getting valid credentials: %s", err)
	}
	cfg := aws.NewConfig().
		WithHTTPClient(httpclient.New(roundtripTimeout, false)).
		WithRegion(ecrPublicRegion).
		WithCredentials(
			awscreds.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey,
				creds.SessionToken))
	sess := session.Must(session.NewSession(cfg))
	return ecrpublic.New(sess)

}
