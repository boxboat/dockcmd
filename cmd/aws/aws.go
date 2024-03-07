// Copyright © 2024 BoxBoat
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

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
)

const latestVersion = "AWSCURRENT"

type SecretsManagerGetSecretAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(options *secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type SecretsClient struct {
	common.SecretClient
	secretsManagerClient *secretsmanager.Client
	secretCache          *cache.Cache
	ctx                  context.Context
	api                  SecretsManagerGetSecretAPI
}

type SecretsClientOpt interface {
	configureSecretsClient(opts *secretsClientOpts) error
}

type secretsClientOpts struct {
	ctx                 context.Context
	region              string
	profile             string
	accessKeyID         string
	secretAccessKey     string
	useChainCredentials bool
	cacheTTL            time.Duration
	api                 *SecretsManagerGetSecretAPI
}

type secretClientOptFn func(opts *secretsClientOpts) error

func CacheTTL(ttl time.Duration) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func AccessKeyIDAndSecretAccessKey(accessKeyID, secretAccessKey string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.accessKeyID = accessKeyID
		opts.secretAccessKey = secretAccessKey
		return nil
	})
}

func Profile(profile string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.profile = profile
		return nil
	})
}

func Region(region string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.region = region
		return nil
	})
}

func UseChainCredentials() SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.useChainCredentials = true
		return nil
	})
}

func WithContext(ctx context.Context) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.ctx = ctx
		return nil
	})
}

func WithMockClient(api SecretsManagerGetSecretAPI) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.api = &api
		return nil
	})
}

func (opt secretClientOptFn) configureSecretsClient(opts *secretsClientOpts) error {
	return opt(opts)
}

func NewSecretsClient(opts ...SecretsClientOpt) (*SecretsClient, error) {
	var o secretsClientOpts
	for _, opt := range opts {
		if opt != nil {
			if err := opt.configureSecretsClient(&o); err != nil {
				return nil, err
			}
		}
	}

	if o.ctx == nil {
		o.ctx = context.Background()
	}

	client := &SecretsClient{
		secretCache: cache.New(o.cacheTTL, o.cacheTTL),
		ctx:         o.ctx,
	}

	// facilitates mock unit testing by allowing the client to be created without a connection to aws
	if o.api == nil {
		var cfg aws.Config
		var err error

		if !o.useChainCredentials {
			if o.accessKeyID == "" || o.secretAccessKey == "" {
				return nil, errors.New("no aws credentials provided")
			}
			cfg, err = config.LoadDefaultConfig(
				o.ctx,
				config.WithRegion(o.region),
				config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(o.accessKeyID, o.secretAccessKey, "")))
			if err != nil {
				return nil, err
			}
		} else {
			cfg, err = config.LoadDefaultConfig(
				o.ctx,
				config.WithRegion(o.region),
				config.WithSharedConfigProfile(o.profile))
			if err != nil {
				return nil, err
			}
		}

		client.secretsManagerClient = secretsmanager.NewFromConfig(cfg)
		client.api = client.secretsManagerClient
	} else {
		client.api = *o.api
	}
	return client, nil
}

func (c *SecretsClient) GetSecret(secretName string) (string, string, error) {
	adjustedSecretName := secretName
	version := latestVersion
	s := strings.Split(adjustedSecretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		adjustedSecretName = s[0]
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(adjustedSecretName),
	}
	if version == latestVersion || version == "latest" {
		input.VersionStage = aws.String(latestVersion)
	} else {
		input.VersionId = aws.String(version)
	}

	common.Logger.Debugf("retrieving [%s] from AWS Secrets Manager", adjustedSecretName)
	result, err := c.api.GetSecretValue(c.ctx, input)

	if err != nil {
		var errorMessage string
		var decryptionFailure *types.DecryptionFailure
		var internalServer *types.InternalServiceError
		var invalidParameter *types.InvalidParameterException
		var invalidRequest *types.InvalidRequestException
		var notFound *types.ResourceNotFoundException

		if errors.As(err, &decryptionFailure) {
			errorMessage = fmt.Sprintf("secret{%s}: %s %s", adjustedSecretName, decryptionFailure.ErrorCode(), decryptionFailure.ErrorMessage())
		} else if errors.As(err, &internalServer) {
			errorMessage = fmt.Sprintf("secret{%s}: %s %s", adjustedSecretName, internalServer.ErrorCode(), internalServer.ErrorMessage())
		} else if errors.As(err, &invalidParameter) {
			errorMessage = fmt.Sprintf("secret{%s}: %s %s", adjustedSecretName, invalidParameter.ErrorCode(), invalidParameter.ErrorMessage())
		} else if errors.As(err, &invalidRequest) {
			errorMessage = fmt.Sprintf("secret{%s}: %s %s", adjustedSecretName, invalidRequest.ErrorCode(), invalidRequest.ErrorMessage())
		} else if errors.As(err, &notFound) {
			errorMessage = fmt.Sprintf("secret{%s}: %s %s", adjustedSecretName, notFound.ErrorCode(), notFound.ErrorMessage())
		} else {
			errorMessage = fmt.Sprintf("secret{%s}: %v", adjustedSecretName, err)
		}
		return adjustedSecretName, "", errors.New(errorMessage)
	}
	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	}

	return adjustedSecretName, secretString, nil
}

func (c *SecretsClient) GetTextSecret(secretName string) (string, error) {
	if val, ok := c.secretCache.Get(secretName); ok {
		common.Logger.Debugf("using cached [%s]", secretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	_, secretString, err := c.GetSecret(secretName)
	if err != nil {
		return "", err
	}

	_ = c.secretCache.Add(secretName, secretString, cache.DefaultExpiration)

	return secretString, nil

}

func (c *SecretsClient) GetJSONSecret(secretName, secretKey string) (string, error) {
	if val, ok := c.secretCache.Get(secretName); ok {
		common.Logger.Debugf("using cached [%s][%s]", secretName, secretKey)
		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
			return secretStr, nil
		}
	}

	adjustedSecretName, secretString, err := c.GetSecret(secretName)
	if err != nil {
		return "", err
	}

	var response map[string]interface{}
	if err = json.Unmarshal([]byte(secretString), &response); err != nil {
		return "", err
	}

	secretStr, ok := response[secretKey].(string)
	if !ok {
		return "", fmt.Errorf("could not convert secrets manager response[%s] for secret [%s] to string",
			secretStr,
			adjustedSecretName)
	}
	_ = c.secretCache.Add(secretName, response, cache.DefaultExpiration)

	return secretStr, nil
}
