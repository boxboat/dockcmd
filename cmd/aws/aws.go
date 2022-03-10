// Copyright © 2022 BoxBoat engineering@boxboat.com
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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
)

const latestVersion = "AWSCURRENT"

type SecretsClient struct {
	common.SecretClient
	secretsManagerClient *secretsmanager.SecretsManager
	secretCache          *cache.Cache
}

// SessionProvider custom provider to allow for fallback to session configured credentials.
type SessionProvider struct {
	Session *session.Session
}

type SecretsClientOpt interface {
	configureSecretsClient(opts *secretsClientOpts) error
}

type secretsClientOpts struct {
	region              string
	profile             string
	accessKeyID         string
	secretAccessKey     string
	useChainCredentials bool
	cacheTTL            time.Duration
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

	client := &SecretsClient{
		secretCache: cache.New(o.cacheTTL, o.cacheTTL),
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	var creds = sess.Config.Credentials
	if o.useChainCredentials {
		creds = credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{
					Profile: o.profile,
				},
				&ec2rolecreds.EC2RoleProvider{
					Client: ec2metadata.New(sess),
				},
				&SessionProvider{
					Session: sess,
				},
			})
	} else {
		if o.accessKeyID == "" || o.secretAccessKey == "" {
			return nil, errors.New("no aws credentials provided")
		}
		creds = credentials.NewStaticCredentials(o.accessKeyID, o.secretAccessKey, "")
	}

	client.secretsManagerClient = secretsmanager.New(
		sess,
		aws.NewConfig().WithRegion(o.region).WithCredentials(creds))

	return client, nil
}

// Retrieve for SessionProvider.
func (m *SessionProvider) Retrieve() (credentials.Value, error) {
	return m.Session.Config.Credentials.Get()
}

// IsExpired for SessionProvider.
func (m *SessionProvider) IsExpired() bool {
	return m.Session.Config.Credentials.IsExpired()
}

func (c *SecretsClient) getSecret(secretName string) (string, string, error) {
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
	result, err := c.secretsManagerClient.GetSecretValue(input)

	if err != nil {
		var errorMessage string
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				errorMessage = fmt.Sprintf("secret{%s}: %v %v", adjustedSecretName, secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
				break

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				errorMessage = fmt.Sprintf("secret{%s}: %v %v", adjustedSecretName, secretsmanager.ErrCodeInternalServiceError, aerr.Error())
				break

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				errorMessage = fmt.Sprintf("secret{%s}: %v %v", adjustedSecretName, secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
				break

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				errorMessage = fmt.Sprintf("secret{%s}: %v %v", adjustedSecretName, secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
				break

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				errorMessage = fmt.Sprintf("secret{%s}: %v %v", adjustedSecretName, secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
				break

			default:
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v", adjustedSecretName, aerr.Error())
				break
			}
		} else {
			errorMessage = fmt.Sprintln(err.Error())
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

	_, secretString, err := c.getSecret(secretName)
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

	adjustedSecretName, secretString, err := c.getSecret(secretName)
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
