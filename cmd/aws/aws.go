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

type SecretsManager struct {
	common.SecretClient
	Session              *session.Session
	SecretsManagerClient *secretsmanager.SecretsManager
	SecretCache          *cache.Cache
}

// SessionProvider custom provider to allow for fallback to session configured credentials.
type SessionProvider struct {
	Session *session.Session
}

type SecretsManagerOpt interface {
	configureSecretsManager(opts *secretsManagerOpts) error
}

type secretsManagerOpts struct {
	region              string
	profile             string
	accessKeyID         string
	secretAccessKey     string
	useChainCredentials bool
	cacheTTL            time.Duration
}

type secretManagerOptFn func(opts *secretsManagerOpts) error

func CacheTTL(ttl time.Duration) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func AccessKeyIDAndSecretAccessKey(accessKeyID, secretAccessKey string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.accessKeyID = accessKeyID
		opts.secretAccessKey = secretAccessKey
		return nil
	})
}

func Profile(profile string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.profile = profile
		return nil
	})
}

func Region(region string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.region = region
		return nil
	})
}

func UseChainCredentials() SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.useChainCredentials = true
		return nil
	})
}

func (opt secretManagerOptFn) configureSecretsManager(opts *secretsManagerOpts) error {
	return opt(opts)
}

func NewSecretsManagerClient(opts ...SecretsManagerOpt) (*SecretsManager, error) {
	var o secretsManagerOpts
	for _, opt := range opts {
		if opt != nil {
			if err := opt.configureSecretsManager(&o); err != nil {
				return nil, err
			}
		}
	}

	client := &SecretsManager{
		SecretCache: cache.New(o.cacheTTL, o.cacheTTL),
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

	client.SecretsManagerClient = secretsmanager.New(
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

func (c *SecretsManager) getSecret(secretName string) (string, string, error) {
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

	common.Logger.Debugf("Retrieving %s", adjustedSecretName)

	common.Logger.Debugf("Retrieving [%s] from AWS Secrets Manager", adjustedSecretName)
	result, err := c.SecretsManagerClient.GetSecretValue(input)

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

func (c *SecretsManager) GetTextSecret(secretName string) (string, error) {
	if val, ok := c.SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s]", secretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	_, secretString, err := c.getSecret(secretName)
	if err != nil {
		return "", err
	}

	_ = c.SecretCache.Add(secretName, secretString, cache.DefaultExpiration)

	return secretString, nil

}

func (c *SecretsManager) GetJSONSecret(secretName, secretKey string) (string, error) {
	if val, ok := c.SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
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
	_ = c.SecretCache.Add(secretName, response, cache.DefaultExpiration)

	return secretStr, nil
}

//var (
//	Region               string
//	Profile              string
//	AccessKeyID          string
//	SecretAccessKey      string
//	UseChainCredentials  bool
//	Session              *session.Session
//	SecretsManagerClient *secretsmanager.SecretsManager
//	SecretCache          *cache.Cache
//	CacheTTL             = 5 * time.Minute
//)

//func init() {
//	SecretCache = cache.New(CacheTTL, CacheTTL)
//}

//func getAwsCredentials(sess *session.Session) *credentials.Credentials {
//	var creds = sess.Config.Credentials
//	if UseChainCredentials {
//		creds = credentials.NewChainCredentials(
//			[]credentials.Provider{
//				&credentials.EnvProvider{},
//				&credentials.SharedCredentialsProvider{
//					Profile: Profile,
//				},
//				&ec2rolecreds.EC2RoleProvider{
//					Client: ec2metadata.New(sess),
//				},
//				&SessionProvider{
//					Session: sess,
//				},
//			})
//	} else {
//		creds = credentials.NewStaticCredentials(AccessKeyID, SecretAccessKey, "")
//	}
//	return creds
//}

//func getAwsSession() (*session.Session, error) {
//	if Session == nil {
//		var err error
//		Session, err = session.NewSessionWithOptions(session.Options{
//			SharedConfigState: session.SharedConfigEnable,
//		})
//		if err != nil {
//			return nil, err
//		}
//	}
//	return Session, nil
//}

//func getAwsSecretsManagerClient() (*secretsmanager.SecretsManager, error) {
//	if SecretsManagerClient == nil {
//		sess, err := getAwsSession()
//		if err != nil {
//			return nil, err
//		}
//		SecretsManagerClient = secretsmanager.New(
//			sess,
//			aws.NewConfig().WithRegion(Region).WithCredentials(
//				getAwsCredentials(sess)))
//	}
//	return SecretsManagerClient, nil
//}

//func GetAwsSecret(secretName string, secretKey string) (string, error) {
//	adjustedSecretName := secretName
//	version := latestVersion
//	s := strings.Split(adjustedSecretName, "?version=")
//	if len(s) > 1 {
//		version = s[1]
//		adjustedSecretName = s[0]
//	}
//
//	input := &secretsmanager.GetSecretValueInput{
//		SecretId: aws.String(adjustedSecretName),
//	}
//	if version == latestVersion || version == "latest" {
//		input.VersionStage = aws.String(latestVersion)
//	} else {
//		input.VersionId = aws.String(version)
//	}
//
//	common.Logger.Debugf("Retrieving %s", adjustedSecretName)
//
//	if val, ok := SecretCache.Get(secretName); ok {
//		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
//		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
//			return secretStr, nil
//		}
//	}
//
//	//Create a Secrets Manager client
//	svc, err := getAwsSecretsManagerClient()
//	if err != nil {
//		return "", err
//	}
//
//	common.Logger.Debugf("Retrieving [%s] from AWS Secrets Manager", adjustedSecretName)
//	result, err := svc.GetSecretValue(input)
//
//	if err != nil {
//		var errorMessage string
//		if aerr, ok := err.(awserr.Error); ok {
//			switch aerr.Code() {
//			case secretsmanager.ErrCodeDecryptionFailure:
//				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
//				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", adjustedSecretName, secretKey, secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
//				break
//
//			case secretsmanager.ErrCodeInternalServiceError:
//				// An error occurred on the server side.
//				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", adjustedSecretName, secretKey, secretsmanager.ErrCodeInternalServiceError, aerr.Error())
//				break
//
//			case secretsmanager.ErrCodeInvalidParameterException:
//				// You provided an invalid value for a parameter.
//				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", adjustedSecretName, secretKey, secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
//				break
//
//			case secretsmanager.ErrCodeInvalidRequestException:
//				// You provided a parameter value that is not valid for the current state of the resource.
//				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", adjustedSecretName, secretKey, secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
//				break
//
//			case secretsmanager.ErrCodeResourceNotFoundException:
//				// We can't find the resource that you asked for.
//				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", adjustedSecretName, secretKey, secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
//				break
//
//			default:
//				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v", adjustedSecretName, secretKey, aerr.Error())
//				break
//			}
//		} else {
//			errorMessage = fmt.Sprintln(err.Error())
//		}
//		return "", errors.New(errorMessage)
//	}
//
//	// Decrypts secret using the associated KMS CMK.
//	// Depending on whether the secret is a string or binary, one of these fields will be populated.
//	var secretString string
//	if result.SecretString != nil {
//		secretString = *result.SecretString
//	}
//
//	common.Logger.Debugf("Secret %s:%s", adjustedSecretName, secretString)
//	var response map[string]interface{}
//	if err = json.Unmarshal([]byte(secretString), &response); err != nil {
//		return "", err
//	}
//
//	secretStr, ok := response[secretKey].(string)
//	if !ok {
//		return "", fmt.Errorf("could not convert secrets manager response[%s][%s] to string",
//			adjustedSecretName,
//			secretKey)
//	}
//	_ = SecretCache.Add(secretName, response, cache.DefaultExpiration)
//
//	return secretStr, nil
//}
