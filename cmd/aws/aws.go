// Copyright © 2021 BoxBoat engineering@boxboat.com
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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
	"time"
)

var (
	Region               string
	Profile              string
	AccessKeyID          string
	SecretAccessKey      string
	UseChainCredentials  bool
	Session              *session.Session
	SecretsManagerClient *secretsmanager.SecretsManager
	SecretCache          *cache.Cache
	CacheTTL             = 5 * time.Minute
)

func init(){
	SecretCache = cache.New(CacheTTL, CacheTTL)
}

// SessionProvider custom provider to allow for fallback to session configured credentials.
type SessionProvider struct {
	Session *session.Session
}

// Retrieve for SessionProvider.
func (m *SessionProvider) Retrieve() (credentials.Value, error) {
	return m.Session.Config.Credentials.Get()
}

// IsExpired for SessionProvider.
func (m *SessionProvider) IsExpired() bool {
	return m.Session.Config.Credentials.IsExpired()
}

func getAwsCredentials(sess *session.Session) *credentials.Credentials {
	var creds = sess.Config.Credentials
	if UseChainCredentials {
		creds = credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{
					Profile: Profile,
				},
				&ec2rolecreds.EC2RoleProvider{
					Client: ec2metadata.New(sess),
				},
				&SessionProvider{
					Session: sess,
				},
			})
	} else {
		creds = credentials.NewStaticCredentials(AccessKeyID, SecretAccessKey, "")
	}
	return creds
}

func getAwsSession() *session.Session {
	if Session == nil {
		var err error
		Session, err = session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		})
		common.HandleError(err)
	}
	return Session
}

func getAwsSecretsManagerClient() *secretsmanager.SecretsManager {
	if SecretsManagerClient == nil {
		SecretsManagerClient = secretsmanager.New(
			getAwsSession(),
			aws.NewConfig().WithRegion(Region).WithCredentials(
				getAwsCredentials(getAwsSession())))
	}
	return SecretsManagerClient
}

func GetAwsSecret(secretName string, secretKey string) string {
	common.Logger.Debugf("Retrieving %s", secretName)
	if val, ok := SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
		secretStr, ok := val.(map[string]interface{})[secretKey].(string)
		if !ok {
			common.HandleError(
				fmt.Errorf(
					"Could not convert [%s][%s] to string",
					secretName,
					secretKey))
		}
		return secretStr
	}
	//Create a Secrets Manager client
	svc := getAwsSecretsManagerClient()
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	common.Logger.Debugf("Retrieving [%s] from AWS Secrets Manager", secretName)
	result, err := svc.GetSecretValue(input)

	if err != nil {
		var errorMessage string
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", secretName, secretKey, secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
				break

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", secretName, secretKey, secretsmanager.ErrCodeInternalServiceError, aerr.Error())
				break

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", secretName, secretKey, secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
				break

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", secretName, secretKey, secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
				break

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v %v", secretName, secretKey, secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
				break

			default:
				errorMessage = fmt.Sprintf("secret{%s[%s]}: %v", secretName, secretKey, aerr.Error())
				break
			}
		} else {
			errorMessage = fmt.Sprintln(err.Error())
		}
		common.HandleError(errors.New(errorMessage))
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	}

	common.Logger.Debugf("Secret %s:%s", secretName, secretString)
	var response map[string]interface{}
	err = json.Unmarshal([]byte(secretString), &response)
	common.HandleError(err)

	secretStr, ok := response[secretKey].(string)
	if !ok {
		common.HandleError(
			fmt.Errorf(
				"Could not convert secrets manager response[%s][%s] to string",
				secretName,
				secretKey))
	}
	_ = SecretCache.Add(secretName, response, cache.DefaultExpiration)

	return secretStr
}
