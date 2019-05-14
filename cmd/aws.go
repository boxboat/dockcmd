// Copyright © 2019 BoxBoat engineering@boxboat.com
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

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	awsRegion               string
	awsProfile              string
	awsAccessKeyID          string
	awsSecretAccessKey      string
	awsUseChainCredentials  bool
	awsSession              *session.Session
	awsSecretsManagerClient *secretsmanager.SecretsManager
	awsSecretCache          map[string]map[string]interface{}
)

func getAwsCredentials(sess *session.Session) *credentials.Credentials {
	var creds *credentials.Credentials
	if awsUseChainCredentials {
		creds = credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{
					Profile: awsProfile,
				},
				&ec2rolecreds.EC2RoleProvider{
					Client: ec2metadata.New(sess),
				},
			})
	} else {
		creds = credentials.NewStaticCredentials(awsAccessKeyID, awsSecretAccessKey, "")
	}
	return creds
}

func getAwsSession() *session.Session {
	if awsSession == nil {
		var err error
		awsSession, err = session.NewSession()
		HandleError(err)
	}
	return awsSession
}

func getAwsSecretsManagerClient() *secretsmanager.SecretsManager {
	if awsSecretsManagerClient == nil {
		awsSecretsManagerClient = secretsmanager.New(
			getAwsSession(),
			aws.NewConfig().WithRegion(awsRegion).WithCredentials(
				getAwsCredentials(getAwsSession())))
	}
	return awsSecretsManagerClient
}

func getAwsSecret(secretName string, secretKey string) string {

	Logger.Debugf("Retrieving %s", secretName)
	if val, ok := awsSecretCache[secretName]; ok {
		Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
		secretStr, ok := val[secretKey].(string)
		if !ok {
			HandleError(
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

	Logger.Debugf("Retrieving [%s] from AWS Secrets Manager", secretName)
	result, err := svc.GetSecretValue(input)

	if err != nil {
		var errorMessage string
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				errorMessage = fmt.Sprintln(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
				break

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				errorMessage = fmt.Sprintln(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
				break

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				errorMessage = fmt.Sprintln(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
				break

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				errorMessage = fmt.Sprintln(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
				break

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				errorMessage = fmt.Sprintln(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
				break

			default:
				errorMessage = fmt.Sprintln(aerr.Error())
				break
			}
		} else {
			errorMessage = fmt.Sprintln(err.Error())
		}
		HandleError(errors.New(errorMessage))
	}

	// Decrypts secret using the associated KMS CMK.
	// Depending on whether the secret is a string or binary, one of these fields will be populated.
	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	}

	Logger.Debugf("Secret %s:%s", secretName, secretString)
	var response map[string]interface{}
	json.Unmarshal([]byte(secretString), &response)

	if awsSecretCache[secretName] == nil {
		awsSecretCache[secretName] = make(map[string]interface{})
	}
	secretStr, ok := response[secretKey].(string)
	if !ok {
		HandleError(
			fmt.Errorf(
				"Could not convert secrets manager response[%s][%s] to string",
				secretName,
				secretKey))
	}
	awsSecretCache[secretName] = response
	return secretStr

}

// awsRegionCmdPersistentPreRunE checks required persistent tokens for awsCmd
func awsCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	Logger.Debugln("awsCmdPersistentPreRunE")
	awsRegion = viper.GetString("region")
	Logger.Debugf("Using AWS Region: {%s}", awsRegion)
	if awsRegion == "" {
		return errors.New("${AWS_DEFAULT_REGION} must be set or passed in via --region")
	}
	awsAccessKeyID = viper.GetString("access-key-id")
	awsSecretAccessKey = viper.GetString("secret-access-key")

	if awsAccessKeyID == "" && awsSecretAccessKey == "" {
		awsUseChainCredentials = true
	}

	return nil
}

// awsCmd represents the aws command
var awsCmd = &cobra.Command{
	Use:               "aws",
	Short:             "AWS Commands",
	Long:              `Commands designed to facilitate interactions with AWS`,
	PersistentPreRunE: awsCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var awsGetSecretsCmd = &cobra.Command{
	Use:   "get-secrets",
	Short: "Retrieve secrets from AWS Secrets Manager",
	Long: `Provide a go template file to request keys from AWS Secrets Manager

Supports sprig functions

Pass in values using --set <key=value> parameters

Example input and output:
<secret-keys.yaml>
---
foo:
  keyA: {{ (aws "foo" "a") | squote }}
  keyB: {{ (aws "foo" "b") | squote }}
  charlie:
    keyC: {{ (aws "foo-charlie" "c") | squote }}
keyD: {{ (aws "root" "d") | quote }}


<secret-values.yaml>
---
foo:
  keyA: '<value-of-secret/foo-a-from-aws-secrets-manager>'
  keyB: '<value-of-secret/foo-b-from-aws-secrets-manager>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-aws-secrets-manager>'
keyD: "<value-of-secret/root-d-from-aws-secrets-manager>"
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		Logger.Debug("get-secrets called")

		// create custom function map
		funcMap := template.FuncMap{
			"aws": getAwsSecret,
		}

		var files []string
		if len(args) > 0 {
			files = args
		}

		CommonGetSecrets(files, funcMap)

	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		Logger.Debug("PreRunE")
		return ReadValuesMap()
	},
}

func init() {
	rootCmd.AddCommand(awsCmd)

	// aws command and common persistent flags
	awsCmd.AddCommand(awsGetSecretsCmd)
	awsCmd.PersistentFlags().StringVarP(
		&awsRegion,
		"region",
		"",
		"",
		"AWS Region can alternatively be set using ${AWS_DEFAULT_REGION}")
	viper.BindEnv("region", "AWS_DEFAULT_REGION")

	awsCmd.PersistentFlags().StringVarP(
		&awsAccessKeyID,
		"access-key-id",
		"",
		"",
		"AWS Access Key ID can alternatively be set using ${AWS_ACCESS_KEY_ID}")

	awsCmd.PersistentFlags().StringVarP(
		&awsSecretAccessKey,
		"secret-access-key",
		"",
		"",
		"AWS Secret Access Key can alternatively be set using ${AWS_SECRET_ACCESS_KEY}")

	awsCmd.PersistentFlags().StringVarP(
		&awsProfile,
		"profile",
		"",
		"",
		"AWS Profile can alternatively be set using ${AWS_PROFILE}")

	viper.BindEnv("access-key-id", "AWS_ACCESS_KEY_ID")
	viper.BindEnv("secret-access-key", "AWS_SECRET_ACCESS_KEY")
	viper.BindEnv("profile", "AWS_PROFILE")
	viper.BindPFlags(awsCmd.PersistentFlags())

	AddValuesArraySupport(awsGetSecretsCmd, &commonValues)
	AddUseAlternateDelimitersSupport(awsGetSecretsCmd, &commonUseAlternateDelims)
	AddEditInPlaceSupport(awsGetSecretsCmd, &commonEditInPlace)

	AddInputFileSupport(awsGetSecretsCmd, &commonGetSecretsInputFile)
	AddOutputFileSupport(awsGetSecretsCmd, &commonGetSecretsOutputFile)

	awsSecretCache = make(map[string]map[string]interface{})
}
