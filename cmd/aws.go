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

package cmd

import (
	"errors"
	"text/template"

	"github.com/boxboat/dockcmd/cmd/aws"
	"github.com/boxboat/dockcmd/cmd/common"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	region              string
	profile             string
	accessKeyID         string
	secretAccessKey     string
	useChainCredentials bool
)

// awsRegionCmdPersistentPreRunE checks required persistent tokens for awsCmd
func awsCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	common.Logger.Debugln("awsCmdPersistentPreRunE")
	region = viper.GetString("region")
	common.Logger.Debugf("Using AWS Region: {%s}", region)
	if region == "" {
		return errors.New("${AWS_DEFAULT_REGION} must be set or passed in via --region")
	}
	accessKeyID = viper.GetString("access-key-id")
	secretAccessKey = viper.GetString("secret-access-key")

	if accessKeyID == "" && secretAccessKey == "" {
		useChainCredentials = true
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
		common.Logger.Debug("get-secrets called")

		opts := []aws.SecretsClientOpt{
			aws.CacheTTL(common.DefaultCacheTTL),
			aws.Profile(profile),
			aws.Region(region),
			aws.WithContext(awsCmd.Context()),
		}
		if useChainCredentials {
			opts = append(opts, aws.UseChainCredentials())
		} else {
			opts = append(opts, aws.AccessKeyIDAndSecretAccessKey(accessKeyID, secretAccessKey))
		}

		client, err := aws.NewSecretsClient(opts...)
		common.ExitIfError(err)

		// create custom function map
		funcMap := template.FuncMap{
			"aws":     client.GetJSONSecret,
			"awsJson": client.GetJSONSecret,
			"awsText": client.GetTextSecret,
		}

		var files []string
		if len(args) > 0 {
			files = args
		}

		err = common.GetSecrets(files, funcMap)
		common.ExitIfError(err)

	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		common.Logger.Debug("PreRunE")
		common.ExitIfError(common.ReadValuesFiles())
		common.ExitIfError(common.ReadSetValues())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(awsCmd)

	// aws command and common persistent flags
	awsCmd.AddCommand(awsGetSecretsCmd)
	awsCmd.PersistentFlags().StringVarP(
		&region,
		"region",
		"",
		"",
		"AWS Region can alternatively be set using ${AWS_DEFAULT_REGION}")
	_ = viper.BindEnv("region", "AWS_DEFAULT_REGION")

	awsCmd.PersistentFlags().StringVarP(
		&accessKeyID,
		"access-key-id",
		"",
		"",
		"AWS Access Key ID can alternatively be set using ${AWS_ACCESS_KEY_ID}")

	awsCmd.PersistentFlags().StringVarP(
		&secretAccessKey,
		"secret-access-key",
		"",
		"",
		"AWS Secret Access Key can alternatively be set using ${AWS_SECRET_ACCESS_KEY}")

	awsCmd.PersistentFlags().StringVarP(
		&profile,
		"profile",
		"",
		"",
		"AWS Profile can alternatively be set using ${AWS_PROFILE}")

	_ = viper.BindEnv("access-key-id", "AWS_ACCESS_KEY_ID")
	_ = viper.BindEnv("secret-access-key", "AWS_SECRET_ACCESS_KEY")
	_ = viper.BindEnv("profile", "AWS_PROFILE")
	_ = viper.BindPFlags(awsCmd.PersistentFlags())

	common.AddSetValuesSupport(awsGetSecretsCmd, &common.Values)
	common.AddValuesFileSupport(awsGetSecretsCmd, &common.ValuesFiles)
	common.AddUseAlternateDelimitersSupport(awsGetSecretsCmd, &common.UseAlternateDelims)
	common.AddEditInPlaceSupport(awsGetSecretsCmd, &common.EditInPlace)

	common.AddInputFileSupport(awsGetSecretsCmd, &common.GetSecretsInputFile)
	common.AddOutputFileSupport(awsGetSecretsCmd, &common.GetSecretsOutputFile)

}
