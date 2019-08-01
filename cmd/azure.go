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
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/2019-03-01/keyvault/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"text/template"
)

var (
	initialized         = false
	azureTenantID       string
	azureClientID       string
	azureClientSecret   string
	azureKeyVaultName   string
	azureKeyVaultClient keyvault.BaseClient
	azureSecretCache    map[string]map[string]interface{}
)

func getKeyVaultClient() keyvault.BaseClient {
	if !initialized {
		authorizer, err := kvauth.NewAuthorizerFromEnvironment()
		HandleError(err)
		azureKeyVaultClient = keyvault.New()
		azureKeyVaultClient.Authorizer = authorizer
		initialized = true
	}
	return azureKeyVaultClient
}

func getAzureJSONSecret(secretName string, secretKey string) string {
	Logger.Debugf("Retrieving [%s][%s]", secretName, secretKey)

	if val, ok := azureSecretCache[secretName]; ok {
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

	secretResp, err := getKeyVaultClient().GetSecret(
		context.Background(),
		"https://"+azureKeyVaultName+".vault.azure.net",
		secretName, "")
	HandleError(err)
	secretJSON := *secretResp.Value
	var response map[string]interface{}
	json.Unmarshal([]byte(secretJSON), &response)

	secretStr, ok := response[secretKey].(string)
	if !ok {
		HandleError(
			fmt.Errorf(
				"Could not convert Key Vault response[%s][%s] to string",
				secretName,
				secretKey))
	}
	if azureSecretCache[secretName] == nil {
		azureSecretCache[secretName] = make(map[string]interface{})
	}
	azureSecretCache[secretName] = response
	return secretStr
}

func getAzureTextSecret(secretName string) string {
	Logger.Debugf("getAzureTextSecret [%s]", secretName)

	secretResp, err := getKeyVaultClient().GetSecret(
		context.Background(),
		"https://"+azureKeyVaultName+".vault.azure.net",
		secretName, "")
	HandleError(err)
	secretStr := *secretResp.Value

	return secretStr

}

// azureRegionCmdPersistentPreRunE checks required persistent tokens for azureCmd
func azureCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	Logger.Debugln("azureCmdPersistentPreRunE")

	azureTenantID = viper.GetString("tenant")
	azureClientID = viper.GetString("client-id")
	azureClientSecret = viper.GetString("client-secret")

	// ensure required environment variables are set
	os.Setenv("AZURE_TENANT_ID", azureTenantID)
	os.Setenv("AZURE_CLIENT_ID", azureClientID)
	os.Setenv("AZURE_CLIENT_SECRET", azureClientSecret)

	return nil
}

// azureCmd represents the azure command
var azureCmd = &cobra.Command{
	Use:               "azure",
	Short:             "Azure Commands",
	Long:              `Commands designed to facilitate interactions with Azure`,
	PersistentPreRunE: azureCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var azureGetSecretsCmd = &cobra.Command{
	Use:   "get-secrets",
	Short: "Retrieve secrets from Azure Key Vault",
	Long: `Provide a go template file to request keys from Azure Key Vault

Supports sprig functions

Pass in values using --set <key=value> parameters

Example input and output:
<secret-keys.yaml>
---
foo:
  keyA: {{ (azureJson "foo" "a") | squote }}
  keyB: {{ (azureJson "foo" "b") | squote }}
  charlie:
    keyC: {{ (azureJson "foo-charlie" "c") | squote }}
keyD: {{ (azureText "root" ) | quote }}


<secret-values.yaml>
---
foo:
  keyA: '<value-of-secret/foo-a-frome-azure-key-vault>'
  keyB: '<value-of-secret/foo-b-frome-azure-key-vault>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-frome-azure-key-vault>'
keyD: "<value-of-secret/root-from-azure-key-vault>"
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		Logger.Debug("get-secrets called")

		// create custom function map
		funcMap := template.FuncMap{
			"azureJson": getAzureJSONSecret,
			"azureText": getAzureTextSecret,
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
	rootCmd.AddCommand(azureCmd)

	// azure command and common persistent flags
	azureCmd.AddCommand(azureGetSecretsCmd)
	azureCmd.PersistentFlags().StringVarP(
		&azureTenantID,
		"tenant",
		"",
		"",
		"Azure tenant ID can alternatively be set using ${AZURE_TENANT_ID}")
	viper.BindEnv("tenant", "AZURE_TENANT_ID")

	azureCmd.PersistentFlags().StringVarP(
		&azureClientID,
		"client-id",
		"",
		"",
		"Azure Client ID can alternatively be set using ${AZURE_CLIENT_ID}")

	azureCmd.PersistentFlags().StringVarP(
		&azureClientSecret,
		"client-secret",
		"",
		"",
		"Azure Client Secret Key can alternatively be set using ${AZURE_CLIENT_SECRET}")

	viper.BindEnv("tenant", "AZURE_TENANT_ID")
	viper.BindEnv("client-id", "AZURE_CLIENT_ID")
	viper.BindEnv("client-secret", "AZURE_CLIENT_SECRET")
	viper.BindPFlags(azureCmd.PersistentFlags())

	azureGetSecretsCmd.PersistentFlags().StringVarP(
		&azureKeyVaultName,
		"key-vault",
		"",
		"",
		"Azure Key Vault Name")
	AddValuesArraySupport(azureGetSecretsCmd, &commonValues)
	AddUseAlternateDelimitersSupport(azureGetSecretsCmd, &commonUseAlternateDelims)
	AddEditInPlaceSupport(azureGetSecretsCmd, &commonEditInPlace)

	AddInputFileSupport(azureGetSecretsCmd, &commonGetSecretsInputFile)
	AddOutputFileSupport(azureGetSecretsCmd, &commonGetSecretsOutputFile)

	azureSecretCache = make(map[string]map[string]interface{})
}
