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

package cmd

import (
	"text/template"

	"github.com/boxboat/dockcmd/cmd/azure"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	client        *azure.KeyVaultClient
	clientID      string
	clientSecret  string
	tenantID      string
	useAzCliLogin bool
	keyVaultName  string
)

// azureRegionCmdPersistentPreRunE checks required persistent tokens for azureCmd
func azureCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	common.Logger.Debugln("azureCmdPersistentPreRunE")

	tenantID = viper.GetString("tenant")
	clientID = viper.GetString("client-id")
	clientSecret = viper.GetString("client-secret")

	if (tenantID == "" && clientID == "" && clientSecret == "") || useAzCliLogin {
		// set to true in case where no service principal credentials provided
		useAzCliLogin = true
	}

	return nil
}

// azureCmd represents the azure command
var azureCmd = &cobra.Command{
	Use:               "azure",
	Short:             "Azure Commands",
	Long:              `Commands designed to facilitate interactions with Azure`,
	PersistentPreRunE: azureCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
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
  keyA: '<value-of-secret/foo-a-from-azure-key-vault>'
  keyB: '<value-of-secret/foo-b-from-azure-key-vault>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-azure-key-vault>'
keyD: "<value-of-secret/root-from-azure-key-vault>"
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		common.Logger.Debug("get-secrets called")

		opts := []azure.KeyVaultOpt{azure.KeyVaultName(keyVaultName), azure.CacheTTL(common.DefaultCacheTTL)}

		if useAzCliLogin {
			opts = append(opts, azure.UseAzCliLogin())
		} else {
			opts = append(opts, azure.ClientIDAndSecret(clientID, clientSecret), azure.TenantID(tenantID))
		}
		var err error
		client, err = azure.NewKeyVaultClient(opts...)
		common.ExitIfError(err)

		// create custom function map
		funcMap := template.FuncMap{
			"azureJson": client.GetJSONSecret,
			"azureText": client.GetTextSecret,
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

func GetJSON(secretName, secretKey string) (string, error) {
	return client.GetJSONSecret(secretName, secretKey)
}

func GetText(secretName string) (string, error) {
	return client.GetTextSecret(secretName)
}

func init() {
	rootCmd.AddCommand(azureCmd)

	// azure command and common persistent flags
	azureCmd.AddCommand(azureGetSecretsCmd)
	azureCmd.PersistentFlags().BoolVarP(
		&useAzCliLogin, "az-cli-login",
		"",
		false,
		"access credentials provided by az login - default if tenant, client-id and client-secret are not set")
	azureCmd.PersistentFlags().StringVarP(
		&tenantID,
		"tenant",
		"",
		"",
		"Azure tenant ID can alternatively be set using ${AZURE_TENANT_ID}")
	_ = viper.BindEnv("tenant", "AZURE_TENANT_ID")

	azureCmd.PersistentFlags().StringVarP(
		&clientID,
		"client-id",
		"",
		"",
		"Azure Client ID can alternatively be set using ${AZURE_CLIENT_ID}")

	azureCmd.PersistentFlags().StringVarP(
		&clientSecret,
		"client-secret",
		"",
		"",
		"Azure Client Secret Key can alternatively be set using ${AZURE_CLIENT_SECRET}")

	_ = viper.BindEnv("tenant", "AZURE_TENANT_ID")
	_ = viper.BindEnv("client-id", "AZURE_CLIENT_ID")
	_ = viper.BindEnv("client-secret", "AZURE_CLIENT_SECRET")
	_ = viper.BindPFlags(azureCmd.PersistentFlags())

	azureGetSecretsCmd.PersistentFlags().StringVarP(
		&keyVaultName,
		"key-vault",
		"",
		"",
		"Azure Key Vault Name")
	common.AddSetValuesSupport(azureGetSecretsCmd, &common.Values)
	common.AddValuesFileSupport(azureGetSecretsCmd, &common.ValuesFiles)
	common.AddUseAlternateDelimitersSupport(azureGetSecretsCmd, &common.UseAlternateDelims)
	common.AddEditInPlaceSupport(azureGetSecretsCmd, &common.EditInPlace)

	common.AddInputFileSupport(azureGetSecretsCmd, &common.GetSecretsInputFile)
	common.AddOutputFileSupport(azureGetSecretsCmd, &common.GetSecretsOutputFile)

}
