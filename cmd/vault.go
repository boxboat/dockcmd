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
	"errors"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/boxboat/dockcmd/cmd/vault"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// vaultCmdPersistentPreRunE checks required persistent tokens for vaultCmd
func vaultCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	common.Logger.Debugln("vaultCmdPersistentPreRunE")
	vault.Addr = viper.GetString("vault-addr")
	if vault.Addr == "" {
		return errors.New("${VAULT_ADDR} must be set or passed in via --vault-addr")
	}
	vault.Token = viper.GetString("vault-token")
	vault.RoleID = viper.GetString("vault-role-id")
	vault.SecretID = viper.GetString("vault-secret-id")

	if vault.RoleID != "" && vault.SecretID != "" {
		vault.Auth = vault.RoleAuth
	} else if vault.Token == "" {
		return errors.New(
			`${VAULT_TOKEN} must be set or passed in via --vault-token
 					or ${VAULT_ROLE_ID} and ${VAULT_SECRET_ID} must be set or passed in
					via --vault-role-id and --vault-secret-id respectively`)
	} else {
		vault.Auth = vault.TokenAuth
	}
	return nil
}

// vaultCmd represents the vault command
var vaultCmd = &cobra.Command{
	Use:               "vault",
	Short:             "Vault Commands",
	Long:              `Commands designed to facilitate interactions with Hashicorp Vault`,
	PersistentPreRunE: vaultCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var vaultGetSecretsCmd = &cobra.Command{
	Use:   "get-secrets",
	Short: "Retrieve secrets from Vault",
	Long: `Provide a go template file to request keys from Vault

Supports sprig functions
Pass in values using --set <key=value> parameters

Example input and output:
<secret-keys.yaml>
---
foo:
  keyA: {{ (vault "secret/foo" "a") | squote }}
  keyB: {{ (vault "secret/foo" "b") | squote }}
  charlie:
    keyC: {{ (vault (printf "%s/%s/%s" "secret/foo" .Deployment "charlie") "c") | squote }}
keyD: {{ (vault "secret/root" "d") | quote }}


<secret-values.yaml>
---
foo:
  keyA: '<value-of-secret/foo-a-from-vault>'
  keyB: '<value-of-secret/foo-b-from-vault>'
  charlie:
    keyC: '<value-of-secret/foo/{{.Deployment}}/charlie-c-from-vault>'
keyD: "<value-of-secret/root-d-from-vault>"
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		common.Logger.Debug("get-secrets called")
		common.Logger.Debugf("Vault URL: '%s'", vault.Addr)

		// create custom function map
		funcMap := template.FuncMap{
			"vault": vault.GetVaultSecret,
		}

		var files []string
		if len(args) > 0 {
			files = args
		}

		err := common.GetSecrets(files, funcMap)
		common.LogErrorAndExit(err)

	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		common.Logger.Debug("PreRunE")
		common.LogErrorAndExit(common.ReadValuesFiles())
		common.LogErrorAndExit(common.ReadSetValues())
		return nil
	},
	Args: cobra.MinimumNArgs(0),
}

func init() {
	rootCmd.AddCommand(vaultCmd)

	// vault command and common persistent flags
	vaultCmd.AddCommand(vaultGetSecretsCmd)
	vaultCmd.PersistentFlags().StringVarP(
		&vault.Addr,
		"vault-addr",
		"",
		"",
		"Vault ADDR")
	viper.BindEnv("vault-addr", "VAULT_ADDR")
	vaultCmd.PersistentFlags().StringVarP(
		&vault.Token,
		"vault-token",
		"",
		"",
		"Vault Token can alternatively be set using ${VAULT_TOKEN}")

	vaultCmd.PersistentFlags().StringVarP(
		&vault.RoleID,
		"vault-role-id",
		"",
		"",
		"Vault Role Id if not using vault-token can alternatively be set using ${VAULT_ROLE_ID} (also requires vault-secret-id)")

	vaultCmd.PersistentFlags().StringVarP(
		&vault.SecretID,
		"vault-secret-id",
		"",
		"",
		"Vault Secret Id if not using vault-token can alternatively be set using ${VAULT_SECRET_ID} (also requires vault-role-id)")

	_ = viper.BindEnv("vault-token", "VAULT_TOKEN")
	_ = viper.BindEnv("vault-role-id", "VAULT_ROLE_ID")
	_ = viper.BindEnv("vault-secret-id", "VAULT_SECRET_ID")
	_ = viper.BindPFlags(vaultCmd.PersistentFlags())

	common.AddSetValuesSupport(vaultGetSecretsCmd, &common.Values)
	common.AddValuesFileSupport(vaultGetSecretsCmd, &common.ValuesFiles)
	common.AddUseAlternateDelimitersSupport(vaultGetSecretsCmd, &common.UseAlternateDelims)
	common.AddEditInPlaceSupport(vaultGetSecretsCmd, &common.EditInPlace)

	common.AddInputFileSupport(vaultGetSecretsCmd, &common.GetSecretsInputFile)
	common.AddOutputFileSupport(vaultGetSecretsCmd, &common.GetSecretsOutputFile)

}
