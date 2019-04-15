// Copyright © 2018 BoxBoat engineering@boxboat.com
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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	VaultConcurrentRequests = 10
	VaultTokenAuth          = "vaultToken"
	VaultRoleAuth           = "vaultRole"
)

var (
	vaultAuth        string
	vaultAddr        string
	vaultClient      *api.Client
	vaultToken       string
	vaultRoleId      string
	vaultSecretId    string
	secretKeysFile   string
	secretValuesFile string
	values           []string
	valuesMap        map[string]interface{}
)

func initVaultClient() {
	if vaultClient == nil {
		config := api.DefaultConfig()
		config.Address = vaultAddr
		var err error
		vaultClient, err = api.NewClient(config)
		HandleError(err)

		if vaultAuth == VaultRoleAuth {
			Logger.Debugf(
				"Getting vault-token using vault-role-id {%s} and vault-secret-id {%s}",
				vaultRoleId,
				vaultSecretId)
			appRoleLogin := map[string]interface{}{
				"role_id":   vaultRoleId,
				"secret_id": vaultSecretId,
			}
			resp, err := vaultClient.Logical().Write("auth/approle/login", appRoleLogin)
			HandleError(err)
			if resp.Auth == nil {
				HandleError(
					errors.New(
						"Failed to obtain VAULT_TOKEN using vault-role-id and vault-secret-id"))
			}
			vaultToken = resp.Auth.ClientToken
		}
		Logger.Debugf("Using vault-token {%s}", vaultToken)
		vaultClient.SetToken(vaultToken)
	}
}

func getVaultSecret(path string, key string) string {
	if vaultClient != nil {
		Logger.Debugf("Reading secret[%s] key[%s]", path, key)
		secret, err := vaultClient.Logical().Read(path)
		HandleError(err)

		return secret.Data[key].(string)
	}
	return ""
}

// vaultCmdPersistentPreRunE checks required persistent tokens for vaultCmd
func vaultCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	Logger.Debugln("vaultCmdPersistentPreRunE")
	vaultAddr = viper.GetString("vault-addr")
	if vaultAddr == "" {
		return errors.New("${VAULT_ADDR} must be set or passed in via --vault-addr")
	}
	vaultToken = viper.GetString("vault-token")
	vaultRoleId = viper.GetString("vault-role-id")
	vaultSecretId = viper.GetString("vault-secret-id")

	if vaultRoleId != "" && vaultSecretId != "" {
		vaultAuth = VaultRoleAuth
	} else if vaultToken == "" {
		return errors.New(
			`${VAULT_TOKEN} must be set or passed in via --vault-token
 					or ${VAULT_ROLE_ID} and ${VAULT_SECRET_ID} must be set or passed in
					via --vault-role-id and --vault-secret-id respectively`)
	} else {
		vaultAuth = VaultTokenAuth
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

var getSecretsCmd = &cobra.Command{
	Use:   "get-secrets",
	Short: "Retrieve secrets from Vault",
	Long: `Provide a go template file to request keys from Vault

Supports sprig functiona pass in values using --set <key=value> parameters

Example input and output:
<secret-keys.yaml>
---
foo:
  keyA: {{ vault( "secret/foo" "a") | squote }}
  keyB: {{ vault( "secret/foo" "b") | squote }}
  bar:
    keyC: {{ vault( "secret/foo/bar" "c") | squote }}
keyD: {{ vault( "secret/root" "d") | quote }}


<secret-values.yaml>
---
vault_secret_test_a:
foo:
  keyA: '<value-of-secret/foo-a-from-vault>'
  keyB: '<value-of-secret/foo-b-from-vault>'
  bar:
    keyC: '<value-of-secret/foo/bar-c-from-vault>'
keyD: "<value-of-secret/root-d-from-vault>"
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		Logger.Debug("get-secrets called")
		Logger.Debugf("Vault URL: '%s'", vaultAddr)

		funcMap := template.FuncMap{
			"vault": getVaultSecret,
		}

		data, err := ReadFileOrStdin(secretKeysFile)
		HandleError(err)

		initVaultClient()
		Logger.Debugf("Input:\n%s", string(data))
		tpl := template.Must(template.New("secret-input").Funcs(sprig.TxtFuncMap()).Funcs(funcMap).Option("missingkey=error").Parse(string(data)))

		var tplOut bytes.Buffer

		Logger.Debugf("valuesMap:\n%s", valuesMap)
		err = tpl.Execute(&tplOut, valuesMap)
		HandleError(err)

		err = WriteFileOrStdout(tplOut.Bytes(), secretValuesFile)

	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		Logger.Debug("PreRunE")
		Logger.Debugf("values {%s}", values)
		valuesMap = make(map[string]interface{})
		for _, s := range values {
			kv := strings.Split(s, "=")
			if len(kv) == 2 {
				valuesMap[kv[0]] = kv[1]
			} else {
				return fmt.Errorf("unable to parse %s", s)
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(vaultCmd)

	// vault command and common persistent flags
	vaultCmd.AddCommand(getSecretsCmd)
	vaultCmd.PersistentFlags().StringVarP(
		&vaultAddr,
		"vault-addr",
		"",
		"",
		"Vault ADDR")
	viper.BindEnv("vault-addr", "VAULT_ADDR")
	vaultCmd.PersistentFlags().StringVarP(
		&vaultToken,
		"vault-token",
		"",
		"",
		"Vault Token can alternatively be set using ${VAULT_TOKEN}")

	vaultCmd.PersistentFlags().StringVarP(
		&vaultRoleId,
		"vault-role-id",
		"",
		"",
		"Vault Role Id if not using vault-token can alternatively be set using ${VAULT_ROLE_ID} (also requires vault-secret-id")

	vaultCmd.PersistentFlags().StringVarP(
		&vaultSecretId,
		"vault-secret-id",
		"",
		"",
		"Vault Secret Id if not using vault-token can alternatively be set using ${VAULT_SECRET_ID} (also requires vault-role-id")

	viper.BindEnv("vault-token", "VAULT_TOKEN")
	viper.BindEnv("vault-role-id", "VAULT_ROLE_ID")
	viper.BindEnv("vault-secret-id", "VAULT_SECRET_ID")
	viper.BindPFlags(vaultCmd.PersistentFlags())

	// get-secrets command and flags
	getSecretsCmd.Flags().StringArrayVar(
		&values,
		"set",
		[]string{},
		"set key=value (can specify multiple times to set multiple values)")

	AddInputFileSupport(getSecretsCmd, &secretKeysFile)
	AddOutputFileSupport(getSecretsCmd, &secretValuesFile)

}
