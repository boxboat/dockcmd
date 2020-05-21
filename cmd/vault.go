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
	"errors"
	"fmt"
	"path"
	"strings"
	"text/template"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	vaultTokenAuth = "vaultToken"
	vaultRoleAuth  = "vaultRole"
)

var (
	vaultAuth        string
	vaultAddr        string
	vaultClient      *api.Client
	vaultToken       string
	vaultRoleID      string
	vaultSecretID    string
	vaultSecretCache map[string]map[string]interface{}
)

func getVaultClient() *api.Client {
	if vaultClient == nil {
		config := api.DefaultConfig()
		config.Address = vaultAddr
		var err error
		vaultClient, err = api.NewClient(config)
		HandleError(err)

		if vaultAuth == vaultRoleAuth {
			Logger.Debugf(
				"Getting vault-token using vault-role-id {%s} and vault-secret-id {%s}",
				vaultRoleID,
				vaultSecretID)
			appRoleLogin := map[string]interface{}{
				"role_id":   vaultRoleID,
				"secret_id": vaultSecretID,
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
	return vaultClient
}

func getVaultSecret(path string, key string) string {
	if val, ok := vaultSecretCache[path]; ok {
		Logger.Debugf("Using cached [%s][%s]", path, key)
		secretStr, ok := val[key].(string)
		if !ok {
			HandleError(
				fmt.Errorf(
					"Could not convert [%s][%s] to string",
					path,
					key))
		}
		return secretStr
	}

	Logger.Debugf("Reading secret[%s] key[%s]", path, key)

	if vaultSecretCache[path] == nil {
		vaultSecretCache[path] = make(map[string]interface{})
	}



	secretStr := ""
	ok := false

	mountPath, v2, err := isKVv2(path, getVaultClient())
	HandleError(err)
	if v2 {
		queryPath := addPrefixToVKVPath(path, mountPath, "data")
		// make empty query for ReadWithData (always retrieve latest secret from v2 kv store)
		query := make(map[string][] string)
		secret, err := getVaultClient().Logical().ReadWithData(queryPath, query)
		HandleError(err)
		if secret != nil {
			secretStr, ok = secret.Data["data"].(map[string]interface{})[key].(string)
		}
		if !ok {
			HandleError(
				fmt.Errorf(
					"Could not convert vault response [%s][%s] to string",
					path,
					key))
		}
		vaultSecretCache[path] = secret.Data["data"].(map[string]interface{})
	} else {
		secret, err := getVaultClient().Logical().Read(path)
		HandleError(err)
		if secret != nil {
			secretStr, ok = secret.Data[key].(string)
		}
		if !ok {
			HandleError(
				fmt.Errorf(
					"Could not convert vault response [%s][%s] to string",
					path,
					key))
		}
		vaultSecretCache[path] = secret.Data
	}

	return secretStr
}


// copied from github.com/vault/command/kv_helpers
func addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path.Join(mountPath, apiPrefix, p)
	}
}

// copied from github.com/vault/command/kv_helpers
func isKVv2(path string, client *api.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

// copied from github.com/vault/command/kv_helpers
func kvPreflightVersionRequest(client *api.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && resp.StatusCode == 404 {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, errors.New("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
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
	vaultRoleID = viper.GetString("vault-role-id")
	vaultSecretID = viper.GetString("vault-secret-id")

	if vaultRoleID != "" && vaultSecretID != "" {
		vaultAuth = vaultRoleAuth
	} else if vaultToken == "" {
		return errors.New(
			`${VAULT_TOKEN} must be set or passed in via --vault-token
 					or ${VAULT_ROLE_ID} and ${VAULT_SECRET_ID} must be set or passed in
					via --vault-role-id and --vault-secret-id respectively`)
	} else {
		vaultAuth = vaultTokenAuth
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
		Logger.Debug("get-secrets called")
		Logger.Debugf("Vault URL: '%s'", vaultAddr)

		// create custom function map
		funcMap := template.FuncMap{
			"vault": getVaultSecret,
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
	Args: cobra.MinimumNArgs(0),
}

func init() {
	rootCmd.AddCommand(vaultCmd)

	// vault command and common persistent flags
	vaultCmd.AddCommand(vaultGetSecretsCmd)
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
		&vaultRoleID,
		"vault-role-id",
		"",
		"",
		"Vault Role Id if not using vault-token can alternatively be set using ${VAULT_ROLE_ID} (also requires vault-secret-id)")

	vaultCmd.PersistentFlags().StringVarP(
		&vaultSecretID,
		"vault-secret-id",
		"",
		"",
		"Vault Secret Id if not using vault-token can alternatively be set using ${VAULT_SECRET_ID} (also requires vault-role-id)")

	viper.BindEnv("vault-token", "VAULT_TOKEN")
	viper.BindEnv("vault-role-id", "VAULT_ROLE_ID")
	viper.BindEnv("vault-secret-id", "VAULT_SECRET_ID")
	viper.BindPFlags(vaultCmd.PersistentFlags())

	AddValuesArraySupport(vaultGetSecretsCmd, &commonValues)
	AddUseAlternateDelimitersSupport(vaultGetSecretsCmd, &commonUseAlternateDelims)
	AddEditInPlaceSupport(vaultGetSecretsCmd, &commonEditInPlace)

	AddInputFileSupport(vaultGetSecretsCmd, &commonGetSecretsInputFile)
	AddOutputFileSupport(vaultGetSecretsCmd, &commonGetSecretsOutputFile)

	vaultSecretCache = make(map[string]map[string]interface{})
}
