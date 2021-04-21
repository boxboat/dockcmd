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

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/2019-03-01/keyvault/keyvault"
	kvauth "github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/boxboat/dockcmd/cmd/common"
	"os"
	"time"
)

var (
	initialized    = false
	TenantID       string
	ClientID       string
	ClientSecret   string
	KeyVaultName   string
	KeyVaultClient keyvault.BaseClient
	SecretCache    map[string]common.SecretCacheItem
	UseAzCliLogin  = false
	CacheTTL       = 5.0
)

func getKeyVaultClient() keyvault.BaseClient {
	if !initialized {
		if UseAzCliLogin {
			authorizer, err := kvauth.NewAuthorizerFromCLI()
			common.HandleError(err)
			KeyVaultClient = keyvault.New()
			KeyVaultClient.Authorizer = authorizer
			initialized = true
		} else {
			// ensure required environment variables are set
			os.Setenv("AZURE_TENANT_ID", TenantID)
			os.Setenv("AZURE_CLIENT_ID", ClientID)
			os.Setenv("AZURE_CLIENT_SECRET", ClientSecret)

			authorizer, err := kvauth.NewAuthorizerFromEnvironment()
			common.HandleError(err)
			KeyVaultClient = keyvault.New()
			KeyVaultClient.Authorizer = authorizer
			initialized = true
		}
	}
	return KeyVaultClient
}

func GetAzureJSONSecret(secretName string, secretKey string) string {
	common.Logger.Debugf("Retrieving [%s][%s]", secretName, secretKey)

	if SecretCache == nil {
		SecretCache = make(map[string]common.SecretCacheItem)
	}

	if val, ok := SecretCache[secretName]; ok && time.Since(val.CachedAt).Minutes() < CacheTTL {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
		secretStr, ok := val.Secret[secretKey].(string)
		if !ok {
			common.HandleError(
				fmt.Errorf(
					"could not convert [%s][%s] to string",
					secretName,
					secretKey))
		}
		return secretStr
	}

	secretResp, err := getKeyVaultClient().GetSecret(
		context.Background(),
		"https://"+KeyVaultName+".vault.azure.net",
		secretName, "")
	common.HandleError(err)
	secretJSON := *secretResp.Value
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(secretJSON), &response); err != nil {
		common.HandleError(err)
	}

	secretStr, ok := response[secretKey].(string)
	if !ok {
		common.HandleError(
			fmt.Errorf(
				"Could not convert Key Vault response[%s][%s] to string",
				secretName,
				secretKey))
	}

	SecretCache[secretName] = common.SecretCacheItem{
		Secret:   response,
		CachedAt: time.Now(),
	}
	return secretStr
}

func GetAzureTextSecret(secretName string) string {
	common.Logger.Debugf("GetAzureTextSecret [%s]", secretName)

	if SecretCache == nil {
		SecretCache = make(map[string]common.SecretCacheItem)
	}

	if val, ok := SecretCache[secretName]; ok && time.Since(val.CachedAt).Minutes() < CacheTTL {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretName)
		secretStr, ok := val.Secret[secretName].(string)
		if !ok {
			common.HandleError(
				fmt.Errorf(
					"could not convert [%s][%s] to string",
					secretName,
					secretName))
		}
		return secretStr
	}

	secretResp, err := getKeyVaultClient().GetSecret(
		context.Background(),
		"https://"+KeyVaultName+".vault.azure.net",
		secretName, "")
	common.HandleError(err)
	secretStr := *secretResp.Value

	var response = make(map[string]interface{})
	// only one secret is stored with azureText so just cache at secretName in map
	response[secretName] = secretStr

	SecretCache[secretName] = common.SecretCacheItem{
		Secret:   response,
		CachedAt: time.Now(),
	}

	return secretStr

}
