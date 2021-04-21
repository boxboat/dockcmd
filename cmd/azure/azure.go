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
	"github.com/patrickmn/go-cache"
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
	SecretCache    *cache.Cache
	UseAzCliLogin  = false
	CacheTTL       = 5 * time.Minute
)

func init(){
	SecretCache = cache.New(CacheTTL, CacheTTL)
}

func getKeyVaultClient() (keyvault.BaseClient, error) {

	if !initialized {
		if UseAzCliLogin {
			KeyVaultClient = keyvault.New()
			authorizer, err := kvauth.NewAuthorizerFromCLI()
			if err != nil {
				return KeyVaultClient, err
			}
			KeyVaultClient.Authorizer = authorizer
			initialized = true
		} else {
			// ensure required environment variables are set
			_ = os.Setenv("AZURE_TENANT_ID", TenantID)
			_ = os.Setenv("AZURE_CLIENT_ID", ClientID)
			_ = os.Setenv("AZURE_CLIENT_SECRET", ClientSecret)

			KeyVaultClient = keyvault.New()
			authorizer, err := kvauth.NewAuthorizerFromEnvironment()
			if err != nil {
				return KeyVaultClient, err
			}
			KeyVaultClient.Authorizer = authorizer
			initialized = true
		}
	}
	return KeyVaultClient, nil
}

func GetAzureJSONSecret(secretName string, secretKey string) (string, error) {
	common.Logger.Debugf("Retrieving [%s][%s]", secretName, secretKey)

	if val, ok := SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
			return secretStr, nil
		}
	}

	client, err := getKeyVaultClient()
	if err != nil {
		return "", err
	}

	secretResp, err := client.GetSecret(
		context.Background(),
		"https://"+KeyVaultName+".vault.azure.net",
		secretName, "")
	if err != nil {
		return "", err
	}
	secretJSON := *secretResp.Value
	var response map[string]interface{}
	if err := json.Unmarshal([]byte(secretJSON), &response); err != nil {
		return "", err
	}

	secretStr, ok := response[secretKey].(string)
	if !ok {
		return "", fmt.Errorf("could not convert Key Vault response[%s][%s] to string",
			secretName,
			secretKey)
	}

	_ = SecretCache.Add(secretName, response, cache.DefaultExpiration)

	return secretStr, nil
}

func GetAzureTextSecret(secretName string) (string, error) {
	common.Logger.Debugf("GetAzureTextSecret [%s]", secretName)

	if val, ok := SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s]", secretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	client, err := getKeyVaultClient()
	if err != nil {
		return "", err
	}

	secretResp, err := client.GetSecret(
		context.Background(),
		"https://"+KeyVaultName+".vault.azure.net",
		secretName, "")
	if err != nil {
		return "", err
	}
	secretStr := *secretResp.Value

	_ = SecretCache.Add(secretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil

}
