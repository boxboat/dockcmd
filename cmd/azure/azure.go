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

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/2019-03-01/keyvault/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
)

const (
	azurePublicKeyVault = "vault.azure.net"
	keyVaultResource    = "https://" + azurePublicKeyVault
)

type KeyVaultClient struct {
	common.SecretClient
	KeyVaultName string
	KeyVault     keyvault.BaseClient
	SecretCache  *cache.Cache
}

type KeyVaultOpt interface {
	configureKeyVault(opts *keyVaultOpts) error
}

type keyVaultOpts struct {
	clientID      string
	clientSecret  string
	tenantID      string
	keyVaultName  string
	useAzCliLogin bool
	cacheTTL      time.Duration
}

type keyVaultOptFn func(opts *keyVaultOpts) error

func CacheTTL(ttl time.Duration) KeyVaultOpt {
	return keyVaultOptFn(func(opts *keyVaultOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func KeyVaultName(keyVaultName string) KeyVaultOpt {
	return keyVaultOptFn(func(opts *keyVaultOpts) error {
		opts.keyVaultName = keyVaultName
		return nil
	})
}

func ClientIDAndSecret(clientID, clientSecret string) KeyVaultOpt {
	return keyVaultOptFn(func(opts *keyVaultOpts) error {
		opts.clientID = clientID
		opts.clientSecret = clientSecret
		return nil
	})
}

func TenantID(tenantID string) KeyVaultOpt {
	return keyVaultOptFn(func(opts *keyVaultOpts) error {
		opts.tenantID = tenantID
		return nil
	})
}

func UseAzCliLogin() KeyVaultOpt {
	return keyVaultOptFn(func(opts *keyVaultOpts) error {
		opts.useAzCliLogin = true
		return nil
	})
}

func (opt keyVaultOptFn) configureKeyVault(opts *keyVaultOpts) error {
	return opt(opts)
}

func NewKeyVaultClient(opts ...KeyVaultOpt) (*KeyVaultClient, error) {
	var o keyVaultOpts
	for _, opt := range opts {
		if opt != nil {
			if err := opt.configureKeyVault(&o); err != nil {
				return nil, err
			}
		}
	}

	client := &KeyVaultClient{
		SecretCache:  cache.New(o.cacheTTL, o.cacheTTL),
		KeyVaultName: o.keyVaultName,
	}
	if o.useAzCliLogin {
		client.KeyVault = keyvault.New()
		authorizer, err := auth.NewAuthorizerFromCLIWithResource(keyVaultResource)
		if err != nil {
			return nil, err
		}
		client.KeyVault.Authorizer = authorizer
	} else {
		client.KeyVault = keyvault.New()
		clientConfig := auth.NewClientCredentialsConfig(o.clientID, o.clientSecret, o.tenantID)
		clientConfig.Resource = keyVaultResource
		authorizer, err := clientConfig.Authorizer()
		if err != nil {
			return nil, err
		}
		client.KeyVault.Authorizer = authorizer
	}
	return client, nil
}

func (c *KeyVaultClient) GetJSONSecret(secretName string, secretKey string) (string, error) {
	adjustedSecretName := secretName
	version := ""
	s := strings.Split(adjustedSecretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		adjustedSecretName = s[0]
	}

	common.Logger.Debugf("Retrieving [%s][%s]", adjustedSecretName, secretKey)

	// allow "latest" to specify the latest version
	if version == "latest" {
		version = ""
	}

	if val, ok := c.SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", secretName, secretKey)
		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
			return secretStr, nil
		}
	}

	secretResp, err := c.KeyVault.GetSecret(
		context.Background(),
		"https://"+c.KeyVaultName+".vault.azure.net",
		adjustedSecretName,
		version)
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
			adjustedSecretName,
			secretKey)
	}

	_ = c.SecretCache.Add(secretName, response, cache.DefaultExpiration)

	return secretStr, nil
}

func (c *KeyVaultClient) GetTextSecret(secretName string) (string, error) {
	adjustedSecretName := secretName
	version := ""
	s := strings.Split(adjustedSecretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		adjustedSecretName = s[0]
	}

	common.Logger.Debugf("GetAzureTextSecret [%s] ", adjustedSecretName)

	// allow "latest" to specify the latest version
	if version == "latest" {
		version = ""
	}

	if val, ok := c.SecretCache.Get(secretName); ok {
		common.Logger.Debugf("Using cached [%s]", secretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	secretResp, err := c.KeyVault.GetSecret(
		context.Background(),
		"https://"+c.KeyVaultName+"."+azurePublicKeyVault,
		adjustedSecretName,
		version)
	if err != nil {
		return "", err
	}
	secretStr := *secretResp.Value

	_ = c.SecretCache.Add(secretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil
}
