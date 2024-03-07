// Copyright © 2024 BoxBoat
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

type KeyVaultGetSecretAPI interface {
	GetSecret(ctx context.Context, vaultBaseURL string, secretName string, secretVersion string) (result keyvault.SecretBundle, err error)
}

type SecretsClient struct {
	common.SecretClient
	keyVaultName string
	keyVault     keyvault.BaseClient
	SecretCache  *cache.Cache
	ctx          context.Context
	api          KeyVaultGetSecretAPI
}

type SecretsClientOpt interface {
	configureSecretsClient(opts *secretsClientOpts) error
}

type secretsClientOpts struct {
	ctx           context.Context
	clientID      string
	clientSecret  string
	tenantID      string
	keyVaultName  string
	useAzCliLogin bool
	cacheTTL      time.Duration
	api           *KeyVaultGetSecretAPI
}

type secretsClientOptFn func(opts *secretsClientOpts) error

func CacheTTL(ttl time.Duration) SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func KeyVaultName(keyVaultName string) SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.keyVaultName = keyVaultName
		return nil
	})
}

func ClientIDAndSecret(clientID, clientSecret string) SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.clientID = clientID
		opts.clientSecret = clientSecret
		return nil
	})
}

func TenantID(tenantID string) SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.tenantID = tenantID
		return nil
	})
}

func UseAzCliLogin() SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.useAzCliLogin = true
		return nil
	})
}

func WithContext(ctx context.Context) SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.ctx = ctx
		return nil
	})
}

func WithMockClient(api KeyVaultGetSecretAPI) SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.api = &api
		return nil
	})
}

func (opt secretsClientOptFn) configureSecretsClient(opts *secretsClientOpts) error {
	return opt(opts)
}

func NewSecretsClient(opts ...SecretsClientOpt) (*SecretsClient, error) {
	var o secretsClientOpts
	for _, opt := range opts {
		if opt != nil {
			if err := opt.configureSecretsClient(&o); err != nil {
				return nil, err
			}
		}
	}

	if o.ctx == nil {
		o.ctx = context.Background()
	}

	client := &SecretsClient{
		SecretCache:  cache.New(o.cacheTTL, o.cacheTTL),
		keyVaultName: o.keyVaultName,
		ctx:          o.ctx,
	}
	if o.api == nil {
		if o.useAzCliLogin {
			client.keyVault = keyvault.New()
			authorizer, err := auth.NewAuthorizerFromCLIWithResource(keyVaultResource)
			if err != nil {
				return nil, err
			}
			client.keyVault.Authorizer = authorizer
		} else {
			client.keyVault = keyvault.New()
			clientConfig := auth.NewClientCredentialsConfig(o.clientID, o.clientSecret, o.tenantID)
			clientConfig.Resource = keyVaultResource
			authorizer, err := clientConfig.Authorizer()
			if err != nil {
				return nil, err
			}
			client.keyVault.Authorizer = authorizer
		}
		client.api = client.keyVault
	} else {
		client.api = *o.api
	}
	return client, nil
}

func (c *SecretsClient) GetJSONSecret(secretName string, secretKey string) (string, error) {
	adjustedSecretName := secretName
	version := ""
	s := strings.Split(adjustedSecretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		adjustedSecretName = s[0]
	}

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

	common.Logger.Debugf("retrieving [%s][%s] from Azure Key Vault", adjustedSecretName, secretKey)

	secretResp, err := c.api.GetSecret(
		c.ctx,
		"https://"+c.keyVaultName+".vault.azure.net",
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

func (c *SecretsClient) GetTextSecret(secretName string) (string, error) {
	adjustedSecretName := secretName
	version := ""
	s := strings.Split(adjustedSecretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		adjustedSecretName = s[0]
	}

	// allow "latest" to specify the latest version
	if version == "latest" {
		version = ""
	}

	if val, ok := c.SecretCache.Get(secretName); ok {
		common.Logger.Debugf("using cached [%s]", secretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	common.Logger.Debugf("retrieving [%s] from Azure Key Vault", adjustedSecretName)

	secretResp, err := c.api.GetSecret(
		c.ctx,
		"https://"+c.keyVaultName+"."+azurePublicKeyVault,
		adjustedSecretName,
		version)
	if err != nil {
		return "", err
	}
	secretStr := *secretResp.Value

	_ = c.SecretCache.Add(secretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil
}
