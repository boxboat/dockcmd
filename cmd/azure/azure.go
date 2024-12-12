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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
)

const (
	azurePublicKeyVault          = "vault.azure.net"
	keyVaultResourceFormatString = "https://%s." + azurePublicKeyVault + "/"
)

type timeoutWrapper struct {
	cred    *azidentity.ManagedIdentityCredential
	timeout time.Duration
}

// GetToken implements the azcore.TokenCredential interface
func (w *timeoutWrapper) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	var tk azcore.AccessToken
	var err error
	if w.timeout > 0 {
		c, cancel := context.WithTimeout(ctx, w.timeout)
		defer cancel()
		tk, err = w.cred.GetToken(c, opts)
		if ce := c.Err(); errors.Is(ce, context.DeadlineExceeded) {
			// The Context reached its deadline, probably because no managed identity is available.
			// A credential unavailable error signals the chain to try its next credential, if any.
			err = azidentity.NewCredentialUnavailableError("managed identity timed out")
		} else {
			// some managed identity implementation is available, so don't apply the timeout to future calls
			w.timeout = 0
		}
	} else {
		tk, err = w.cred.GetToken(ctx, opts)
	}
	return tk, err
}

type KeyVaultGetSecretAPI interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

type SecretsClient struct {
	common.SecretClient
	keyVaultName string
	keyVault     *azsecrets.Client
	SecretCache  *cache.Cache
	ctx          context.Context
	api          KeyVaultGetSecretAPI
}

type SecretsClientOpt interface {
	configureSecretsClient(opts *secretsClientOpts) error
}

type secretsClientOpts struct {
	ctx                 context.Context
	clientID            string
	clientSecret        string
	tenantID            string
	keyVaultName        string
	useChainCredentials bool
	cacheTTL            time.Duration
	api                 *KeyVaultGetSecretAPI
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

func UseChainCredentials() SecretsClientOpt {
	return secretsClientOptFn(func(opts *secretsClientOpts) error {
		opts.useChainCredentials = true
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
		if o.useChainCredentials {
			common.Logger.Debugf("using chain credentials")

			managed, err := azidentity.NewManagedIdentityCredential(nil)
			if err != nil {
				return nil, err
			}

			azCli, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{AdditionallyAllowedTenants: []string{o.tenantID}})
			if err != nil {
				return nil, err
			}

			chain, err := azidentity.NewChainedTokenCredential([]azcore.TokenCredential{&timeoutWrapper{managed, time.Second}, azCli}, nil)
			if err != nil {
				return nil, err
			}

			azSecretsClient, err := azsecrets.NewClient(fmt.Sprintf(keyVaultResourceFormatString, client.keyVaultName), chain, nil)
			client.keyVault = azSecretsClient

		} else {

			cred, err := azidentity.NewClientSecretCredential(o.tenantID, o.clientID, o.clientSecret, nil)
			if err != nil {
				return nil, err
			}
			azSecretsClient, err := azsecrets.NewClient(fmt.Sprintf(keyVaultResourceFormatString, client.keyVaultName), cred, nil)
			client.keyVault = azSecretsClient

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
		adjustedSecretName,
		version,
		nil)
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
		adjustedSecretName,
		version,
		nil)
	if err != nil {
		return "", err
	}
	secretStr := *secretResp.Value

	_ = c.SecretCache.Add(secretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil
}
