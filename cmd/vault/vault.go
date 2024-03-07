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

package vault

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/hashicorp/vault/api"
	"github.com/patrickmn/go-cache"
)

const (
	TokenAuth = "Token"
	RoleAuth  = "vaultRole"
)

type GetSecretAPI interface {
	ReadWithData(path string, data map[string][]string) (*api.Secret, error)
	Read(path string) (*api.Secret, error)
}

type SecretsClient struct {
	common.SecretClient
	secretCache *cache.Cache
	vaultClient *api.Client
	api         GetSecretAPI
}

type SecretsClientOpt interface {
	configureSecretsClient(opts *secretsClientOpts) error
}

type secretsClientOpts struct {
	cacheTTL time.Duration
	address  string
	authType string
	token    string
	roleID   string
	secretID string
	api      *GetSecretAPI
}

type secretClientOptFn func(opts *secretsClientOpts) error

func (opt secretClientOptFn) configureSecretsClient(opts *secretsClientOpts) error {
	return opt(opts)
}

func CacheTTL(ttl time.Duration) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func Address(address string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.address = address
		return nil
	})
}

func Token(token string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.token = token
		return nil
	})
}

func AuthType(authType string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.authType = authType
		return nil
	})
}

func RoleAndSecretID(roleID, secretID string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.roleID = roleID
		opts.secretID = secretID
		return nil
	})
}

func WithMockClient(api GetSecretAPI) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.api = &api
		return nil
	})
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
	client := &SecretsClient{
		secretCache: cache.New(o.cacheTTL, o.cacheTTL),
	}

	if o.api == nil {
		config := api.DefaultConfig()
		config.Address = o.address
		vaultClient, err := api.NewClient(config)
		if err != nil {
			return nil, err
		}

		if o.authType == RoleAuth {
			common.Logger.Debugf(
				"getting vault-token using vault-role-id {%s} and vault-secret-id {%s}",
				o.roleID,
				o.secretID)
			appRoleLogin := map[string]interface{}{
				"role_id":   o.roleID,
				"secret_id": o.secretID,
			}
			resp, err := vaultClient.Logical().Write("auth/approle/login", appRoleLogin)
			if err != nil {
				return nil, err
			}
			if resp.Auth == nil {
				return nil, errors.New("failed to obtain VAULT_TOKEN using vault-role-id and vault-secret-id")
			}
			common.Logger.Debugf("using vault-token {%s}", resp.Auth.ClientToken)
			vaultClient.SetToken(resp.Auth.ClientToken)
		} else {
			common.Logger.Debugf("using specified vault-token {%s}", o.token)
			vaultClient.SetToken(o.token)
		}
		client.vaultClient = vaultClient
		client.api = vaultClient.Logical()
	} else {
		client.api = *o.api
	}
	return client, nil
}

func (c *SecretsClient) GetJSONSecret(path string, key string) (string, error) {

	secretPath := path
	version := ""
	s := strings.Split(secretPath, "?version=")
	if len(s) > 1 {
		secretPath = s[0]
		version = s[1]
	}

	if val, ok := c.secretCache.Get(path); ok {
		common.Logger.Debugf("using cached [%s][%s]", path, key)
		secretStr, ok := val.(map[string]interface{})[key].(string)
		if ok {
			return secretStr, nil
		}
	}

	if version == "latest" {
		version = ""
	}

	common.Logger.Debugf("retrieving secret[%s] key[%s] from Vault", secretPath, key)

	secretStr := ""
	ok := false

	mountPath, v2, err := isKVv2(secretPath, c.vaultClient)
	if err != nil {
		return "", err
	}
	if v2 {
		queryPath := addPrefixToKVPath(secretPath, mountPath, "data", false)
		// make empty query for ReadWithData
		query := url.Values{}
		if version != "" {
			query.Add("version", version)
		}

		secret, err := c.api.ReadWithData(queryPath, query)
		if err != nil {
			return "", err
		}
		if secret != nil {
			secretStr, ok = secret.Data["data"].(map[string]interface{})[key].(string)
		}
		if !ok {
			return "", fmt.Errorf("could not convert vault response [%s][%s] to string",
				secretPath,
				key)
		}
		_ = c.secretCache.Add(path, secret.Data["data"].(map[string]interface{}), cache.DefaultExpiration)
	} else {
		secret, err := c.api.Read(secretPath)
		if err != nil {
			return "", err
		}
		if secret != nil {
			secretStr, ok = secret.Data[key].(string)
		}
		if !ok {
			return "", fmt.Errorf("could not convert vault response [%s][%s] to string",
				secretPath,
				key)
		}
		_ = c.secretCache.Add(path, secret.Data, cache.DefaultExpiration)
	}

	return secretStr, nil
}
