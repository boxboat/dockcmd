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

type SecretsManager struct {
	common.SecretClient
	SecretCache *cache.Cache
	VaultClient *api.Client
}

type SecretsManagerOpt interface {
	configureSecretsManager(opts *secretsManagerOpts) error
}

type secretsManagerOpts struct {
	cacheTTL time.Duration
	address  string
	authType string
	token    string
	roleID   string
	secretID string
}

type secretManagerOptFn func(opts *secretsManagerOpts) error

func (opt secretManagerOptFn) configureSecretsManager(opts *secretsManagerOpts) error {
	return opt(opts)
}

func CacheTTL(ttl time.Duration) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func Address(address string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.address = address
		return nil
	})
}

func Token(token string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.token = token
		return nil
	})
}

func AuthType(authType string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.authType = authType
		return nil
	})
}

func RoleAndSecretID(roleID, secretID string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.roleID = roleID
		opts.secretID = secretID
		return nil
	})
}

func NewVaultClient(opts ...SecretsManagerOpt) (*SecretsManager, error) {
	var o secretsManagerOpts
	for _, opt := range opts {
		if opt != nil {
			if err := opt.configureSecretsManager(&o); err != nil {
				return nil, err
			}
		}
	}
	client := &SecretsManager{
		SecretCache: cache.New(o.cacheTTL, o.cacheTTL),
	}

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
		common.Logger.Debugf("Using specified vault-token {%s}", o.token)
		vaultClient.SetToken(o.token)
	}
	client.VaultClient = vaultClient
	return client, nil
}

func (c *SecretsManager) GetJSONSecret(path string, key string) (string, error) {

	secretPath := path
	version := ""
	s := strings.Split(secretPath, "?version=")
	if len(s) > 1 {
		secretPath = s[0]
		version = s[1]
	}

	if val, ok := c.SecretCache.Get(path); ok {
		common.Logger.Debugf("Using cached [%s][%s]", path, key)
		secretStr, ok := val.(map[string]interface{})[key].(string)
		if ok {
			return secretStr, nil
		}
	}

	if version == "latest" {
		version = ""
	}

	common.Logger.Debugf("Reading secret[%s] key[%s]", secretPath, key)

	secretStr := ""
	ok := false

	mountPath, v2, err := isKVv2(secretPath, c.VaultClient)
	if err != nil {
		return "", err
	}
	if v2 {
		queryPath := addPrefixToVKVPath(secretPath, mountPath, "data")
		// make empty query for ReadWithData
		query := url.Values{}
		if version != "" {
			query.Add("version", version)
		}

		secret, err := c.VaultClient.Logical().ReadWithData(queryPath, query)
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
		_ = c.SecretCache.Add(path, secret.Data["data"].(map[string]interface{}), cache.DefaultExpiration)
	} else {
		secret, err := c.VaultClient.Logical().Read(secretPath)
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
		_ = c.SecretCache.Add(path, secret.Data, cache.DefaultExpiration)
	}

	return secretStr, nil
}
