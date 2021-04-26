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

package vault

import (
	"errors"
	"fmt"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/hashicorp/vault/api"
	"github.com/patrickmn/go-cache"
	"net/url"
	"strings"
	"time"
)

const (
	TokenAuth = "Token"
	RoleAuth  = "vaultRole"
)

var (
	Auth        string
	Addr        string
	Client      *api.Client
	Token       string
	RoleID      string
	SecretID    string
	SecretCache *cache.Cache
	CacheTTL    = 5 * time.Minute
)

func init(){
	SecretCache = cache.New(CacheTTL, CacheTTL)
}

func getVaultClient() (*api.Client, error){
	if Client == nil {
		config := api.DefaultConfig()
		config.Address = Addr
		var err error
		Client, err = api.NewClient(config)
		if err != nil {
			return nil, err
		}

		if Auth == RoleAuth {
			common.Logger.Debugf(
				"getting vault-token using vault-role-id {%s} and vault-secret-id {%s}",
				RoleID,
				SecretID)
			appRoleLogin := map[string]interface{}{
				"role_id":   RoleID,
				"secret_id": SecretID,
			}
			resp, err := Client.Logical().Write("auth/approle/login", appRoleLogin)
			if err != nil {
				return nil, err
			}
			if resp.Auth == nil {
				return nil, errors.New("failed to obtain VAULT_TOKEN using vault-role-id and vault-secret-id")
			}
			Token = resp.Auth.ClientToken
		}
		common.Logger.Debugf("Using vault-token {%s}", Token)
		Client.SetToken(Token)
	}
	return Client, nil
}

func GetVaultSecret(path string, key string) (string, error) {

	secretPath := path
	version := ""
	s := strings.Split(secretPath, "?version=")
	if len(s) > 1 {
		secretPath = s[0]
		version = s[1]
	}

	if val, ok := SecretCache.Get(path); ok {
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

	client, err := getVaultClient()
	if err != nil {
		return "", err
	}

	mountPath, v2, err := isKVv2(secretPath, client)
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
		client, err := getVaultClient()
		if err != nil {
			return "", err
		}
		secret, err := client.Logical().ReadWithData(queryPath, query)
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
		_ = SecretCache.Add(path, secret.Data["data"].(map[string]interface{}), cache.DefaultExpiration)
	} else {
		secret, err := client.Logical().Read(secretPath)
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
		_ = SecretCache.Add(path, secret.Data, cache.DefaultExpiration)
	}

	return secretStr, nil
}
