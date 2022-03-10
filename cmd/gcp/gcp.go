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

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/option"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

const latestVersion = "latest"

type SecretsManager struct {
	ctx                  context.Context
	SecretsManagerClient *secretmanager.Client
	SecretCache          *cache.Cache
	Project              string
}

type SecretsManagerOpt interface {
	configureSecretsManager(opts *secretsManagerOpts) error
}

type secretsManagerOpts struct {
	credentialsFile          string
	credentialsJson          []byte
	useAppDefaultCredentials bool
	cacheTTL                 time.Duration
}

type secretManagerOptFn func(opts *secretsManagerOpts) error

func (opt secretManagerOptFn) configureSecretsManager(opts *secretsManagerOpts) error {
	return opt(opts)
}

func CredentialsFile(filename string) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.credentialsFile = filename
		return nil
	})
}

func CredentialsJson(jsonBytes []byte) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.credentialsJson = jsonBytes
		return nil
	})
}

func UseApplicationDefaultCredentials() SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.useAppDefaultCredentials = true
		return nil
	})
}

func CacheTTL(ttl time.Duration) SecretsManagerOpt {
	return secretManagerOptFn(func(opts *secretsManagerOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func NewSecretsManagerClient(ctx context.Context, gcpProject string, opts ...SecretsManagerOpt) (*SecretsManager, error) {
	var o secretsManagerOpts
	for _, opt := range opts {
		if opt != nil {
			if err := opt.configureSecretsManager(&o); err != nil {
				return nil, err
			}
		}
	}

	client := &SecretsManager{
		ctx:                  ctx,
		SecretsManagerClient: nil,
		SecretCache:          cache.New(o.cacheTTL, o.cacheTTL),
		Project:              gcpProject,
	}
	if o.useAppDefaultCredentials {
		common.Logger.Debugf("using ADC for client authentication")
		c, err := secretmanager.NewClient(ctx)
		if err != nil {
			return nil, err
		}
		client.SecretsManagerClient = c
	} else if o.credentialsFile != "" {
		common.Logger.Debugf("using credentials file[%s] for client authentication", o.credentialsFile)
		c, err := secretmanager.NewClient(ctx, option.WithCredentialsFile(o.credentialsFile))
		if err != nil {
			return nil, err
		}
		client.SecretsManagerClient = c
	} else if len(o.credentialsJson) > 0 {
		common.Logger.Debugf("using credentials json for client authentication")
		c, err := secretmanager.NewClient(ctx, option.WithCredentialsJSON(o.credentialsJson))
		if err != nil {
			return nil, err
		}
		client.SecretsManagerClient = c
	} else {
		return nil, fmt.Errorf("unknown GCP authentication method provided, please use ADC or JSON authentication methods")
	}

	return client, nil

}

func (c *SecretsManager) GetJSONSecret(secretName, secretKey string) (string, error) {
	version := latestVersion
	s := strings.Split(secretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		secretName = s[0]
	}

	projectSecretName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", c.Project, secretName, version)

	common.Logger.Debugf("Retrieving [%s][%s]", projectSecretName, secretKey)

	if val, ok := c.SecretCache.Get(projectSecretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", projectSecretName, secretKey)
		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
			return secretStr, nil
		}
	}

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: projectSecretName,
	}

	// Call the API.
	result, err := c.SecretsManagerClient.AccessSecretVersion(c.ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %v", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(result.Payload.Data, &response); err != nil {
		return "", err
	}

	secretStr, ok := response[secretKey].(string)
	if !ok {
		return "", fmt.Errorf("could not convert GCP response[%s][%s] to string",
			projectSecretName,
			secretKey)
	}

	_ = c.SecretCache.Add(projectSecretName, response, cache.DefaultExpiration)

	return secretStr, nil
}

func (c *SecretsManager) GetTextSecret(secretName string) (string, error) {
	version := latestVersion
	s := strings.Split(secretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		secretName = s[0]
	}

	projectSecretName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", c.Project, secretName, version)

	common.Logger.Debugf("Retrieving [%s]", projectSecretName)

	if val, ok := c.SecretCache.Get(projectSecretName); ok {
		common.Logger.Debugf("Using cached [%s]", projectSecretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: projectSecretName,
	}

	// Call the API.
	result, err := c.SecretsManagerClient.AccessSecretVersion(context.Background(), req)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %v", err)
	}

	secretStr := string(result.Payload.Data)

	_ = c.SecretCache.Add(projectSecretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil
}
