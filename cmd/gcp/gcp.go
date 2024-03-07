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

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/googleapis/gax-go/v2"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/option"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

const latestVersion = "latest"

type SecretsManagerGetSecretAPI interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

type SecretsClient struct {
	ctx                  context.Context
	secretsManagerClient *secretmanager.Client
	secretCache          *cache.Cache
	project              string
	api                  SecretsManagerGetSecretAPI
}

type SecretsClientOpt interface {
	configureSecretsClient(opts *secretsClientOpts) error
}

type secretsClientOpts struct {
	ctx                      context.Context
	credentialsFile          string
	credentialsJson          []byte
	useAppDefaultCredentials bool
	project                  string
	cacheTTL                 time.Duration
	api                      *SecretsManagerGetSecretAPI
}

type secretClientOptFn func(opts *secretsClientOpts) error

func (opt secretClientOptFn) configureSecretsClient(opts *secretsClientOpts) error {
	return opt(opts)
}

func CredentialsFile(filename string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.credentialsFile = filename
		return nil
	})
}

func CredentialsJson(jsonBytes []byte) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.credentialsJson = jsonBytes
		return nil
	})
}

func Project(project string) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.project = project
		return nil
	})
}

func UseApplicationDefaultCredentials() SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.useAppDefaultCredentials = true
		return nil
	})
}

func CacheTTL(ttl time.Duration) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.cacheTTL = ttl
		return nil
	})
}

func WithContext(ctx context.Context) SecretsClientOpt {
	return secretClientOptFn(func(opts *secretsClientOpts) error {
		opts.ctx = ctx
		return nil
	})
}

func WithMockClient(api SecretsManagerGetSecretAPI) SecretsClientOpt {
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
		ctx:         o.ctx,
		secretCache: cache.New(o.cacheTTL, o.cacheTTL),
		project:     o.project,
	}

	if o.api == nil {
		if o.useAppDefaultCredentials {
			common.Logger.Debugf("using ADC for client authentication")
			c, err := secretmanager.NewClient(o.ctx)
			if err != nil {
				return nil, err
			}
			client.secretsManagerClient = c
		} else if o.credentialsFile != "" {
			common.Logger.Debugf("using credentials file[%s] for client authentication", o.credentialsFile)
			c, err := secretmanager.NewClient(o.ctx, option.WithCredentialsFile(o.credentialsFile))
			if err != nil {
				return nil, err
			}
			client.secretsManagerClient = c
		} else if len(o.credentialsJson) > 0 {
			common.Logger.Debugf("using credentials json for client authentication")
			c, err := secretmanager.NewClient(o.ctx, option.WithCredentialsJSON(o.credentialsJson))
			if err != nil {
				return nil, err
			}
			client.secretsManagerClient = c
		} else {
			return nil, fmt.Errorf("unknown GCP authentication method provided, please use ADC or JSON authentication methods")
		}
		client.api = client.secretsManagerClient
	} else {
		client.api = *o.api
	}

	return client, nil

}

func (c *SecretsClient) GetJSONSecret(secretName, secretKey string) (string, error) {
	version := latestVersion
	s := strings.Split(secretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		secretName = s[0]
	}

	projectSecretName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", c.project, secretName, version)

	if val, ok := c.secretCache.Get(projectSecretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", projectSecretName, secretKey)
		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
			return secretStr, nil
		}
	}

	common.Logger.Debugf("retrieving [%s][%s] from GCP Secrets Manager", projectSecretName, secretKey)

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: projectSecretName,
	}

	// Call the API.
	result, err := c.api.AccessSecretVersion(c.ctx, req)
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

	_ = c.secretCache.Add(projectSecretName, response, cache.DefaultExpiration)

	return secretStr, nil
}

func (c *SecretsClient) GetTextSecret(secretName string) (string, error) {
	version := latestVersion
	s := strings.Split(secretName, "?version=")
	if len(s) > 1 {
		version = s[1]
		secretName = s[0]
	}

	projectSecretName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", c.project, secretName, version)

	if val, ok := c.secretCache.Get(projectSecretName); ok {
		common.Logger.Debugf("Using cached [%s]", projectSecretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	common.Logger.Debugf("retrieving [%s] from GCP Secrets Manager", projectSecretName)

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: projectSecretName,
	}

	// Call the API.
	result, err := c.api.AccessSecretVersion(c.ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %v", err)
	}

	secretStr := string(result.Payload.Data)

	_ = c.secretCache.Add(projectSecretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil
}
