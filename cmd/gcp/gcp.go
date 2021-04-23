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

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/option"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var (
	Project                          string
	CredentialsFile                  string
	UseApplicationDefaultCredentials bool
	Client                           *secretmanager.Client
	SecretCache                      *cache.Cache
	CacheTTL                         = 5 * time.Minute
)

func init() {
	SecretCache = cache.New(CacheTTL, CacheTTL)
}

func getClient() (*secretmanager.Client, error) {
	if Client == nil {
		ctx := context.Background()
		var err error
		if UseApplicationDefaultCredentials {
			Client, err = secretmanager.NewClient(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			Client, err = secretmanager.NewClient(ctx, option.WithCredentialsFile(CredentialsFile))
			if err != nil {
				return nil, err
			}
		}
	}
	return Client, nil
}

func GetJSONSecret(secretName string, secretKey string) (string, error) {

	projectSecretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", Project, secretName)

	common.Logger.Debugf("Retrieving [%s][%s]", projectSecretName, secretKey)

	if val, ok := SecretCache.Get(projectSecretName); ok {
		common.Logger.Debugf("Using cached [%s][%s]", projectSecretName, secretKey)
		if secretStr, ok := val.(map[string]interface{})[secretKey].(string); ok {
			return secretStr, nil
		}
	}

	client, err := getClient()
	if err != nil {
		return "", err
	}

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: projectSecretName,
	}

	// Call the API.
	result, err := client.AccessSecretVersion(context.Background(), req)
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

	_ = SecretCache.Add(projectSecretName, response, cache.DefaultExpiration)

	return secretStr, nil

}

func GetTextSecret(secretName string) (string, error) {

	projectSecretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", Project, secretName)

	common.Logger.Debugf("Retrieving [%s]", projectSecretName)

	if val, ok := SecretCache.Get(projectSecretName); ok {
		common.Logger.Debugf("Using cached [%s]", projectSecretName)
		if secretStr, ok := val.(string); ok {
			return secretStr, nil
		}
	}

	client, err := getClient()
	if err != nil {
		return "", err
	}

	// Build the request.
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: projectSecretName,
	}

	// Call the API.
	result, err := client.AccessSecretVersion(context.Background(), req)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %v", err)
	}

	secretStr := string(result.Payload.Data)

	_ = SecretCache.Add(projectSecretName, secretStr, cache.DefaultExpiration)

	return secretStr, nil

}
