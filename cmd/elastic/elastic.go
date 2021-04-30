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

package elastic

import (
	"encoding/json"
	"fmt"
	"github.com/boxboat/dockcmd/cmd/common"
	elasticsearch6 "github.com/elastic/go-elasticsearch/v6"
	elasticsearch7 "github.com/elastic/go-elasticsearch/v7"
)

var (
	DryRun        bool
	PrettyPrint   bool
	URL           string
	Version       string
	APIKey        string
	Username      string
	Password      string
	RetentionDays int
	es6Client     *elasticsearch6.Client
	es7Client     *elasticsearch7.Client
)

func getEs6Client() *elasticsearch6.Client {
	common.Logger.Debugln("Using v6 client")
	if es6Client == nil {
		cfg := elasticsearch6.Config{
			Addresses: []string{
				URL,
			},
			Username: Username,
			Password: Password,
			APIKey:   APIKey,
		}
		common.Logger.Debugf("Username:[%s]", cfg.Username)
		common.Logger.Debugf("Password:[%s]", cfg.Password)
		common.Logger.Debugf("ApiKey:[%s]", cfg.APIKey)
		var err error
		es6Client, err = elasticsearch6.NewClient(cfg)
		common.ExitIfError(err)
	}
	return es6Client
}

func getEs7Client() *elasticsearch7.Client {
	common.Logger.Debugln("Using v7 client")
	if es7Client == nil {
		cfg := elasticsearch7.Config{
			Addresses: []string{
				URL,
			},
			Username: Username,
			Password: Password,
			APIKey:   APIKey,
		}
		common.Logger.Debugf("Username:[%s]", cfg.Username)
		common.Logger.Debugf("Password:[%s]", cfg.Password)
		common.Logger.Debugf("ApiKey:[%s]", cfg.APIKey)
		var err error
		es7Client, err = elasticsearch7.NewClient(cfg)
		common.ExitIfError(err)
	}
	return es7Client
}

func DeleteIndex(delete []string) {
	if Version == "v6" {
		esClient := getEs6Client()
		_, err := esClient.Indices.Delete(delete)
		common.LogIfError(err)
	} else if Version == "v7" {
		esClient := getEs7Client()
		_, err := esClient.Indices.Delete(delete)
		common.LogIfError(err)
	}
}

func FindIndices(search []string) map[string]interface{} {

	var indices map[string]interface{}

	if Version == "v6" {
		esClient := getEs6Client()
		response, err := esClient.Indices.Get(search)
		common.ExitIfError(err)
		if response.IsError() {
			common.ExitIfError(
				fmt.Errorf(
					"error: %s",
					response.String()))
		}
		err = json.NewDecoder(response.Body).Decode(&indices)
		common.ExitIfError(err)

	} else if Version == "v7" {
		esClient := getEs7Client()
		response, err := esClient.Indices.Get(search)
		common.ExitIfError(err)
		if response.IsError() {
			common.ExitIfError(
				fmt.Errorf(
					"error: %s",
					response.String()))
		}
		err = json.NewDecoder(response.Body).Decode(&indices)
		common.ExitIfError(err)
	}
	return indices
}