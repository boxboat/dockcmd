// Copyright © 2019 BoxBoat engineering@boxboat.com
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

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/boxboat/dockcmd/cmd/elastic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"strconv"
	"time"
)



var esDeleteIndicesCmd = &cobra.Command{
	Use:   "delete-indices",
	Short: "Delete matching indices from Elasticsearch",
	Long:  `Provide an index name to delete from Elasticsearch`,
	Run: func(cmd *cobra.Command, args []string) {
		common.Logger.Debug("delete-indices called")

		var search []string
		if len(args) == 1 {
			search = args
		} else {
			common.ExitIfError(errors.New("Provide delete string"))
		}
		common.Logger.Debugf("Deleting [%s] from elasticsearch", search)

		indices := elastic.FindIndices(search)

		for k, v := range indices {
			settings := v.(map[string]interface{})["settings"].(map[string]interface{})
			index := settings["index"].(map[string]interface{})
			creationDateMs, err := strconv.ParseInt(index["creation_date"].(string), 10, 64)
			common.ExitIfError(err)

			common.Logger.Debugf("key[%s] creationDate[%s]\n", k, index["creation_date"])

			age := time.Now().Sub(time.Unix(0, creationDateMs*int64(time.Millisecond)))
			common.Logger.Debugf("Age[%s]\n", age)
			if age.Seconds() > float64(elastic.RetentionDays*24.0*60.0*60.0) {
				if elastic.DryRun == false {
					fmt.Printf("Deleting index [%s]\n", k)
					elastic.DeleteIndex([]string{k})
				} else {
					fmt.Printf("[%s] would be deleted\n", k)
				}
			}
		}

	},
}

var esGetIndicesCmd = &cobra.Command{
	Use:   "get-indices",
	Short: "Retrieve list of matching indices from Elasticsearch",
	Long:  `Provide an index name to query Elasticsearch`,
	Run: func(cmd *cobra.Command, args []string) {
		common.Logger.Debug("get-indices called")

		var search []string
		if len(args) == 1 {
			search = args
		} else {
			common.ExitIfError(errors.New("Provide search string"))
		}
		common.Logger.Debugf("Searching elasticsearch for [%s]", search)

		indices := elastic.FindIndices(search)
		var out []byte
		var err error
		if elastic.PrettyPrint {
			out, err = json.MarshalIndent(indices, "", "  ")
		} else {
			out, err = json.Marshal(indices)
		}
		common.ExitIfError(err)
		fmt.Println(string(out))
	},
}

// esCmdPersistentPreRunE checks required persistent tokens for esCmd
func esCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	common.Logger.Debugln("esCmdPersistentPreRunE")
	common.Logger.Debugf("Using ES URL: {%s}", elastic.URL)
	elastic.URL = viper.GetString("url")
	elastic.Username = viper.GetString("username")
	elastic.Password = viper.GetString("password")
	elastic.APIKey = viper.GetString("api-key")

	if elastic.URL == "" {
		return errors.New("${ES_URL} must be set or passed in via --url")
	}
	return nil
}

// esCmd represents the es command
var esCmd = &cobra.Command{
	Use:               "es",
	Short:             "Elasticsearch Commands",
	Long:              `Commands designed to facilitate interactions with Elasticsearch`,
	PersistentPreRunE: esCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(esCmd)
	esCmd.AddCommand(esGetIndicesCmd)
	esCmd.AddCommand(esDeleteIndicesCmd)

	esCmd.PersistentFlags().StringVarP(
		&elastic.URL,
		"url",
		"",
		"",
		"Elasticsearch URL can alternatively be set using ${ES_URL}")
	viper.BindEnv("url", "ES_URL")

	esCmd.PersistentFlags().StringVarP(
		&elastic.Version,
		"api-version",
		"",
		"",
		"Elasticsearch major version, currently supports v6 and v7 e.g. --api-version v6")

	esCmd.PersistentFlags().StringVarP(
		&elastic.Username,
		"username",
		"",
		"",
		"Elasticsearch username for Basic Auth can alternatively be set using ${ES_USERNAME}")
	viper.BindEnv("username", "ES_USERNAME")

	esCmd.PersistentFlags().StringVarP(
		&elastic.Password,
		"password",
		"",
		"",
		"Elasticsearch password for Basic Auth can alternatively be set using ${ES_PASSWORD}")
	viper.BindEnv("password", "ES_PASSWORD")

	esCmd.PersistentFlags().StringVarP(
		&elastic.APIKey,
		"api-key",
		"",
		"",
		"Elasticsearch Base64 encoded authorization api token - will override Basic Auth can alternatively be set using ${ES_API_KEY}")
	viper.BindEnv("api-key", "ES_API_KEY")

	viper.BindPFlags(esCmd.PersistentFlags())

	esGetIndicesCmd.Flags().BoolVarP(
		&elastic.PrettyPrint,
		"pretty-print",
		"",
		false,
		"Pretty print json output")

	esDeleteIndicesCmd.Flags().IntVarP(
		&elastic.RetentionDays,
		"retention-days",
		"",
		0,
		"Days to retain indexes matching delete pattern")
	esDeleteIndicesCmd.Flags().BoolVarP(
		&elastic.DryRun,
		"dry-run",
		"",
		false,
		"Enable dry run to see what indices would be deleted")

}
