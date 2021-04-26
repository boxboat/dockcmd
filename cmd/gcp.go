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

package cmd

import (
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/boxboat/dockcmd/cmd/gcp"
	"github.com/spf13/cobra"
	"text/template"
)

// gcpCmdPersistentPreRunE checks required persistent tokens for gcpCmd
func gcpCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	common.Logger.Debugln("gcpCmdPersistentPreRunE")

	if gcp.CredentialsFile != "" {
		gcp.UseApplicationDefaultCredentials = false
	} else {
		gcp.UseApplicationDefaultCredentials = true
	}

	return nil
}

// gcpCmd represents the gcp command
var gcpCmd = &cobra.Command{
	Use:               "gcp",
	Short:             "Google Cloud Commands",
	Long:              `Commands designed to facilitate interactions with GCP`,
	PersistentPreRunE: gcpCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var gcpGetSecretsCmd = &cobra.Command{
	Use:   "get-secrets",
	Short: "Retrieve secrets from Google Secrets Manager",
	Long: `Provide a go template file to request keys from Google Secrets Manager

Supports sprig functions

Pass in values using --set <key=value> parameters

Example input and output:
<secret-keys.yaml>
---
foo:
  keyA: {{ (gcpJson "foo" "a") | squote }}
  keyB: {{ (gcpJson "foo" "b") | squote }}
  charlie:
    keyC: {{ (gcpJson "foo-charlie" "c") | squote }}
keyD: {{ (gcpText "root" ) | quote }}


<secret-values.yaml>
---
foo:
  keyA: '<value-of-secret/foo-a-from-gcp-secrets-manager>'
  keyB: '<value-of-secret/foo-b-from-gcp-secrets-manager>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-gcp-secrets-manager>'
keyD: "<value-of-secret/root-from-gcp-secrets-manager>"
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		common.Logger.Debug("get-secrets called")

		// create custom function map
		funcMap := template.FuncMap{
			"gcpJson": gcp.GetJSONSecret,
			"gcpText": gcp.GetTextSecret,
		}

		var files []string
		if len(args) > 0 {
			files = args
		}

		err := common.GetSecrets(files, funcMap)
		common.ExitIfError(err)

	},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		common.Logger.Debug("PreRunE")
		common.ExitIfError(common.ReadValuesFiles())
		common.ExitIfError(common.ReadSetValues())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(gcpCmd)

	// gcp command and common persistent flags
	gcpCmd.AddCommand(gcpGetSecretsCmd)
	gcpCmd.PersistentFlags().StringVarP(
		&gcp.CredentialsFile,
		"credentials-file",
		"",
		"",
		"GCP Credentials JSON File")

	gcpCmd.PersistentFlags().StringVarP(
		&gcp.Project,
		"project",
		"",
		"",
		"GCP Project")

	common.AddSetValuesSupport(gcpGetSecretsCmd, &common.Values)
	common.AddValuesFileSupport(gcpGetSecretsCmd, &common.ValuesFiles)
	common.AddUseAlternateDelimitersSupport(gcpGetSecretsCmd, &common.UseAlternateDelims)
	common.AddEditInPlaceSupport(gcpGetSecretsCmd, &common.EditInPlace)

	common.AddInputFileSupport(gcpGetSecretsCmd, &common.GetSecretsInputFile)
	common.AddOutputFileSupport(gcpGetSecretsCmd, &common.GetSecretsOutputFile)

}
