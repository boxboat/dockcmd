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
	"github.com/boxboat/dockcmd/cmd/common"
	"github.com/spf13/cobra"
	"text/template"
)

var gotplCmd = &cobra.Command{
	Use:   "gotpl",
	Short: "Parse a go template file",
	Long: `Provide a go template file to be parsed

Supports sprig functions, behavior is modeled on helm template parsing.

Pass in values using --set <key=value> parameters

Example input and output:
<keys.yaml>
---
foo:
  keyA: {{ .foo | squote }}
  keyB: {{ .bar | squote }}

<values.yaml>
---
foo:
  keyA: '<value-of-foo>'
  keyB: '<value-of-bar>'
...
`,
	Run: func(cmd *cobra.Command, args []string) {
		common.Logger.Debug("gotpl called")

		// create custom function map
		funcMap := template.FuncMap{}

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
	rootCmd.AddCommand(gotplCmd)

	// gotpl command and common persistent flags
	common.AddSetValuesSupport(gotplCmd, &common.Values)
	common.AddValuesFileSupport(gotplCmd, &common.ValuesFiles)
	common.AddUseAlternateDelimitersSupport(gotplCmd, &common.UseAlternateDelims)
	common.AddEditInPlaceSupport(gotplCmd, &common.EditInPlace)

	common.AddInputFileSupport(gotplCmd, &common.GetSecretsInputFile)
	common.AddOutputFileSupport(gotplCmd, &common.GetSecretsOutputFile)

}
