// Copyright © 2018 BoxBoat engineering@boxboat.com
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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

// AddInputFileSupport will add the standard boxcmd input file option
// and store the user input in the provided string variable.
func AddInputFileSupport(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(
		p,
		"input-file",
		"i",
		"",
		"Input file or stdin")

}

// AddOutputFileSupport will add the standard boxcmd output file option
// and store the user input in the provided string variable.
func AddOutputFileSupport(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(
		p,
		"output-file",
		"o",
		"",
		"Output file (prints to stdout by default)")
}

// ReadFileOrStdin will read from stdin if "-" is passed as input string
// or it will the files contents to a byte array.
func ReadFileOrStdin(input string) ([]byte, error) {
	if input != "-" {
		Logger.Debugf("Reading from %s", input)
		return ioutil.ReadFile(input)
	}
	Logger.Debugln("Reading from stdin")
	return ioutil.ReadAll(os.Stdin)
}

// WriteFileOrStdout will write the provided data to stdout or to the
// specified file.
func WriteFileOrStdout(data []byte, output string) error {
	if output != "" {
		Logger.Debugf("Writing %s:\n%s", output, data)
		return ioutil.WriteFile(output, data, 0644)
	}
	fmt.Print(string(data))
	return nil

}

// HandleError will generically handle an error by logging its contents
// and exiting with a return code of 1.
func HandleError(err error) {
	if err != nil {
		Logger.Errorf("%s", err)
		os.Exit(1)
	}
}
