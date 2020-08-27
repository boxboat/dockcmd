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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/strvals"
)

const (
	// AltLeftDelim for go templating
	AltLeftDelim = "<<"
	// AltRightDelim for go templating
	AltRightDelim = ">>"
	// DefaultLeftDelim for go templating
	DefaultLeftDelim = "{{"
	// DefaultRightDelim for go templating
	DefaultRightDelim = "}}"
)

var (
	commonGetSecretsInputFile  string
	commonGetSecretsOutputFile string
	commonUseAlternateDelims   bool
	commonEditInPlace          bool
	commonValues               []string
	commonValuesFiles          []string
	commonValuesMap            = map[string]interface{}{}
)

// AddEditInPlaceSupport will add the standard edit in place option and store
// the user input in the provided bool variable.
func AddEditInPlaceSupport(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVarP(
		p,
		"edit-in-place",
		"",
		false,
		"Enable edit in place, edit input file(s) in place")
}

// AddInputFileSupport will add the standard dockcmd input file option
// and store the user input in the provided string variable.
func AddInputFileSupport(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(
		p,
		"input-file",
		"i",
		"",
		"Input file or stdin")
}

// AddOutputFileSupport will add the standard dockcmd output file option
// and store the user input in the provided string variable.
func AddOutputFileSupport(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(
		p,
		"output-file",
		"o",
		"",
		"Output file (prints to stdout by default)")
}

// AddUseAlternateDelimitersSupport will add the standard use alternate
// delimeters option and store the user input in the provided bool variable.
func AddUseAlternateDelimitersSupport(cmd *cobra.Command, p *bool) {
	cmd.Flags().BoolVarP(
		p,
		"use-alt-delims",
		"",
		false,
		"Enable '<< >>' delimiters for go template processing")
}

// AddSetValuesSupport will add the standard values array and store in the
// provided string array variable.
func AddSetValuesSupport(cmd *cobra.Command, p *[]string) {
	cmd.Flags().StringArrayVar(
		p,
		"set",
		[]string{},
		"set key=value (can specify multiple times to set multiple values)")
}

// AddValuesFileSupport will add the standard values file array and store in the
// provided string array variable.
func AddValuesFileSupport(cmd *cobra.Command, p *[]string) {
	cmd.Flags().StringArrayVar(
		p,
		"values",
		[]string{},
		"values file.yaml (can specify multiple times to set multiple values)")
}

// CommonGetSecrets process get-secrets request.
func CommonGetSecrets(files []string, funcMap template.FuncMap) {

	var data []byte
	var err error

	if len(files) > 0 {
		Logger.Debugf("Processing files: " + strings.Join(files, ","))
		for _, file := range files {
			data, err = ReadFileOrStdin(file)
			HandleError(err)
			output := ParseSecretsTemplate(data, funcMap)
			if commonEditInPlace {
				err = WriteFileOrStdout(output, file)
			} else {
				err = WriteFileOrStdout(output, "")
			}
			HandleError(err)
		}

	} else {
		data, err = ReadFileOrStdin(commonGetSecretsInputFile)
		HandleError(err)
		output := ParseSecretsTemplate(data, funcMap)
		if commonEditInPlace {
			err = WriteFileOrStdout(output, commonGetSecretsInputFile)
		} else {
			err = WriteFileOrStdout(output, commonGetSecretsOutputFile)
		}
		HandleError(err)
	}
}

// ReadSetValues will add all of the values passed in with --set and store the
// values in commonValuesMap.
func ReadSetValues() error {
	Logger.Debugf("ReadSetValues")
	for _, v := range commonValues {
		Logger.Debugf("parsing [%s]", v)
		err := strvals.ParseInto(v, commonValuesMap)
		HandleError(err)
	}
	return nil
}

func ReadValuesFiles() error {
	Logger.Debugf("ReadValuesFiles")
	for _, f := range commonValuesFiles {
		currentValues := map[string]interface{}{}
		bytes,err := readFile(f)
		HandleError(err)
		err = yaml.Unmarshal(bytes, &currentValues)
		HandleError(err)
		commonValuesMap = mergeMaps(commonValuesMap, currentValues)
	}
	return nil
}

// ParseSecretsTemplate uses the provided funcMap to parse secrets.
func ParseSecretsTemplate(data []byte, funcMap template.FuncMap) []byte {
	Logger.Debugf("Parsing Template:\n%s", string(data))

	// setup go template delimiters
	leftDelim := DefaultLeftDelim
	rightDelim := DefaultRightDelim
	if commonUseAlternateDelims {
		leftDelim = AltLeftDelim
		rightDelim = AltRightDelim
	}

	tpl := template.Must(
		template.New("template").
			Funcs(sprig.TxtFuncMap()).
			Funcs(funcMap).
			Option("missingkey=default").
			Delims(leftDelim, rightDelim).
			Parse(string(data)))

	var tplOut bytes.Buffer

	Logger.Debugf("Using Values:\n%s", commonValuesMap)
	err := tpl.Execute(&tplOut, commonValuesMap)
	HandleError(err)

	return tplOut.Bytes()
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

// mergeMaps merges values of provided maps and returns a merged copy. Merges right to left.
func mergeMaps(left map[string]interface{}, right map[string]interface{}) map[string]interface{} {
	final := make(map[string]interface{}, len(left))
	for k, v := range left {
		final[k] = v
	}
	for k, v := range right {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := final[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					final[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		final[k] = v
	}
	return final
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
