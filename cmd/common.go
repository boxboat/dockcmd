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
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/spf13/cobra"
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
	commonValuesMap            map[string]interface{}
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

// AddValuesArraySupport will add the standard values array and store in the
// provided string array variable.
func AddValuesArraySupport(cmd *cobra.Command, p *[]string) {
	cmd.Flags().StringArrayVar(
		p,
		"set",
		[]string{},
		"set key=value (can specify multiple times to set multiple values)")
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

// ReadValuesMap will add all of the values passed in with --set and store the
// values in commonValuesMap.
func ReadValuesMap() error {
	Logger.Debugf("Read provided values")
	commonValuesMap = make(map[string]interface{})
	for _, s := range commonValues {
		kv := strings.Split(s, "=")
		if len(kv) == 2 {
			commonValuesMap[kv[0]] = kv[1]
		} else {
			return fmt.Errorf("unable to parse %s", s)
		}
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
		template.New("secret-template").
			Funcs(sprig.TxtFuncMap()).
			Funcs(funcMap).
			Option("missingkey=error").
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
