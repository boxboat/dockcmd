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

package common

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/Masterminds/sprig/v3"
	log "github.com/sirupsen/logrus"
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
	// DefaultCacheTTL secrets client default cache TTL
	DefaultCacheTTL = 5 * time.Minute
)

var (
	// Logger for global use
	Logger               = log.New()
	GetSecretsInputFile  string
	GetSecretsOutputFile string
	UseAlternateDelims   bool
	EditInPlace          bool
	Values               []string
	ValuesFiles          []string
	ValuesMap            = map[string]interface{}{}
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

// GetSecrets process get-secrets request.
func GetSecrets(files []string, funcMap template.FuncMap) error {

	var data []byte
	var err error

	if len(files) > 0 {
		Logger.Debugf("Processing files: " + strings.Join(files, ","))
		for _, file := range files {
			data, err = ReadFileOrStdin(file)
			if err != nil {
				return err
			}
			if EditInPlace {
				if err := parseFile(data, funcMap, file); err != nil {
					return err
				}
			} else {
				if err := parseFile(data, funcMap, ""); err != nil {
					return err
				}
			}
		}

	} else {
		data, err = ReadFileOrStdin(GetSecretsInputFile)
		if err != nil {
			return err
		}
		if EditInPlace {
			return parseFile(data, funcMap, GetSecretsInputFile)
		} else {
			return parseFile(data, funcMap, GetSecretsOutputFile)
		}
	}
	return nil
}

func parseFile(data []byte, funcMap template.FuncMap, file string) error {
	output, err := ParseSecretsTemplate(data, funcMap)
	if err != nil {
		return err
	}
	if err := WriteFileOrStdout(output, file); err != nil {
		return err
	}
	return nil
}

// ReadSetValues will add all of the values passed in with --set and store the
// values in ValuesMap.
func ReadSetValues() error {
	Logger.Debugf("ReadSetValues")
	for _, v := range Values {
		Logger.Debugf("parsing [%s]", v)
		if err := strvals.ParseInto(v, ValuesMap); err != nil {
			return err
		}
	}
	return nil
}

func ReadValuesFiles() error {
	Logger.Debugf("ReadValuesFiles")
	for _, f := range ValuesFiles {
		currentValues := map[string]interface{}{}
		b, err := readFile(f)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(b, &currentValues); err != nil {
			return err
		}
		ValuesMap = mergeMaps(ValuesMap, currentValues)
	}
	return nil
}

// Copied from https://github.com/helm/helm/blob/master/pkg/engine/funcs.go#L83
// toYAML takes an interface, marshals it to yaml, and returns a string. It will
// always return a string, even on marshal error (empty string).
//
// This is designed to be called from a template.
func toYAML(v interface{}) string {
	data, err := yaml.Marshal(v)
	if err != nil {
		// Swallow errors inside of a template.
		return ""
	}
	return strings.TrimSuffix(string(data), "\n")
}

// urlDecode URL Decodes a string
// This is designed to be called from a template.
func urlDecode(s string) string {
	d, err := url.QueryUnescape(s)
	if err != nil {
		// Swallow errors inside of a template and return original string.
		return s
	}
	return d
}

// urlEncode URL Encodes a string
// This is designed to be called from a template.
func urlEncode(s string) string {
	return url.QueryEscape(s)
}

// ParseSecretsTemplate uses the provided funcMap to parse secrets.
func ParseSecretsTemplate(data []byte, funcMap template.FuncMap) ([]byte, error) {
	Logger.Debugf("Parsing Template:\n%s", string(data))

	// setup go template delimiters
	leftDelim := DefaultLeftDelim
	rightDelim := DefaultRightDelim
	if UseAlternateDelims {
		leftDelim = AltLeftDelim
		rightDelim = AltRightDelim
	}

	extraFuncMap := template.FuncMap{
		"toYaml":    toYAML,
		"urlEncode": urlEncode,
		"urlDecode": urlDecode,
	}

	tpl := template.Must(
		template.New("template").
			Funcs(sprig.TxtFuncMap()).
			Funcs(extraFuncMap).
			Funcs(funcMap).
			Option("missingkey=default").
			Delims(leftDelim, rightDelim).
			Parse(string(data)))

	var tplOut bytes.Buffer

	Logger.Debugf("Using Values:\n%s", ValuesMap)
	if err := tpl.Execute(&tplOut, ValuesMap); err != nil {
		return nil, err
	}

	return tplOut.Bytes(), nil
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

// ExitIfError will generically handle an error by logging its contents
// and exiting with a return code of 1.
func ExitIfError(err error) {
	if err != nil {
		Logger.Errorf("%v", err)
		os.Exit(1)
	}
}

func LogIfError(err error) {
	if err != nil {
		Logger.Warnf("%v", err)
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
