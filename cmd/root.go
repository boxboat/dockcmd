// Copyright © 2022 BoxBoat engineering@boxboat.com
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
	"os"
	"strings"

	"github.com/boxboat/dockcmd/cmd/common"

	log "github.com/sirupsen/logrus"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// EnableDebug compile flag.
	EnableDebug = "true"
	// CfgFile containing dockcmd config
	CfgFile string
	debug   bool
)

// rootCmdPersistentPreRunE configures logging
func rootCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	common.Logger.SetOutput(os.Stdout)
	common.Logger.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	if debug {
		common.Logger.SetLevel(log.DebugLevel)
	} else {
		common.Logger.SetLevel(log.WarnLevel)
	}
	common.Logger.Debugln("rootCmdPersistentPreRunE")
	return nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:               "dockcmd",
	Short:             "BoxOps Utilities",
	Long:              `A collection of BoxOps utilities developed by BoxBoat to facilitate Ops`,
	PersistentPreRunE: rootCmdPersistentPreRunE,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	rootCmd.Version = version
	err := rootCmd.Execute()
	common.ExitIfError(err)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(
		&CfgFile,
		"config",
		"",
		"config file (default is $HOME/.dockcmd.yaml)")

	if EnableDebug == "true" {
		rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "debug output")
	}

	_ = viper.BindPFlags(rootCmd.PersistentFlags())
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if CfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(CfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		common.ExitIfError(err)

		// Search config in home directory with name ".dockcmd" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".dockcmd")
	}

	viper.SetEnvPrefix("dockcmd")
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		common.Logger.Debugf("Using config file: [%s]", viper.ConfigFileUsed())
	}
}
