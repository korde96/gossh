/*
Copyright © 2020 Ajinkya Korde <askorde2@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"gossh/sshutils"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "gossh",
	Short:   "pssh alternative in go",
	Example: `gossh --hosts=hosts.txt --cert=/Users/ajinkya.korde/.ssh/stage-cert.pub --cmd="syslog"`,
	Run:     root,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().String("hosts-file", "", "Hosts filepath")
	rootCmd.Flags().String("host", "", "Host")
	rootCmd.Flags().StringSlice("cert", []string{}, "Cert filepath")
	rootCmd.Flags().String("cmd", "", "Command")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// removed viper code
	// reconsider config/env file method
}

//do proper error checks
func root(cmd *cobra.Command, args []string) {
	host, err := cmd.Flags().GetString("host")
	hosts, err := cmd.Flags().GetString("hosts-file")
	certs, err := cmd.Flags().GetStringSlice("cert")
	execCmd, err := cmd.Flags().GetString("cmd")
	if err != nil {
		cmd.Usage()
		log.Fatal(err)
	}
	var hostList []string
	if (hosts == "" && host == "") || (hosts != "" && host != "") {
		fmt.Println("either host or hostfile is required")
		cmd.Usage()
		log.Fatal("either host or hostfile is required")
	}
	if host != "" {
		hostList = []string{host}
	}
	if hosts != "" {
		hostList = sshutils.GetHosts(hosts)
	}
	sshutils.RunCmd(certs, hostList, execCmd)
}
