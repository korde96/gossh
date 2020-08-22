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

package sshutils

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// add err handling
func getKnownSigners() []ssh.Signer {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	return signers
}

// add err handling
func getCertSigner(certPath string, knownSigner ssh.Signer) ssh.Signer {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Fatalf("unable to read certificate file: %v", err)
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey(cert)
	if err != nil {
		log.Fatalf("unable to parse public key: %v", err)
	}

	certSigner, err := ssh.NewCertSigner(pk.(*ssh.Certificate), knownSigner)
	if err != nil {
		log.Fatalf("failed to create cert signer: %v", err)
	}
	return certSigner
}

func executeCmdStream(cmd, hostname string, config ssh.ClientConfig) (outPipe, errPipe io.Reader, err error) {
	conn, err := ssh.Dial("tcp", hostname+":22", &config)
	if err != nil {
		log.Println("unable to dial", hostname, ": ", err)
		return nil, nil, err
	}
	session, _ := conn.NewSession()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err = session.RequestPty("xterm", 25, 100, modes); err != nil {
		log.Println("unable to attach pty: ", err)
		return nil, nil, err
	}

	outPipe, err = session.StdoutPipe()
	if err != nil {
		log.Println("unable to attach stdout: ", err)
		return nil, nil, err
	}

	errPipe, err = session.StderrPipe()
	if err != nil {
		log.Println("unable to attach stderr: ", err)
		return nil, nil, err
	}

	go func() (err error) {
		log.Print("Running command")
		bashCmd := strings.Join([]string{"bash -c '", cmd, "'"}, "")
		if err := session.Start(bashCmd); err != nil {
			log.Println("unable to run command: ", err)
			return err
		}
		session.Wait()
		session.Close()
		return
	}()
	return
}

func GetHosts(hostsPath string) []string {
	f, err := ioutil.ReadFile(hostsPath)
	if err != nil {
		log.Fatal("unable to read hosts file: ", err)
	}
	return strings.Split(string(f), "\n")
}

func GetClientConfig(certPaths []string) ssh.ClientConfig {
	signers := getKnownSigners()
	for _, certPath := range certPaths {
		signer := getCertSigner(certPath, signers[0])
		signers = append(signers, signer)
	}
	user := os.Getenv("USER")
	config := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	return config
}

type HostPipe struct {
	hostname string
	outPipe  io.Reader
	errPipe  io.Reader
}

func handleHostPipe(pipeC <-chan HostPipe) <-chan string {
	var readerWg sync.WaitGroup
	results := make(chan string, 100)
	for c := range pipeC {

		readerWg.Add(2)
		h := c.hostname
		scanner := bufio.NewScanner(c.outPipe)
		scanner.Split(bufio.ScanLines)
		go func() {
			defer readerWg.Done()
			for scanner.Scan() {
				results <- strings.Join([]string{h, "-->", scanner.Text()}, "")
			}
		}()

		errScanner := bufio.NewScanner(c.errPipe)
		errScanner.Split(bufio.ScanLines)
		go func() {
			defer readerWg.Done()
			for errScanner.Scan() {
				results <- strings.Join([]string{"[ERROR]", h, "-->", errScanner.Text()}, "")
			}
		}()
	}

	go func() {
		readerWg.Wait()
		close(results)
	}()

	return results

}

func genOutPipes(config ssh.ClientConfig, hosts []string, execCmd string) <-chan HostPipe {
	pipeC := make(chan HostPipe, len(hosts))
	var cmdExecWg sync.WaitGroup

	for _, hostname := range hosts {
		cmdExecWg.Add(1)
		go func(h string) {
			defer cmdExecWg.Done()
			outPipe, errPipe, err := executeCmdStream(execCmd, h, config)
			if err != nil {
				log.Print("failed to execute command for host: " + h)
			} else {
				pipeC <- HostPipe{h, outPipe, errPipe}
			}
		}(hostname)
	}
	go func() {
		cmdExecWg.Wait()
		close(pipeC)
	}()
	return pipeC
}

func RunCmd(certPaths, hosts []string, execCmd string) {
	config := GetClientConfig(certPaths)

	pipeC := genOutPipes(config, hosts, execCmd)

	results := handleHostPipe(pipeC)

	for r := range results {
		fmt.Println(r)
	}
	log.Println("Execution completed")
}
