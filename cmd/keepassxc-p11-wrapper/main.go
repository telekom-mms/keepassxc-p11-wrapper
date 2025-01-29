/*
Copyright 2022-2023 Deutsche Telekom MMS GmbH
SPDX-License-Identifier: MIT
*/

package main

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	psprocess "github.com/shirou/gopsutil/process"
	"pault.ag/go/pkcs7"

	"github.com/sirupsen/logrus"

	"github.com/T-Systems-MMS/keepassxc-p11-wrapper/internal/keepassxc"
	"github.com/T-Systems-MMS/keepassxc-p11-wrapper/internal/smartcard"
)

const (
	executableName = "keepassxc"
	dbExtension    = ".kdbx"
	keyExtension   = ".p7mkey"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug output")
	slotNum := flag.Int("slot", 0, "use the given key slot")
	p11Module := flag.String("p11module", "", "absolute path to a PKCS#11 module library file")
	flag.Parse()

	if debug != nil && *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if flag.NArg() != 1 {
		logrus.Fatal("expecting database file as single argument")
	}

	dataFile := flag.Arg(0)

	if path.Ext(dataFile) != dbExtension {
		logrus.Fatal("only kdbx files are supported")
	}

	executable, err := exec.LookPath(executableName)
	if err != nil {
		logrus.Fatalf("could not find keepassxc in PATH")
	}

	alreadyRunning := checkKeepassXcSubprocess(executableName)
	if alreadyRunning {
		logrus.Fatalf("keepassxc already running, please stop it before starting again")
	}

	keyData, err := parseKeyFile(dataFile)

	if err != nil {
		if os.IsNotExist(err) {
			logrus.Debugf("key file does not exist, fallback to keepassxc without key")

			err := runKeepassXc(executable, dataFile, nil)
			if err != nil {
				logrus.Error(err)
			}

			return
		}

		logrus.Fatal(err)
	}

	decryptionKey, err := smartcard.GetDecryptionKey(*p11Module, &keyData.Recipients, *slotNum)
	if err != nil {
		logrus.Fatalf("could not get decryption key: %v", err)
	}

	content, err := keyData.EncryptedContentInfo.RawDecrypt(decryptionKey)
	if err != nil {
		logrus.Fatalf("could not decrypt content: %v", err)
	}

	err = runKeepassXc(executable, dataFile, content)
	if err != nil {
		logrus.Error(err)
	}
}

func parseKeyFile(dataFile string) (*pkcs7.EnvelopedData, error) {
	keyFile := strings.TrimSuffix(dataFile, dbExtension) + keyExtension

	key, err := os.Open(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key file does not exist: %w", err)
		}

		return nil, fmt.Errorf("could not open %s: %w", keyFile, err)
	}

	keyData, err := keepassxc.GetPKCS7Content(key)
	if err != nil {
		return nil, fmt.Errorf("could not parse key store %s: %w", key.Name(), err)
	}

	logrus.Infoln("parsed keystore file successfully")

	for _, rep := range keyData.Recipients {
		var issuer pkix.RDNSequence

		_, err := asn1.Unmarshal(rep.IssuerAndSerialNumber.Issuer.FullBytes, &issuer)
		if err != nil {
			logrus.Errorf("could not parse issuer name: %v", err)

			continue
		}

		logrus.Debugf("encrypted for certificate serial number %s (issued by %s)", rep.IssuerAndSerialNumber.Serial, issuer)
	}

	return keyData, nil
}

func runKeepassXc(executable string, dataFile string, decryptedKey []byte) error {
	const waitForKeepassXc = 5 * time.Second

	var (
		done chan struct{}
		args []string
	)

	if decryptedKey == nil {
		args = []string{dataFile}
	} else {
		temp, err := writeKey(decryptedKey)
		if err != nil {
			return fmt.Errorf("could not write temporary key: %w", err)
		}
		defer func(fileName string) {
			err := os.Remove(fileName)
			if err != nil {
				logrus.Errorf("could not remove temporary file: %v", err)
			}
		}(temp.Name())
		args = []string{"--keyfile", temp.Name(), dataFile}
	}

	go func(d chan struct{}) {
		err := runKeepassXcSubprocess(executable, args)
		if err != nil {
			logrus.Error(err)
		}
		d <- struct{}{}
	}(done)

	t := time.After(waitForKeepassXc)
	select {
	case <-t: // wait for keepassxc
	case <-done: // or wait for keepassxc exit
	}

	return nil
}

func runKeepassXcSubprocess(executable string, args []string) error {
	process := exec.Command(executable, args...)
	if err := process.Run(); err != nil {
		return fmt.Errorf("could not run keepassxc: %w", err)
	}

	output, err := process.CombinedOutput()
	if err != nil {
		return fmt.Errorf("errors from keepassxc: %w", err)
	}

	if len(output) > 0 {
		logrus.Debugf("output from keepassxc:\n%s", string(output))
	}

	return nil
}

func checkKeepassXcSubprocess(executable string) bool {
	processes, _ := psprocess.Processes()
	for _, process := range processes {
		name, _ := process.Name()
		if 0 == strings.Compare(name, executable) {
			return true
		}
	}
	return false
}

func writeKey(decryptedKey []byte) (*os.File, error) {
	temp, err := os.CreateTemp("", "keyfile*.key")
	if err != nil {
		return nil, fmt.Errorf("could not create temporary file: %w", err)
	}

	_, err = io.Copy(temp, bytes.NewReader(decryptedKey))
	if err != nil {
		return nil, fmt.Errorf("could not write key to key file: %w", err)
	}

	defer func(f *os.File) {
		_ = f.Close()
	}(temp)

	return temp, nil
}
