/*
Copyright 2022-2023 Deutsche Telekom MMS GmbH
SPDX-License-Identifier: MIT
*/

package keepassxc

import (
	"fmt"
	"io"
	"io/ioutil"

	"pault.ag/go/pkcs7"
)

func GetPKCS7Content(data io.Reader) (*pkcs7.EnvelopedData, error) {
	p7bytes, err := ioutil.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("could not read content: %w", err)
	}

	ci, err := pkcs7.Parse(p7bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse PKCS#7 data: %w", err)
	}

	envelopedData, err := ci.EnvelopedData()
	if err != nil {
		return nil, fmt.Errorf("could not get enveloped data from PKCS#7 structure: %w", err)
	}

	return envelopedData, nil
}
