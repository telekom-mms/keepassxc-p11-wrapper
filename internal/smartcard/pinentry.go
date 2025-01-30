/*
Copyright 2022-2025 Deutsche Telekom MMS GmbH
SPDX-License-Identifier: MIT
*/

package smartcard

import (
	"fmt"

	"github.com/gopasspw/pinentry"
)

func GetPin() ([]byte, error) {
	client, err := pinentry.New()

	if err != nil {
		return nil, fmt.Errorf("could not create pinentry client: %w", err)
	}

	defer client.Close()

	err = client.Option("default-prompt=SmartCard PIN:")
	if err != nil {
		return nil, fmt.Errorf("could not set pinentry prompt: %w", err)
	}

	key, err := client.GetPin()
	if err != nil {
		return nil, fmt.Errorf("pin input failed: %w", err)
	}

	return key, nil
}
