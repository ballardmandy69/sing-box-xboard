package main

import (
	"encoding/base64"
	"fmt"

	"github.com/sagernet/sing-box/transport/anytlsnative"

	"github.com/spf13/cobra"
)

// commandGenerateAnyTLSNativeKeyPair generates local keys without network access.
// @author lyt
// @date 2026-10-29
var commandGenerateAnyTLSNativeKeyPair = &cobra.Command{
	Use:   "anytls-native-keypair",
	Short: "Generate AnyTLS Native X25519 key pair",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		privateKey, publicKey, err := anytlsnative.GenerateKeyPair()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "PrivateKey: %s\nPublicKey: %s\n",
			base64.RawURLEncoding.EncodeToString(privateKey),
			base64.RawURLEncoding.EncodeToString(publicKey))
		return err
	},
}

func init() {
	commandGenerate.AddCommand(commandGenerateAnyTLSNativeKeyPair)
}
