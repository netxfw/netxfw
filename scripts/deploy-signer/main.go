// Command deploy-signer manages the ed25519 key pair used to sign
// scripts/deploy.sh, and produces the detached signature that the
// netxfw binary verifies before executing the update script as root.
//
// Usage:
//
//	deploy-signer genkey                 # print hex public/private key pair (run once by maintainer)
//	deploy-signer sign <script> <priv>   # write <script>.sig (hex ed25519 signature)
//	deploy-signer verify <script> <sig> <pub>
//
// The private half belongs in the GitHub secret DEPLOY_SCRIPT_PRIVATE_KEY;
// the public half is compiled into the binary as deploy.PublicKeyHex.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: deploy-signer genkey | sign <script> <privhex> | verify <script> <sighex-path> <pubhex>")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "genkey":
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate key failed:", err)
			os.Exit(1)
		}
		fmt.Printf("public (embed as deploy.PublicKeyHex): %s\n", hex.EncodeToString(pub))
		fmt.Printf("private (store as DEPLOY_SCRIPT_PRIVATE_KEY secret): %s\n", hex.EncodeToString(priv.Seed()))
	case "sign":
		if len(os.Args) != 4 {
			usage()
		}
		script, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "read script failed:", err)
			os.Exit(1)
		}
		seed, err := hex.DecodeString(os.Args[3])
		if err != nil || len(seed) != ed25519.SeedSize {
			fmt.Fprintln(os.Stderr, "invalid private key seed (want 32-byte hex)")
			os.Exit(1)
		}
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), script)
		out := os.Args[2] + ".sig"
		if err := os.WriteFile(out, []byte(hex.EncodeToString(sig)), 0600); err != nil {
			fmt.Fprintln(os.Stderr, "write signature failed:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", out)
	case "verify":
		if len(os.Args) != 5 {
			usage()
		}
		script, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "read script failed:", err)
			os.Exit(1)
		}
		sigHex, err := os.ReadFile(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "read signature failed:", err)
			os.Exit(1)
		}
		sig, err := hex.DecodeString(trimSpace(string(sigHex)))
		if err != nil {
			fmt.Fprintln(os.Stderr, "signature is not valid hex:", err)
			os.Exit(1)
		}
		pub, err := hex.DecodeString(os.Args[4])
		if err != nil || len(pub) != ed25519.PublicKeySize {
			fmt.Fprintln(os.Stderr, "invalid public key")
			os.Exit(1)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), script, sig) {
			fmt.Fprintln(os.Stderr, "VERIFY FAILED")
			os.Exit(1)
		}
		fmt.Println("verify ok")
	default:
		usage()
	}
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
