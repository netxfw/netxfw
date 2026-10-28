package deploy

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestVerifyWithKey_ValidAndTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	script := []byte("#!/bin/bash\necho deploy\n")
	sig := ed25519.Sign(priv, script)

	if err := VerifyWithKey(pubHex, script, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := []byte("#!/bin/bash\necho evil\n")
	if err := VerifyWithKey(pubHex, tampered, sig); err == nil {
		t.Fatal("tampered script passed verification")
	}

	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyWithKey(hex.EncodeToString(otherPub), script, sig); err == nil {
		t.Fatal("wrong key passed verification")
	}
}

func TestVerifyWithKey_MalformedKey(t *testing.T) {
	if err := VerifyWithKey("not-hex", []byte("x"), []byte("y")); err != ErrKeyNotConfigured {
		t.Fatalf("want ErrKeyNotConfigured, got %v", err)
	}
	if err := VerifyWithKey("abcd", []byte("x"), []byte("y")); err != ErrKeyNotConfigured {
		t.Fatalf("short key must not be accepted, got %v", err)
	}
}

func TestVerifyUsesEmbeddedKey(t *testing.T) {
	if len(PublicKeyHex) != 64 {
		t.Fatalf("embedded public key must be a 32-byte hex ed25519 key, got %q", PublicKeyHex)
	}
	// A random signature must never verify against the embedded key.
	if err := Verify([]byte("script"), []byte("00")); err == nil {
		t.Fatal("bogus signature must not verify")
	}
}
