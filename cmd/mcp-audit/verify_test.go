package main

import (
	"testing"
)

func TestVerifyCmdRegistered(t *testing.T) {
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Use == "verify" {
			found = true
			break
		}
	}
	if !found {
		t.Error("verify command is not registered on rootCmd")
	}
}

func TestVerifyCmdUse(t *testing.T) {
	if verifyCmd.Use != "verify" {
		t.Errorf("verifyCmd.Use = %q, want %q", verifyCmd.Use, "verify")
	}
}

func TestVerifyCmdTextFlagExists(t *testing.T) {
	flag := verifyCmd.Flags().Lookup("text")
	if flag == nil {
		t.Fatal("verify command missing --text flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("--text default = %q, want %q", flag.DefValue, "false")
	}
}
