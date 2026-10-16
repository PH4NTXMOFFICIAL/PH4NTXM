// Copyright (C) PH4NTXM
// Licensed under the GNU General Public License v3.0.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct horse battery staple"

func TestMain(m *testing.M) {
	debug.SetMemoryLimit(softMemoryLimit)
	os.Exit(m.Run())
}

type repeatingReader struct{}

func (repeatingReader) Read(data []byte) (int, error) {
	clear(data)
	return len(data), nil
}

func TestPasswordInput(t *testing.T) {
	valid := []string{testPassword, "abcdefghijkl", strings.Repeat("ö", 12), strings.Repeat("a", maxPassword)}
	for _, password := range valid {
		data, err := json.Marshal(map[string]string{"password": password})
		if err != nil {
			t.Fatal(err)
		}
		got, err := readPassword(bytes.NewReader(append(data, '\n')), "encrypt")
		if err != nil || got != password {
			t.Fatalf("valid password rejected: %v", err)
		}
	}
	invalid := []string{
		"",
		"{}\n",
		"[]\n",
		"{\"password\":\"abcdefghijkl\"}",
		"{\"password\":\"abcdefghijkl\"}\n\n",
		"{\"password\":\"abcdefghijkl\",\"password\":\"abcdefghijkl\"}\n",
		"{\"password\":\"abcdefghijkl\",\"extra\":true}\n",
		"{\"Password\":\"abcdefghijkl\"}\n",
		"{\"password\":null}\n",
		"{\"password\":false}\n",
		"{\"password\":\"\"}\n",
		"{\"password\":\"abcdefghijk\"}\n",
		"{\"password\":\"abcdefghijkl\"}{}\n",
		"{\"password\":\"" + strings.Repeat("a", maxPassword+1) + "\"}\n",
		"{\"password\":\"" + strings.Repeat("ö", maxPassword/2+1) + "\"}\n",
		strings.Repeat(" ", maxPasswordInput) + "\n",
		"{\"password\":\"abcdefghijk\xff\"}\n",
	}
	for index, input := range invalid {
		if _, err := readPassword(strings.NewReader(input), "encrypt"); err == nil {
			t.Errorf("invalid password case %d accepted", index)
		}
	}
	if password, err := readPassword(strings.NewReader("{\"password\":\"x\"}\n"), "decrypt"); err != nil || password != "x" {
		t.Fatal("legacy short decrypt password rejected")
	}
}

func TestMemoryContainment(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "user.slice", "vault.service")
	if err := os.MkdirAll(unit, 0700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		memory string
		swap   string
		valid  bool
	}{
		{"536870912", "0", true},
		{"268435456", "0", true},
		{"536870913", "0", false},
		{"max", "0", false},
		{"0", "0", false},
		{"536870912", "max", false},
		{"536870912", "1", false},
	} {
		if err := os.WriteFile(filepath.Join(unit, "memory.max"), []byte(item.memory+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(unit, "memory.swap.max"), []byte(item.swap+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if memoryBounded(root, "0::/user.slice/vault.service\n") != item.valid {
			t.Fatalf("unexpected containment result for %s/%s", item.memory, item.swap)
		}
	}
	if memoryBounded(root, "0::/missing.service\n") || memoryBounded(root, "1:memory:/user.slice/vault.service\n") {
		t.Fatal("missing cgroup accepted")
	}
}

func TestAgeRoundTripAndHostileInputs(t *testing.T) {
	plain := bytes.Repeat([]byte("Vault payload\n"), 10000)
	var encrypted bytes.Buffer
	if err := encrypt(bytes.NewReader(plain), &encrypted, testPassword); err != nil {
		t.Fatal(err)
	}
	ciphertext := encrypted.Bytes()
	if !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Fatal("output is not a standard binary age passphrase file")
	}
	var output bytes.Buffer
	if err := decrypt(bytes.NewReader(ciphertext), &output, testPassword); err != nil || !bytes.Equal(output.Bytes(), plain) {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if err := decrypt(bytes.NewReader(ciphertext), io.Discard, "wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 1
	variants := [][]byte{
		tampered,
		ciphertext[:len(ciphertext)-1],
		append(bytes.Clone(ciphertext), 0),
		[]byte("not age"),
	}
	failedOutput, err := os.CreateTemp(t.TempDir(), "failed")
	if err != nil {
		t.Fatal(err)
	}
	defer failedOutput.Close()
	for index, input := range variants {
		if code := transform(bytes.NewReader(input), failedOutput, "decrypt", testPassword); code != 3 {
			t.Errorf("hostile ciphertext case %d accepted", index)
		}
		info, err := failedOutput.Stat()
		if err != nil || info.Size() != 0 {
			t.Fatalf("failed ciphertext case %d retained plaintext", index)
		}
		if _, err := failedOutput.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
	}
	highCost := bytes.Replace(ciphertext, []byte(" 18\n"), []byte(" 30\n"), 1)
	if bytes.Equal(highCost, ciphertext) {
		t.Fatal("missing scrypt work factor")
	}
	started := time.Now()
	if err := decrypt(bytes.NewReader(highCost), io.Discard, testPassword); err == nil {
		t.Fatal("excessive work factor accepted")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("excessive work factor was evaluated")
	}
}

func TestInputLimit(t *testing.T) {
	input := io.LimitReader(repeatingReader{}, maxClear+1)
	if err := encrypt(input, io.Discard, testPassword); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
}

func TestFileValidation(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input")
	outputPath := filepath.Join(directory, "output")
	if err := os.WriteFile(inputPath, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(outputPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := validateFiles(input, output, "encrypt"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := validateFiles(input, output, "encrypt"); err == nil {
		t.Fatal("input at nonzero offset accepted")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := output.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	if err := validateFiles(input, output, "encrypt"); err == nil {
		t.Fatal("public output accepted")
	}
	if err := output.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	writableInput, err := os.OpenFile(inputPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writableInput.Close()
	if err := writableInput.Truncate(maxCipher + 1); err != nil {
		t.Fatal(err)
	}
	largeInput, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer largeInput.Close()
	if err := validateFiles(largeInput, output, "decrypt"); err == nil {
		t.Fatal("oversized ciphertext accepted")
	}
}
