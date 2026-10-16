// Copyright (C) PH4NTXM
// Licensed under the GNU General Public License v3.0.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"filippo.io/age"
)

const (
	maxClear         = 64*1024*1024 + 128*1024
	maxCipher        = maxClear + 128*1024
	maxPassword      = 1024
	maxPasswordInput = 4096
	maxCgroupMemory  = 512 * 1024 * 1024
	softMemoryLimit  = 384 * 1024 * 1024
)

var errLimit = errors.New("size limit")

type cappedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errLimit
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func readPassword(reader io.Reader, mode string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxPasswordInput+1))
	if err != nil || len(data) > maxPasswordInput || len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 || !utf8.Valid(data) {
		return "", errors.New("invalid password input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') || !decoder.More() {
		return "", errors.New("invalid password input")
	}
	token, err = decoder.Token()
	if err != nil || token != "password" {
		return "", errors.New("invalid password input")
	}
	var password string
	if err = decoder.Decode(&password); err != nil || decoder.More() {
		return "", errors.New("invalid password input")
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return "", errors.New("invalid password input")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return "", errors.New("invalid password input")
	}
	if len(password) == 0 || len(password) > maxPassword || !utf8.ValidString(password) || (mode == "encrypt" && utf8.RuneCountInString(password) < 12) {
		return "", errors.New("invalid password input")
	}
	return password, nil
}

func memoryBounded(root, membership string) bool {
	for _, line := range strings.Split(membership, "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		current := filepath.Join(root, strings.TrimPrefix(line, "0::/"))
		memory, err := os.ReadFile(filepath.Join(current, "memory.max"))
		if err != nil {
			return false
		}
		limit, err := strconv.ParseUint(strings.TrimSpace(string(memory)), 10, 64)
		if err != nil || limit == 0 || limit > maxCgroupMemory {
			return false
		}
		swap, err := os.ReadFile(filepath.Join(current, "memory.swap.max"))
		return err == nil && strings.TrimSpace(string(swap)) == "0"
	}
	return false
}

func configureRuntime() error {
	runtime.GOMAXPROCS(2)
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	debug.SetMemoryLimit(softMemoryLimit)
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !memoryBounded("/sys/fs/cgroup", string(membership)) {
		return errors.New("memory containment unavailable")
	}
	return nil
}

func fileFlags(file *os.File) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFL, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(flags), nil
}

func validateFiles(input, output *os.File, mode string) error {
	inputInfo, err := input.Stat()
	if err != nil || !inputInfo.Mode().IsRegular() {
		return errors.New("invalid input")
	}
	limit := int64(maxClear)
	if mode == "decrypt" {
		limit = maxCipher
	}
	if inputInfo.Size() < 0 || inputInfo.Size() > limit {
		return errors.New("invalid input")
	}
	inputFlags, err := fileFlags(input)
	if err != nil || inputFlags&syscall.O_ACCMODE != syscall.O_RDONLY {
		return errors.New("invalid input")
	}
	inputOffset, err := input.Seek(0, io.SeekCurrent)
	if err != nil || inputOffset != 0 {
		return errors.New("invalid input")
	}
	outputInfo, err := output.Stat()
	if err != nil || !outputInfo.Mode().IsRegular() || outputInfo.Size() != 0 || outputInfo.Mode().Perm() != 0600 || os.SameFile(inputInfo, outputInfo) {
		return errors.New("invalid output")
	}
	stat, ok := outputInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&07777 != 0600 {
		return errors.New("invalid output")
	}
	outputFlags, err := fileFlags(output)
	if err != nil || outputFlags&syscall.O_ACCMODE == syscall.O_RDONLY || outputFlags&syscall.O_APPEND != 0 {
		return errors.New("invalid output")
	}
	outputOffset, err := output.Seek(0, io.SeekCurrent)
	if err != nil || outputOffset != 0 {
		return errors.New("invalid output")
	}
	return nil
}

func encrypt(input io.Reader, output io.Writer, password string) error {
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return err
	}
	recipient.SetWorkFactor(18)
	writer, err := age.Encrypt(&cappedWriter{writer: output, remaining: maxCipher}, recipient)
	if err != nil {
		return err
	}
	count, err := io.Copy(writer, io.LimitReader(input, maxClear+1))
	if err != nil {
		return err
	}
	if count > maxClear {
		return errLimit
	}
	return writer.Close()
}

func decrypt(input io.Reader, output io.Writer, password string) error {
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return err
	}
	identity.SetMaxWorkFactor(18)
	reader, err := age.Decrypt(io.LimitReader(input, maxCipher+1), identity)
	if err != nil {
		return err
	}
	_, err = io.Copy(&cappedWriter{writer: output, remaining: maxClear}, reader)
	return err
}

func reply(code int, message string) int {
	response := struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}{OK: code == 0, Error: message}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		return 4
	}
	return code
}

func transform(input io.Reader, output *os.File, mode, password string) (code int) {
	defer func() {
		if code != 0 {
			if err := output.Truncate(0); err != nil {
				code = 4
			}
		}
	}()
	var err error
	if mode == "encrypt" {
		err = encrypt(input, output, password)
	} else {
		err = decrypt(input, output, password)
	}
	if err != nil {
		if mode == "decrypt" {
			return 3
		}
		return 4
	}
	if err := output.Sync(); err != nil {
		return 4
	}
	return 0
}

func run() int {
	if len(os.Args) != 4 || os.Args[1] != "encrypt" && os.Args[1] != "decrypt" || os.Args[2] != "/input" || os.Args[3] != "/output" {
		return reply(2, "invalid_request")
	}
	mode := os.Args[1]
	if err := configureRuntime(); err != nil {
		return reply(4, "runtime_unavailable")
	}
	password, err := readPassword(os.Stdin, mode)
	if err != nil {
		return reply(2, "invalid_request")
	}
	input, err := os.OpenFile("/input", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return reply(2, "invalid_request")
	}
	defer input.Close()
	output, err := os.OpenFile("/output", os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return reply(2, "invalid_request")
	}
	defer output.Close()
	if err := validateFiles(input, output, mode); err != nil {
		return reply(2, "invalid_request")
	}
	code := transform(input, output, mode, password)
	message := ""
	if code == 3 {
		message = "unlock_failed"
	} else if code != 0 {
		message = "runtime_failure"
	}
	result := reply(code, message)
	if result != 0 {
		output.Truncate(0)
	}
	return result
}

func main() {
	os.Exit(run())
}
