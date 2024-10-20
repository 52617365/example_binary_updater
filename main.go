package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"time"
)

func pidExists(pid int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("invalid pid %v", pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true, nil
	}
	if err.Error() == "os: process already finished" {
		return false, nil
	}
	var errno syscall.Errno
	ok := errors.As(err, &errno)
	if !ok {
		return false, err
	}
	switch {
	case errors.Is(errno, syscall.ESRCH):
		return false, nil
	case errors.Is(errno, syscall.EPERM):
		return true, nil
	}
	return false, err
}

func waitUntilPidIsDead(pid int) (success bool) {
	var c int
	for {
		time.Sleep(1 * time.Second)
		if c >= 20 {
			return false
		}
		c += 1
		pidExists, err := pidExists(pid)
		if err != nil {
			log.Printf("check number %d check returned %v", c, err)
		}
		if !pidExists {
			return true
		}
	}
}

func main() {
	// Fetches the pid of the parent of this binary (The binary that needs updating.)
	isTest := flag.Bool("test", false, "set testing to true if testing")
	flag.Parse()
	if !(*isTest) {
		binaryPid := os.Getppid()
		log.Printf("Found parent pid: %d\n", binaryPid)

		log.Printf("Found parent process from pid: %d\n", binaryPid)

		success := waitUntilPidIsDead(binaryPid)
		if !success {
			log.Fatalln("Error waiting for parent pid to die")
		}

		log.Printf("Parent process %d has died, we can continue updating\n", binaryPid)
	}

	remoteName := "example_binary_for_updater"
	binaryRemotePath := fmt.Sprintf("git@github.com:52617365/%s.git", remoteName)
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fullPathTmp := filepath.Join(dir, remoteName)
	fetchNewBinaryFromRemote(binaryRemotePath, fullPathTmp)

	encryptedShasumPath := path.Join(fullPathTmp, "signature.bin")
	encryptedShasum, err := os.ReadFile(encryptedShasumPath)
	if err != nil {
		log.Fatalln("signature did not exist in fetched repository")
	}
	binaryPath := path.Join(fullPathTmp, "AutoUpdateBinary")
	binaryShasum := generateShasum256FromFile(binaryPath)
	currentWorkingDirectory, _ := os.Getwd()
	publicKeyPath := path.Join(currentWorkingDirectory, "public.pub")

	publicKey, err := readPublicKey(publicKeyPath)
	if err != nil {
		log.Fatalf("Error reading public key: %v", err)
	}

	err = verifySignature(publicKey, binaryShasum, encryptedShasum)
	if err != nil {
		log.Fatalln("Invalid signature")
	}
}

func readPublicKey(filename string) (*rsa.PublicKey, error) {
	// Read the file
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse RSA public key")
	}
	return rsaPubKey, nil
}

func verifySignature(publicKey *rsa.PublicKey, fileShasum []byte, signature []byte) error {
	err := rsa.VerifyPSS(publicKey, crypto.SHA256, fileShasum, signature, nil)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}
	return nil
}

func generateShasum256FromFile(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return h.Sum(nil)
}

func fetchNewBinaryFromRemote(path string, outPath string) {
	_, err := exec.Command("git", "clone", path, outPath).Output()
	if err != nil {
		log.Fatalf("Failed to fetch new binary: %v", err)
	}
	log.Printf("Successfully fetched new binary from remote")

	pathToGitFolder := filepath.Join(outPath, ".git")
	err = os.RemoveAll(pathToGitFolder)
	if err != nil {
		log.Fatalf("Failed to remove .git folder: %v", err)
	}

}
