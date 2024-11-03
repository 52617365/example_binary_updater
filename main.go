package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"time"
)

func waitUntilPidIsDead(pid int) (success bool) {
	var c int
	for {
		time.Sleep(1 * time.Second)
		if c >= 20 {
			return false
		}
		c += 1
		pExists, err := pidExists(pid)
		if err != nil {
			log.Fatalf("check number %d check returned %v", c, err)
		}
		if !pExists {
			return true
		}
	}
}

//func configureLogFile(p string) {
//	logFile, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
//	if err != nil {
//		log.Fatalf("Error opening log file: %v", err)
//	}
//	log.SetOutput(logFile)
//}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <pid> <path to binary to update>", os.Args[0])
	}
	binaryPid := os.Args[1]
	binaryToUpdate := os.Args[2]

	//	logPath := path.Join(path.Dir(os.Args[0]), "updater.log")
	//	configureLogFile(logPath)

	strconvPid, err := strconv.Atoi(binaryPid)
	if err != nil {
		log.Fatalf("Invalid pid: %v", err)
	}
	success := waitUntilPidIsDead(strconvPid)

	if !success {
		log.Fatalf("We waited 20 seconds for the ppid %d to die but it did not. We will not kill the parent process because it could lead to unexpected consequences.", strconvPid)
	}

	remoteBinaryPathDirectory := fetchNewBinaryFromRemote()

	publishersEncryptedShasum, err := getBinarySignature(remoteBinaryPathDirectory)
	if err != nil {
		log.Fatalln("signature did not exist in fetched repository")
	}

	remoteBinaryPath := path.Join(remoteBinaryPathDirectory, "AutoUpdateBinary")
	remoteBinaryShasum := generateLocalSha256FromBinary(remoteBinaryPath)

	publishersPublicKey, err := getPublishersPublicKey()
	if err != nil {
		log.Fatalf("Error reading publishers public key: %v", err)
	}

	err = verifyPublishersSignature(publishersPublicKey, remoteBinaryShasum, publishersEncryptedShasum)
	if err != nil {
		log.Fatalln("Invalid signature")
	}

	log.Println("The signature was correct, updating the binary")

	err = updateBinary(binaryToUpdate, remoteBinaryPath)

	if err != nil {
		log.Fatalln(err)
	}
	// Either restart the original GUI/CLI or just exit
}

func getBinarySignature(remoteBinaryPathDirectory string) ([]byte, error) {
	encryptedShasumPath := path.Join(remoteBinaryPathDirectory, "signature.bin")
	remoteEncryptedShasum, err := os.ReadFile(encryptedShasumPath)
	if err != nil {
		return nil, err
	}
	return remoteEncryptedShasum, nil
}

func getPublishersPublicKey() (*rsa.PublicKey, error) {
	currentExecutableRootPath := path.Dir(os.Args[0])
	publicKeyPath := path.Join(currentExecutableRootPath, "public.pub")

	publicKey, err := readPublicKey(publicKeyPath)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func updateBinary(dst string, src string) error {
	dstFileStats, err := os.Stat(dst)
	if err != nil {
		return err
	}

	dstFilePermissions := dstFileStats.Mode()

	srcContents, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Creating a backup of the destination file.
	unixStamp := time.Now().Unix()
	err = os.Rename(dst, fmt.Sprintf("%s.bak_%d", dst, unixStamp))
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, srcContents, dstFilePermissions)
	return err
}

func readPublicKey(filename string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

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

// verifyPublishersSignature verifies that the signature created by the release publisher is correct.
// The publisher first generates a sha256sum from the file contents and then signs this shasum with their private key, we call this the "encrypted shasum".
// On the "client" side, a sha256sum is generated from the file contents and the encrypted shasum is decrypted with the public key. These shasums are then compared
// and if they're equal the signature is correct. This is the exact method used by CA's that sign certificates.
func verifyPublishersSignature(publicKey *rsa.PublicKey, fileShasum []byte, signature []byte) error {
	err := rsa.VerifyPSS(publicKey, crypto.SHA256, fileShasum, signature, nil)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}
	return nil
}

func generateLocalSha256FromBinary(p string) []byte {
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

// gitInPath checks that "git" is installed on the system and assigned to path. For the sake of this blog post, the function checks that git is in the path but if you're using some
// other remote server you don't need to do this. Even if you used git but did not want to set it into your path you could also specify the whole path and use it that way.
func gitInPath() bool {
	_, err := exec.LookPath("git")
	if errors.Is(err, exec.ErrDot) {
		err = nil
	}
	if err != nil {
		return false
	}
	return true
}

// fetchNewBinaryFromRemote fetches the new binary that is being used to update the current one from a remote server.
// This remote server could be anything but for the sake of example in this blog post it is a git repository.
func fetchNewBinaryFromRemote() string {
	if !gitInPath() {
		log.Fatalf("Git is not installed on the system")
	}

	remoteName := "example_binary_for_updater"
	binaryRemotePath := fmt.Sprintf("git@github.com:52617365/%s.git", remoteName)
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	fullPathToRemote := filepath.Join(dir, remoteName)

	_, err = exec.Command("git", "clone", binaryRemotePath, fullPathToRemote).Output()
	if err != nil {
		log.Fatalf("Failed to fetch new binary: %v", err)
	}

	log.Printf("Successfully fetched new binary from remote")

	pathToGitFolder := filepath.Join(fullPathToRemote, ".git")
	err = os.RemoveAll(pathToGitFolder)

	if err != nil {
		log.Fatalf("Failed to remove .git folder: %v", err)
	}

	return fullPathToRemote
}
