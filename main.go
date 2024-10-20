package main

import (
	"errors"
	"fmt"
	"log"
	"os"
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
	binaryPid := os.Getppid()
	log.Printf("Found parent pid: %d\n", binaryPid)

	log.Printf("Found parent process from pid: %d\n", binaryPid)

	success := waitUntilPidIsDead(binaryPid)
	if !success {
		log.Fatalln("Error waiting for parent pid to die")
	}

	log.Printf("Parent process %d has died, we can continue updating\n", binaryPid)

}
