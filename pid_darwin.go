package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"

	_ "unsafe"
)

func pidExists(pid int) (bool, error) {
	log.Println("Checking if pid exists")
	if pid <= 0 {
		return false, fmt.Errorf("invalid pid %v", pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		// This will only be hit on Windows machines.
		// see https://pkg.go.dev/os?utm_source=godoc#FindProcess for reason
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
