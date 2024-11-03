package main

import (
	"fmt"
	"log"

	_ "unsafe"

	"golang.org/x/sys/windows"
)

func pidExists(pid int) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("invalid pid %v", pid)
	}
	ps := make([]uint32, 255)
	var read uint32 = 0
	err := windows.EnumProcesses(ps, &read)
	if err != nil {
		return false, err
	}

	log.Printf("found the following pids: %v", ps)
	for _, p := range ps {
		if p == uint32(pid) {
			return true, nil
		}
	}
	return false, nil
}
