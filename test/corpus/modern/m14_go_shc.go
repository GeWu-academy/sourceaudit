package main

import (
	"os/exec"
)

func ping(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c1 "+host).Output()
}
