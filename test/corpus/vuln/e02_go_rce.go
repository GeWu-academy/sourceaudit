package main
import "os/exec"
func run(c string) {
	exec.Command("sh", "-c", c).Run()
}
