package proc

import (
	"runtime"
	"testing"
	"time"
)

func TestCapturesOutputAndExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	r, err := Run([]string{"sh", "-c", "read x; echo out:$x; echo err >&2; exit 3"}, Options{Stdin: []byte("hi\n"), Timeout: 10 * time.Second})
	if err != nil || r.Code != 3 || string(r.Stdout) != "out:hi\n" || string(r.Stderr) != "err\n" {
		t.Fatalf("got %+v %v", r, err)
	}
}
