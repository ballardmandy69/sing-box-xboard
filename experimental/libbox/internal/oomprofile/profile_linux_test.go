package oomprofile

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWriteProfiles verifies real runtime snapshots with Go's independent pprof decoder.
// @author lyt
// @date 2026-10-29
func TestWriteProfiles(t *testing.T) {
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	for _, test := range []struct{ name, sample string }{
		{"heap", "inuse_space/bytes"},
		{"allocs", "alloc_space/bytes"},
		{"goroutine", "goroutine/count"},
		{"block", "contentions/count"},
		{"mutex", "contentions/count"},
		{"threadcreate", "threadcreate/count"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), test.name+".pb")
			if err := WriteFile(path, test.name); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() == 0 {
				t.Fatalf("empty profile: %v", err)
			}
			command := exec.Command(goTool, "tool", "pprof", "-raw", "-symbolize=none", path)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("pprof decode failed: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), test.sample) || !strings.Contains(string(output), "Mappings") {
				t.Fatalf("profile lost sample type or mappings:\n%s", output)
			}
		})
	}
}
