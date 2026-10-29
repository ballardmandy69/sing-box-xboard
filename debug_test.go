package box

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime/debug"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// TestLegacyDebugMemoryLimit checks the process-wide runtime setting in child
// processes so the tests do not alter the parent process's memory policy.
func TestLegacyDebugMemoryLimit(t *testing.T) {
	const (
		caseEnvironment = "SING_BOX_TEST_DEBUG_MEMORY_LIMIT_CASE"
		initialLimit    = int64(192 << 20)
	)
	testCases := []struct {
		name    string
		options string
		want    int64
	}{
		{name: "bytes", options: `{"memory_limit":100663296}`, want: 96 << 20},
		{name: "memory_unit", options: `{"memory_limit":"96MB"}`, want: 96 << 20},
		{name: "exact_integer", options: `{"memory_limit":9007199254740993}`, want: 9007199254740993},
		{name: "zero", options: `{"memory_limit":0}`, want: initialLimit},
		{name: "omitted", options: `{}`, want: initialLimit},
	}

	if selectedCase := os.Getenv(caseEnvironment); selectedCase != "" {
		for _, testCase := range testCases {
			if testCase.name != selectedCase {
				continue
			}
			debug.SetMemoryLimit(initialLimit)
			var options option.DebugOptions
			if err := json.Unmarshal([]byte(testCase.options), &options); err != nil {
				t.Fatal(err)
			}
			applyDebugOptions(options)
			if got := debug.SetMemoryLimit(-1); got != testCase.want {
				t.Fatalf("runtime memory limit = %d, want %d", got, testCase.want)
			}
			t.Logf("runtime memory limit = %d", testCase.want)
			return
		}
		t.Fatalf("unknown child test case %q", selectedCase)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			command := exec.Command(executable, "-test.run=^TestLegacyDebugMemoryLimit$", "-test.v")
			command.Env = append(os.Environ(), caseEnvironment+"="+testCase.name)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("child test failed: %v\n%s", err, output)
			}
			t.Logf("%s", output)
		})
	}
}
